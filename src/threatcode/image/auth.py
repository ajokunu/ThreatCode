"""Registry authentication: credential store and token exchange."""

from __future__ import annotations

import base64
import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_WWW_AUTH_RE = re.compile(r'(\w+)="([^"]*)"')
_DOCKER_HUB_AUTH_KEY = "https://index.docker.io/v1/"


@dataclass
class RegistryCredential:
    username: str
    password: str


class CredentialStore:
    """Resolve credentials for container registries.

    Reads ~/.docker/config.json and supports:
    - Per-registry credential helpers (credHelpers)
    - Default credential store (credsStore)
    - Inline base64-encoded credentials (auths)
    """

    def __init__(self, docker_config_path: Path | None = None) -> None:
        if docker_config_path is None:
            docker_config_path = Path.home() / ".docker" / "config.json"
        self._config: dict[str, Any] = {}
        if docker_config_path.is_file():
            try:
                self._config = json.loads(docker_config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.debug("Could not read docker config: %s", e)

    def get(self, registry: str) -> RegistryCredential | None:
        """Return credentials for the given registry hostname, or None."""
        # 1. Per-registry credential helper
        cred_helpers: dict[str, str] = self._config.get("credHelpers", {})
        if registry in cred_helpers:
            helper = cred_helpers[registry]
            cred = self._from_cred_helper(helper, registry)
            if cred:
                return cred

        # 2. Default credential store
        creds_store: str = self._config.get("credsStore", "")
        if creds_store:
            cred = self._from_cred_helper(creds_store, registry)
            if cred:
                return cred

        # 3. Inline auths
        return self._from_auths(registry)

    def _from_cred_helper(self, helper_name: str, registry: str) -> RegistryCredential | None:
        """Invoke docker-credential-{helper_name} to get credentials."""
        binary = f"docker-credential-{helper_name}"
        try:
            result = subprocess.run(
                [binary, "get"],
                input=registry,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            data = json.loads(result.stdout)
            username = data.get("Username", "")
            secret = data.get("Secret", "")
            if username and secret:
                return RegistryCredential(username=username, password=secret)
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass
        return None

    def _from_auths(self, registry: str) -> RegistryCredential | None:
        """Look up inline base64-encoded credentials."""
        auths: dict[str, Any] = self._config.get("auths", {})

        # Try exact registry match, then Docker Hub legacy key
        candidates = [registry]
        if registry in ("registry-1.docker.io", "docker.io", "index.docker.io"):
            candidates.append(_DOCKER_HUB_AUTH_KEY)

        for key in candidates:
            entry = auths.get(key, {})
            auth_b64 = entry.get("auth", "")
            if auth_b64:
                try:
                    decoded = base64.b64decode(auth_b64).decode("utf-8")
                    username, _, password = decoded.partition(":")
                    if username:
                        return RegistryCredential(username=username, password=password)
                except Exception:
                    pass

        return None


class TokenProvider:
    """Exchange Docker Registry v2 bearer tokens."""

    def __init__(
        self,
        http_client: Any,  # httpx.Client
        credential: RegistryCredential | None = None,
    ) -> None:
        self._client = http_client
        self._credential = credential

    def get_token(self, registry: str, repository: str) -> str | None:
        """Obtain a bearer token for the given registry and repository.

        Returns the token string, or None if no authentication is needed.
        Raises on HTTP errors that prevent token exchange.
        """
        # Probe the registry v2 endpoint
        probe_url = f"https://{registry}/v2/"
        try:
            resp = self._client.get(probe_url)
        except Exception as e:
            logger.debug("Registry probe failed for %s: %s", registry, e)
            return None

        if resp.status_code == 200:
            # No auth required
            return None

        if resp.status_code != 401:
            logger.debug("Unexpected status %d from %s", resp.status_code, probe_url)
            return None

        # Parse Www-Authenticate header
        www_auth = resp.headers.get("Www-Authenticate", "")
        if not www_auth.lower().startswith("bearer "):
            logger.debug("Non-bearer auth scheme: %s", www_auth[:50])
            return None

        params: dict[str, str] = {}
        for key, value in _WWW_AUTH_RE.findall(www_auth):
            params[key] = value

        realm = params.get("realm", "")
        if not realm:
            logger.debug("No realm in Www-Authenticate: %s", www_auth[:100])
            return None

        # Build token request
        token_params: dict[str, str] = {}
        if "service" in params:
            token_params["service"] = params["service"]
        token_params["scope"] = params.get("scope", f"repository:{repository}:pull")

        headers: dict[str, str] = {}
        if self._credential:
            raw = f"{self._credential.username}:{self._credential.password}"
            b64 = base64.b64encode(raw.encode()).decode()
            headers["Authorization"] = f"Basic {b64}"

        try:
            token_resp = self._client.get(realm, params=token_params, headers=headers)
            token_resp.raise_for_status()
            data = token_resp.json()
            return data.get("token") or data.get("access_token") or None
        except Exception as e:
            logger.debug("Token exchange failed for %s: %s", realm, e)
            return None
