"""Dockerfile parser for ThreatCode."""

from __future__ import annotations

import re
from typing import Any

from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

# Regex to parse Dockerfile instructions
_INSTRUCTION_RE = re.compile(
    r"^\s*(?P<instruction>[A-Z]+)\s+(?P<arguments>.+)$",
    re.MULTILINE,
)

# Instructions that can contain secrets
_SECRET_ENV_PATTERNS = re.compile(
    r"(?i)(password|secret|key|token|api_key|apikey|auth|credential)",
)


class DockerfileParser(BaseParser):
    """Parse Dockerfile instructions into ParsedResource objects."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, str):
            data = str(data)

        resources: list[ParsedResource] = []
        instructions = self._parse_instructions(data)

        # Track state for synthetic summary
        has_user = False
        has_healthcheck = False
        uses_latest_tag = False
        exposed_ports: list[int] = []
        base_image = ""
        user_value = ""
        has_workdir = False
        entrypoint_count = 0
        add_count = 0
        copy_without_chown = 0

        for idx, (instruction, arguments, line_num) in enumerate(instructions):
            resource_type = f"dockerfile_{instruction.lower()}"
            address = f"dockerfile.{instruction.lower()}.{idx}"

            props: dict[str, Any] = {
                "instruction": instruction,
                "arguments": arguments,
                "line_number": line_num,
            }

            if instruction == "FROM":
                image = arguments.split()[0] if arguments else ""
                if not base_image:
                    base_image = image
                tag = ""
                if ":" in image and not image.startswith("sha256:"):
                    tag = image.split(":")[-1]
                elif "@" not in image:
                    tag = "latest"
                    uses_latest_tag = True
                if tag == "latest":
                    uses_latest_tag = True
                props["image"] = image
                props["tag"] = tag

            elif instruction == "USER":
                has_user = True
                user_value = arguments.strip()
                props["user"] = user_value

            elif instruction == "HEALTHCHECK":
                if arguments.strip().upper() != "NONE":
                    has_healthcheck = True

            elif instruction == "EXPOSE":
                for port_str in arguments.split():
                    port_str = port_str.split("/")[0]  # Remove protocol
                    try:
                        port = int(port_str)
                        exposed_ports.append(port)
                        props["port"] = port
                    except ValueError:
                        pass

            elif instruction == "ENV" or instruction == "ARG":
                # Check for secret-looking keys
                key = arguments.split("=")[0].split()[0] if arguments else ""
                props["key"] = key
                props["has_secret_pattern"] = bool(_SECRET_ENV_PATTERNS.search(key))

            elif instruction == "RUN":
                props["has_sudo"] = "sudo " in arguments or arguments.startswith("sudo")
                props["has_curl_pipe"] = bool(
                    re.search(r"curl\s+.*\|\s*(sh|bash|zsh)", arguments)
                    or re.search(r"wget\s+.*\|\s*(sh|bash|zsh)", arguments)
                )
                props["has_apt_no_recommends"] = (
                    "apt-get" in arguments
                    and "install" in arguments
                    and "--no-install-recommends" not in arguments
                )

            elif instruction == "ADD":
                add_count += 1
                # Check if source is local (not URL)
                parts = arguments.split()
                if len(parts) >= 2:
                    src = parts[0]
                    props["is_local_add"] = not src.startswith(("http://", "https://"))
                    props["has_sensitive_file"] = bool(
                        re.search(r"\.(key|pem|p12|pfx)$|id_rsa|\.env$", src)
                    )

            elif instruction == "COPY":
                has_chown = "--chown" in arguments or "--chmod" in arguments
                props["has_chown"] = has_chown
                if not has_chown:
                    copy_without_chown += 1
                # Check for sensitive files
                parts = arguments.split()
                src_parts = [p for p in parts if not p.startswith("--") and p != parts[-1]]
                for src in src_parts:
                    if re.search(r"\.(key|pem|p12|pfx)$|id_rsa|\.env$", src):
                        props["has_sensitive_file"] = True

            elif instruction == "WORKDIR":
                has_workdir = True

            elif instruction == "ENTRYPOINT":
                entrypoint_count += 1

            resources.append(
                ParsedResource(
                    resource_type=resource_type,
                    address=address,
                    name=f"{instruction} {arguments[:50]}",
                    provider="docker",
                    properties=props,
                    source_location=f"{source_path}:{line_num}",
                )
            )

        # Synthetic summary resource
        summary_props: dict[str, Any] = {
            "has_user": has_user,
            "has_healthcheck": has_healthcheck,
            "uses_latest_tag": uses_latest_tag,
            "exposed_ports": exposed_ports,
            "base_image": base_image,
            "user_value": user_value,
            "has_workdir": has_workdir,
            "entrypoint_count": entrypoint_count,
            "has_ssh_exposed": 22 in exposed_ports,
            "has_privileged_port": any(p < 1024 for p in exposed_ports),
            "add_count": add_count,
            "copy_without_chown": copy_without_chown,
            "is_root_user": user_value.lower() in ("root", "0"),
        }

        resources.append(
            ParsedResource(
                resource_type="dockerfile_image",
                address="dockerfile.image.summary",
                name=f"Dockerfile ({base_image or 'unknown'})",
                provider="docker",
                properties=summary_props,
                source_location=source_path,
            )
        )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="dockerfile",
        )

    def _parse_instructions(self, content: str) -> list[tuple[str, str, int]]:
        """Parse Dockerfile content, handling line continuations."""
        # Join continuation lines
        content = re.sub(r"\\\s*\n", " ", content)

        instructions: list[tuple[str, str, int]] = []
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _INSTRUCTION_RE.match(stripped)
            if match:
                instructions.append(
                    (match.group("instruction"), match.group("arguments"), line_num)
                )

        return instructions
