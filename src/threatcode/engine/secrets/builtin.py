"""Built-in secret detection patterns.

Every pattern captures the secret in a named group ``secret``.
The scanner redacts, de-duplicates and allow-lists that span only, so the key name or the quotes
around a value never take part.

The scanner is best effort: it knows the credential shapes that show up in infrastructure code and
in agent configuration, and it keeps false positives low enough to feed a threat model.
It is not a replacement for a dedicated scanner such as Gitleaks; ingest its SARIF with
``threatcode scan --ingest`` for broad coverage.

Bounded repetition (``{min,max}``) is used for every unbounded-looking value so that a very long
line cannot make a pattern run for long.
"""

from __future__ import annotations

import re
from typing import Final

from threatcode.engine.secrets.rules import SecretRule

# A value that merely excuses itself as a sample inside a random provider token. Generic rules do
# not use this list: a substring such as "test" or "sample" inside a real-looking password must
# not suppress it.
_PROVIDER_ALLOW: Final = (re.compile(r"(?i)example|dummy|fake|placeholder|sample|x{6,}|0{10,}"),)

# Hosts of a local or documentation URL, matched against the host component alone
_LOCAL_HOSTS: Final = (
    re.compile(
        r"(?i)^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal"
        r"|(?:[a-z0-9-]+\.)*example\.(?:com|org|net)|(?:[a-z0-9-]+\.)*localhost)$"
    ),
)

_DB_SCHEMES: Final = (
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver"
    r"|oracle|cockroachdb|clickhouse)"
)


def _token(body: str) -> re.Pattern[str]:
    """A provider token: captured whole and not part of a longer alphanumeric run."""
    return re.compile(rf"(?<![A-Za-z0-9])(?P<secret>{body})(?![A-Za-z0-9])")


def _assignment(
    key: str, *, min_len: int, max_len: int = 256, charset: str | None = None
) -> re.Pattern[str]:
    """``key = value`` in dotenv, YAML, JSON, HCL, shell and source code.

    The key may be quoted (``"password": "x"``), the value may be quoted or bare.
    A quoted value may hold anything but its own quote; a bare value stops at whitespace, ``;`` or
    ``,`` and must not start like a template or an expression.
    ``charset`` limits the characters of the value for token-like secrets.
    """
    bare_class = charset or r"""[^\s"'`;,{}()\[\]<>\\]"""
    quoted_class = rf"(?:{charset})" if charset else r"[^\r\n]"
    return re.compile(
        rf"(?i)(?:{key})[\"']?[ \t]{{0,32}}(?::=|=>|[=:])[ \t]{{0,32}}(?![=~>])"
        r"""(?P<q>["'])?"""
        r"(?P<secret>(?(q)"
        rf"(?:(?!(?P=q)){quoted_class}){{{min_len},{max_len}}}"
        rf"|(?![$<!*&])(?:{bare_class}){{{min_len},{max_len}}}"
        r"))"
        r"(?(q)(?P=q)|(?=[\s;,)}\]]|$))"
    )


_TOKEN_CHARS: Final = r"[A-Za-z0-9_\-/+=.~]"  # noqa: S105 - a regex character class

_RULES: Final[tuple[SecretRule, ...]] = (
    # AWS
    SecretRule(
        id="SECRET_AWS_ACCESS_KEY",
        category="aws",
        title="AWS Access Key ID",
        severity="critical",
        regex=_token(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
        keywords=["akia", "asia"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_AWS_SECRET_KEY",
        category="aws",
        title="AWS Secret Access Key",
        severity="critical",
        regex=re.compile(
            r"(?i)(?:aws[_-]?secret(?:[_-]?access)?(?:[_-]?key)?|secret[_-]?access[_-]?key)"
            r"[\"']?[ \t]{0,32}[=:][ \t]{0,32}[\"']?"
            r"(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        keywords=[
            "aws_secret",
            "aws-secret",
            "awssecret",
            "secret_access_key",
            "secret-access-key",
            "secretaccesskey",
        ],
        allow_values=_PROVIDER_ALLOW,
        min_classes=2,
    ),
    # GitHub
    SecretRule(
        id="SECRET_GITHUB_PAT",
        category="github",
        title="GitHub Token",
        severity="critical",
        regex=_token(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        keywords=["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_GITHUB_FINE_GRAINED",
        category="github",
        title="GitHub Fine-Grained Token",
        severity="critical",
        regex=_token(r"github_pat_[A-Za-z0-9_]{22,255}"),
        keywords=["github_pat_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # GitLab
    SecretRule(
        id="SECRET_GITLAB_PAT",
        category="gitlab",
        title="GitLab Personal Access Token",
        severity="critical",
        regex=_token(r"glpat-[A-Za-z0-9\-_]{20,}"),
        keywords=["glpat-"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Slack
    SecretRule(
        id="SECRET_SLACK_TOKEN",
        category="slack",
        title="Slack Token",
        severity="high",
        regex=_token(r"(?:xox[abposr]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+)"),
        keywords=["xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-", "xapp-"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_SLACK_WEBHOOK",
        category="slack",
        title="Slack Incoming Webhook URL",
        severity="high",
        regex=re.compile(
            r"hooks\.slack\.com/services/(?P<secret>T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,})"
        ),
        keywords=["hooks.slack.com"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Private keys: PKCS#1, PKCS#8, SEC1, OpenSSH, PGP and encrypted PKCS#8
    SecretRule(
        id="SECRET_PRIVATE_KEY",
        category="crypto",
        title="Private Key",
        severity="critical",
        regex=re.compile(
            r"(?P<secret>-----BEGIN[ \t]+(?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)[ \t]+)?"
            r"PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----)"
        ),
        keywords=["private key"],
    ),
    # JWT
    SecretRule(
        id="SECRET_JWT",
        category="auth",
        title="JSON Web Token",
        severity="medium",
        regex=_token(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        keywords=["eyj"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Credentials in a URL: database connection strings first, then any other scheme
    SecretRule(
        id="SECRET_DB_CONNECTION_STRING",
        category="database",
        title="Database Connection String With Credentials",
        severity="high",
        regex=re.compile(
            rf"(?i)(?<![A-Za-z0-9+.\-])(?:{_DB_SCHEMES})://[^\s:/@'\"<>?#]{{1,128}}:"
            r"(?P<secret>[^\s/@'\"<>?#]{3,128})@(?P<host>\[[0-9A-Fa-f:]{2,45}\]|[^\s/:'\"<>?#@\[\]]{1,255})"
        ),
        keywords=["://"],
        kind="structure",
        keyed=False,
        allow_hosts=_LOCAL_HOSTS,
    ),
    SecretRule(
        id="SECRET_URL_CREDENTIALS",
        category="url",
        title="Credentials in URL",
        severity="high",
        regex=re.compile(
            rf"(?i)(?<![A-Za-z0-9+.\-])(?!{_DB_SCHEMES}://)[A-Za-z][A-Za-z0-9+.\-]{{1,24}}://"
            r"[^\s:/@'\"<>?#]{1,128}:(?P<secret>[^\s/@'\"<>?#]{3,128})@"
            r"(?P<host>\[[0-9A-Fa-f:]{2,45}\]|[^\s/:'\"<>?#@\[\]]{1,255})"
        ),
        keywords=["://"],
        kind="structure",
        keyed=False,
        allow_hosts=_LOCAL_HOSTS,
    ),
    SecretRule(
        id="SECRET_AUTHORIZATION_HEADER",
        category="auth",
        title="Authorization Header Credential",
        severity="high",
        regex=re.compile(
            r"(?i)authorization[\"']?[ \t]{0,8}[:=][ \t]{0,8}[\"']?(?:bearer|basic|token)[ \t]+"
            r"(?P<secret>[A-Za-z0-9._~+/=\-]{16,1024})(?![A-Za-z0-9._~+/=\-])"
        ),
        keywords=["authorization"],
        kind="structure",
        min_classes=2,
    ),
    SecretRule(
        id="SECRET_CONNECTION_STRING_PASSWORD",
        category="database",
        title="Password in Connection String",
        severity="high",
        regex=re.compile(
            r"(?i)\b(?:server|data[ ]source|host|uid|user[ ]id|username|initial[ ]catalog"
            r"|database)[ \t]{0,8}=[^;\r\n]{1,256};(?:[^;\r\n]{0,256};){0,8}?"
            r"[ \t]{0,8}(?:password|pwd)[ \t]{0,8}=[ \t]{0,8}"
            r"(?P<secret>\{[^}\r\n]{3,128}\}|[^;\s\"'{}]{3,128})"
        ),
        keywords=["password", "pwd"],
        kind="structure",
    ),
    # Azure
    SecretRule(
        id="SECRET_AZURE_CLIENT_SECRET",
        category="azure",
        title="Azure Client Secret",
        severity="critical",
        regex=re.compile(
            r"(?i)azure[_-]?client[_-]?secret[\"']?[ \t]{0,32}[=:][ \t]{0,32}[\"']?"
            r"(?P<secret>[A-Za-z0-9~._\-]{34,})(?![A-Za-z0-9~._\-])"
        ),
        keywords=["azure_client_secret", "azure-client-secret", "azureclientsecret"],
        allow_values=_PROVIDER_ALLOW,
        min_classes=2,
    ),
    SecretRule(
        id="SECRET_AZURE_STORAGE_KEY",
        category="azure",
        title="Azure Storage Account Key",
        severity="critical",
        regex=re.compile(r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{86}==)"),
        keywords=["accountkey="],
        allow_values=_PROVIDER_ALLOW,
    ),
    # GCP: a service account key file carries a private_key field; the stub that only names
    # the account type is not a credential
    SecretRule(
        id="SECRET_GCP_SERVICE_ACCOUNT",
        category="gcp",
        title="GCP Service Account Key",
        severity="critical",
        regex=re.compile(r'"type"\s*:\s*"(?P<secret>service_account)"'),
        keywords=["service_account"],
        requires=re.compile(r'"private_key"\s*:\s*"-----BEGIN'),
    ),
    SecretRule(
        id="SECRET_GOOGLE_API_KEY",
        category="gcp",
        title="Google API Key",
        severity="high",
        regex=_token(r"AIza[0-9A-Za-z_\-]{35}"),
        keywords=["aiza"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # AI providers
    SecretRule(
        id="SECRET_ANTHROPIC_KEY",
        category="anthropic",
        title="Anthropic API Key",
        severity="critical",
        regex=_token(r"sk-ant-[a-z]{3,10}\d{0,3}-[A-Za-z0-9_\-]{32,}"),
        keywords=["sk-ant-"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_OPENAI_KEY",
        category="openai",
        title="OpenAI API Key",
        severity="critical",
        regex=_token(
            r"(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{32,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
        ),
        keywords=["sk-proj-", "sk-svcacct-", "sk-admin-", "t3blbkfj"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_HUGGINGFACE_TOKEN",
        category="huggingface",
        title="Hugging Face Access Token",
        severity="high",
        regex=_token(r"hf_[A-Za-z0-9]{34,}"),
        keywords=["hf_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Stripe: live keys only. Test-mode keys (sk_test_, pk_test_) and publishable keys
    # (pk_live_) are deliberately not matched.
    SecretRule(
        id="SECRET_STRIPE_KEY",
        category="stripe",
        title="Stripe Live Secret Key",
        severity="critical",
        regex=_token(r"(?:sk|rk)_live_[A-Za-z0-9]{24,}"),
        keywords=["sk_live_", "rk_live_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Twilio
    SecretRule(
        id="SECRET_TWILIO_KEY",
        category="twilio",
        title="Twilio API Key",
        severity="high",
        regex=_token(r"SK[0-9a-fA-F]{32}"),
        keywords=["twilio"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # SendGrid
    SecretRule(
        id="SECRET_SENDGRID_KEY",
        category="sendgrid",
        title="SendGrid API Key",
        severity="high",
        regex=_token(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"),
        keywords=["sg."],
        allow_values=_PROVIDER_ALLOW,
    ),
    # npm
    SecretRule(
        id="SECRET_NPM_TOKEN",
        category="npm",
        title="NPM Access Token",
        severity="high",
        regex=_token(r"npm_[A-Za-z0-9]{36,}"),
        keywords=["npm_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    SecretRule(
        id="SECRET_NPMRC_AUTH_TOKEN",
        category="npm",
        title="npm Registry Auth Token",
        severity="high",
        regex=re.compile(
            r"(?i)_authtoken[\"']?[ \t]{0,8}=[ \t]{0,8}[\"']?"
            r"(?P<secret>[A-Za-z0-9._~+/=\-]{16,512})(?![A-Za-z0-9._~+/=\-])"
        ),
        keywords=["_authtoken"],
        kind="structure",
        min_classes=2,
    ),
    # Heroku
    SecretRule(
        id="SECRET_HEROKU_KEY",
        category="heroku",
        title="Heroku API Key",
        severity="high",
        regex=re.compile(
            r"(?i)heroku[_-]?api[_-]?key[\"']?[ \t]{0,32}[=:][ \t]{0,32}[\"']?"
            r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        ),
        keywords=["heroku"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Mailgun
    SecretRule(
        id="SECRET_MAILGUN_KEY",
        category="mailgun",
        title="Mailgun API Key",
        severity="high",
        regex=_token(r"key-[A-Za-z0-9]{32,}"),
        keywords=["mailgun"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Square
    SecretRule(
        id="SECRET_SQUARE_TOKEN",
        category="square",
        title="Square Access Token",
        severity="high",
        regex=_token(r"sq0[a-z]{3}-[A-Za-z0-9\-_]{22,}"),
        keywords=["sq0"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Shopify
    SecretRule(
        id="SECRET_SHOPIFY_TOKEN",
        category="shopify",
        title="Shopify Access Token",
        severity="high",
        regex=_token(r"shpat_[A-Fa-f0-9]{32,}"),
        keywords=["shpat_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Databricks
    SecretRule(
        id="SECRET_DATABRICKS_TOKEN",
        category="databricks",
        title="Databricks Access Token",
        severity="high",
        regex=_token(r"dapi[a-f0-9]{32,}"),
        keywords=["dapi"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Linear
    SecretRule(
        id="SECRET_LINEAR_KEY",
        category="linear",
        title="Linear API Key",
        severity="high",
        regex=_token(r"lin_api_[A-Za-z0-9]{40,}"),
        keywords=["lin_api_"],
        allow_values=_PROVIDER_ALLOW,
    ),
    # Generic assignments: the key name is the only evidence, so these need a long enough value
    # with a mix of characters.
    SecretRule(
        id="SECRET_GENERIC_PASSWORD",
        category="generic",
        title="Generic Password Assignment",
        severity="medium",
        regex=_assignment(r"password|passwd|pwd", min_len=8, max_len=256),
        keywords=["password", "passwd", "pwd"],
        kind="generic",
        min_length=8,
        min_classes=2,
        needs_non_alpha=True,
    ),
    SecretRule(
        id="SECRET_GENERIC_API_KEY",
        category="generic",
        title="Generic API Key Assignment",
        severity="medium",
        regex=_assignment(
            r"api[_-]?key|apikey", min_len=20, max_len=256, charset=r"[A-Za-z0-9_\-]"
        ),
        keywords=["api_key", "apikey", "api-key"],
        kind="generic",
        min_length=20,
        min_classes=2,
    ),
    SecretRule(
        id="SECRET_GENERIC_SECRET",
        category="generic",
        title="Generic Secret Assignment",
        severity="medium",
        regex=_assignment(
            r"secret(?:[_-]?key)?|token", min_len=16, max_len=512, charset=_TOKEN_CHARS
        ),
        keywords=["secret", "token"],
        kind="generic",
        min_length=16,
        min_classes=2,
    ),
)


def get_builtin_rules() -> list[SecretRule]:
    """Return all built-in secret detection rules (a new list; the rule objects are shared)."""
    return list(_RULES)


def entropy_rule(threshold: float) -> SecretRule:
    """The optional high-entropy fallback: a long random-looking value under a credential key.

    It is off unless a configuration asks for it, because entropy alone flags hashes and ids.
    """
    return SecretRule(
        id="SECRET_HIGH_ENTROPY",
        category="generic",
        title="High-Entropy Value Under a Credential Key",
        severity="medium",
        regex=_assignment(
            r"secret|token|credential|passwd|password|pwd|private[_-]?key|api[_-]?key|apikey|key",
            min_len=20,
            max_len=512,
            charset=_TOKEN_CHARS,
        ),
        keywords=["secret", "token", "credential", "passwd", "password", "pwd", "key"],
        kind="generic",
        min_length=20,
        min_classes=3,
        min_entropy=threshold,
    )
