"""Built-in secret detection patterns."""

from __future__ import annotations

import re

from threatcode.engine.secrets.rules import SecretRule

# Common allow-list patterns (test values, examples, placeholders)
_COMMON_ALLOW = [
    re.compile(r"(?i)(example|test|dummy|fake|placeholder|sample|changeme|xxx+|your[_-])"),
    re.compile(r"<[A-Z_]+>"),  # Placeholder like <YOUR_API_KEY>
    re.compile(r"\$\{"),  # Template variables like ${VAR}
]


def get_builtin_rules() -> list[SecretRule]:
    """Return all built-in secret detection rules."""
    return [
        # AWS
        SecretRule(
            id="SECRET_AWS_ACCESS_KEY",
            category="aws",
            title="AWS Access Key ID",
            severity="critical",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)"),
            keywords=["AKIA"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        SecretRule(
            id="SECRET_AWS_SECRET_KEY",
            category="aws",
            title="AWS Secret Access Key",
            severity="critical",
            regex=re.compile(
                r"(?i)(?:aws_secret|secret_access_key|aws_secret_access_key)"
                r"[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            ),
            keywords=["aws_secret", "secret_access_key"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # GitHub
        SecretRule(
            id="SECRET_GITHUB_PAT",
            category="github",
            title="GitHub Personal Access Token",
            severity="critical",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(gh[ps]_[A-Za-z0-9_]{36,})(?:[^A-Za-z0-9]|$)"),
            keywords=["ghp_", "ghs_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        SecretRule(
            id="SECRET_GITHUB_FINE_GRAINED",
            category="github",
            title="GitHub Fine-Grained Token",
            severity="critical",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(github_pat_[A-Za-z0-9_]{22,})(?:[^A-Za-z0-9]|$)"),
            keywords=["github_pat_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # GitLab
        SecretRule(
            id="SECRET_GITLAB_PAT",
            category="gitlab",
            title="GitLab Personal Access Token",
            severity="critical",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(glpat-[A-Za-z0-9\-_]{20,})(?:[^A-Za-z0-9]|$)"),
            keywords=["glpat-"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Slack
        SecretRule(
            id="SECRET_SLACK_TOKEN",
            category="slack",
            title="Slack Token",
            severity="high",
            regex=re.compile(
                r"(?:^|[^A-Za-z0-9])(xox[bpors]-[A-Za-z0-9\-]{10,})(?:[^A-Za-z0-9]|$)"
            ),
            keywords=["xoxb-", "xoxp-", "xoxo-", "xoxr-", "xoxs-"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Private keys
        SecretRule(
            id="SECRET_PRIVATE_KEY",
            category="crypto",
            title="Private Key",
            severity="critical",
            regex=re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"),
            keywords=["PRIVATE KEY"],
            allow_rules=[],
        ),
        # JWT
        SecretRule(
            id="SECRET_JWT",
            category="auth",
            title="JSON Web Token",
            severity="medium",
            regex=re.compile(
                r"(?:^|[^A-Za-z0-9])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"
            ),
            keywords=["eyJ"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Database connection strings
        SecretRule(
            id="SECRET_DB_CONNECTION_STRING",
            category="database",
            title="Database Connection String",
            severity="high",
            regex=re.compile(
                r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                r"[^\s'\"<>]{5,}"
            ),
            keywords=[
                "postgres://",
                "postgresql://",
                "mysql://",
                "mongodb://",
                "redis://",
                "amqp://",
            ],
            allow_rules=[
                re.compile(r"localhost"),
                re.compile(r"127\.0\.0\.1"),
                re.compile(r"example\.com"),
                *_COMMON_ALLOW,
            ],
        ),
        # Azure
        SecretRule(
            id="SECRET_AZURE_CLIENT_SECRET",
            category="azure",
            title="Azure Client Secret",
            severity="critical",
            regex=re.compile(
                r"(?i)(?:azure[_-]?client[_-]?secret|AZURE_CLIENT_SECRET)"
                r"[\s]*[=:]\s*['\"]?([A-Za-z0-9~._\-]{34,})['\"]?"
            ),
            keywords=["azure_client_secret", "AZURE_CLIENT_SECRET"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # GCP Service Account
        SecretRule(
            id="SECRET_GCP_SERVICE_ACCOUNT",
            category="gcp",
            title="GCP Service Account Key",
            severity="critical",
            regex=re.compile(r'"type"\s*:\s*"service_account"'),
            keywords=["service_account", "private_key_id"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Generic password patterns
        SecretRule(
            id="SECRET_GENERIC_PASSWORD",
            category="generic",
            title="Generic Password Assignment",
            severity="medium",
            regex=re.compile(r"(?i)(?:password|passwd|pwd)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]"),
            keywords=["password", "passwd", "pwd"],
            allow_rules=[
                re.compile(r"(?i)(example|test|dummy|placeholder|changeme|xxx|your|password_here)"),
                re.compile(r"\$\{"),
                re.compile(r"<[A-Z_]+>"),
                re.compile(r"\*{3,}"),
            ],
        ),
        # Generic API Key
        SecretRule(
            id="SECRET_GENERIC_API_KEY",
            category="generic",
            title="Generic API Key Assignment",
            severity="medium",
            regex=re.compile(
                r"(?i)(?:api[_-]?key|apikey)[\s]*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"
            ),
            keywords=["api_key", "apikey", "api-key"],
            allow_rules=[
                *_COMMON_ALLOW,
                re.compile(r"\*{3,}"),
            ],
        ),
        # Generic Secret
        SecretRule(
            id="SECRET_GENERIC_SECRET",
            category="generic",
            title="Generic Secret Assignment",
            severity="medium",
            regex=re.compile(
                r"(?i)(?:secret|token|auth[_-]?token)[\s]*[=:]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]"
            ),
            keywords=["secret", "token", "auth_token"],
            allow_rules=[
                *_COMMON_ALLOW,
                re.compile(r"\*{3,}"),
            ],
        ),
        # Stripe
        SecretRule(
            id="SECRET_STRIPE_KEY",
            category="stripe",
            title="Stripe API Key",
            severity="critical",
            regex=re.compile(
                r"(?:^|[^A-Za-z0-9])((?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,})(?:[^A-Za-z0-9]|$)"
            ),
            keywords=["sk_live_", "sk_test_", "pk_live_", "pk_test_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Twilio
        SecretRule(
            id="SECRET_TWILIO_KEY",
            category="twilio",
            title="Twilio API Key",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(SK[0-9a-fA-F]{32})(?:[^A-Za-z0-9]|$)"),
            keywords=["twilio", "TWILIO"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # SendGrid
        SecretRule(
            id="SECRET_SENDGRID_KEY",
            category="sendgrid",
            title="SendGrid API Key",
            severity="high",
            regex=re.compile(
                r"(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,})(?:[^A-Za-z0-9]|$)"
            ),
            keywords=["SG."],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # NPM Token
        SecretRule(
            id="SECRET_NPM_TOKEN",
            category="npm",
            title="NPM Access Token",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(npm_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9]|$)"),
            keywords=["npm_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Heroku
        SecretRule(
            id="SECRET_HEROKU_KEY",
            category="heroku",
            title="Heroku API Key",
            severity="high",
            regex=re.compile(
                r"(?i)(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)"
                r"[\s]*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"
            ),
            keywords=["heroku", "HEROKU_API_KEY"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Mailgun
        SecretRule(
            id="SECRET_MAILGUN_KEY",
            category="mailgun",
            title="Mailgun API Key",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(key-[A-Za-z0-9]{32,})(?:[^A-Za-z0-9]|$)"),
            keywords=["mailgun", "key-"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Square
        SecretRule(
            id="SECRET_SQUARE_TOKEN",
            category="square",
            title="Square Access Token",
            severity="high",
            regex=re.compile(
                r"(?:^|[^A-Za-z0-9])(sq0[a-z]{3}-[A-Za-z0-9\-_]{22,})(?:[^A-Za-z0-9]|$)"
            ),
            keywords=["sq0"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Shopify
        SecretRule(
            id="SECRET_SHOPIFY_TOKEN",
            category="shopify",
            title="Shopify Access Token",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(shpat_[A-Fa-f0-9]{32,})(?:[^A-Za-z0-9]|$)"),
            keywords=["shpat_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Databricks
        SecretRule(
            id="SECRET_DATABRICKS_TOKEN",
            category="databricks",
            title="Databricks Access Token",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(dapi[a-f0-9]{32,})(?:[^A-Za-z0-9]|$)"),
            keywords=["dapi"],
            allow_rules=list(_COMMON_ALLOW),
        ),
        # Linear
        SecretRule(
            id="SECRET_LINEAR_KEY",
            category="linear",
            title="Linear API Key",
            severity="high",
            regex=re.compile(r"(?:^|[^A-Za-z0-9])(lin_api_[A-Za-z0-9]{40,})(?:[^A-Za-z0-9]|$)"),
            keywords=["lin_api_"],
            allow_rules=list(_COMMON_ALLOW),
        ),
    ]
