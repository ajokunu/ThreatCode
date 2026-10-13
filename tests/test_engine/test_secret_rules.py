"""Tests for secret detection rules: shapes, allow-lists and the checks on captured values."""

from __future__ import annotations

import re
import time

import pytest

from threatcode.engine.secrets.builtin import entropy_rule, get_builtin_rules
from threatcode.engine.secrets.rules import (
    SecretRule,
    char_classes,
    has_template_marker,
    is_env_var_name,
    is_placeholder,
    is_reference,
)
from threatcode.engine.secrets.scanner import SecretScanner


def _join(*parts: str) -> str:
    """Build a token from parts so this file holds no complete credential-shaped string."""
    return "".join(parts)


AWS_KEY = _join("AKIA", "Q4TRB7ZYXWVU3SPN")
AWS_STS_KEY = _join("ASIA", "Q4TRB7ZYXWVU3SPN")
AWS_SECRET = _join("wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYZAB1234CDE")
GITHUB_TAIL = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
BODY = "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7sU9wY1"

# The base64 body of a synthetic private key: 64 characters of an invented value
KEY_BODY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq7Zk2n0xJ1pY4wNcTm1h"
KEY_BODY_LINES = [KEY_BODY[:32], KEY_BODY[32:]]


def pem(label: str = "PRIVATE KEY", body: list[str] | None = None) -> str:
    """A private key block, written as a file would hold it."""
    lines = KEY_BODY_LINES if body is None else body
    return "\n".join([f"-----BEGIN {label}-----", *lines, f"-----END {label}-----"])


# One positive sample per built-in rule; {K} is replaced by a key name where the rule is keyed.
POSITIVE: dict[str, str] = {
    "SECRET_AWS_ACCESS_KEY": f'key = "{AWS_KEY}"',
    "SECRET_AWS_SECRET_KEY": f'{{K}}: "{AWS_SECRET}"',
    "SECRET_GITHUB_PAT": _join("token: gh", "p_", GITHUB_TAIL),
    "SECRET_GITHUB_FINE_GRAINED": _join(
        "token: github", "_pat_", "11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuV"
    ),
    "SECRET_GITLAB_PAT": _join("token: gl", "pat-", "aB3dE5gH7jK9mN1pQ3sT"),
    "SECRET_SLACK_TOKEN": _join("token: xo", "xs-", "1234567890-1234567890123-AbCdEfGhIjKlMnOp"),
    "SECRET_SLACK_WEBHOOK": _join(
        "url: https://hooks.slack",
        ".com/services/",
        "T0A1B2C3D4/B0E5F6G7H8/aBcDeFgHiJkLmNoPqRsTuVwX",
    ),
    "SECRET_PRIVATE_KEY": pem(),
    "SECRET_JWT": _join(
        "t: ey",
        "JhbGciOiJIUzI1NiJ9.",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    ),
    "SECRET_DB_CONNECTION_STRING": "url: postgres://admin:Zx9fQ2mLp7@db.prod.internal:5432/app",
    "SECRET_URL_CREDENTIALS": "url: https://deploy:Zx9fQ2mLp7@git.internal/team/repo.git",
    "SECRET_AUTHORIZATION_HEADER": 'curl -H "Authorization: Bearer aB3dE5gH7jK9mN1pQ3sT5vX7zA"',
    "SECRET_CONNECTION_STRING_PASSWORD": (
        "Server=db;Database=x;User Id=sa;Password=Zx9fQ2mLp7Tr;Encrypt=True;"
    ),
    "SECRET_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET=aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3k",
    "SECRET_AZURE_STORAGE_KEY": "AccountKey=" + (BODY * 2)[:86] + "==",
    "SECRET_GCP_SERVICE_ACCOUNT": (
        '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}'
    ),
    "SECRET_GOOGLE_API_KEY": _join("key: AI", "zaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    "SECRET_ANTHROPIC_KEY": _join("key: sk", "-ant-", "api03-", BODY),
    "SECRET_OPENAI_KEY": _join("key: sk", "-proj-", BODY),
    "SECRET_HUGGINGFACE_TOKEN": _join("token: hf", "_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"),
    "SECRET_STRIPE_KEY": _join("key: sk", "_live_", "AbCdEfGhIjKlMnOpQrStUvWx"),
    "SECRET_TWILIO_KEY": _join("TWILIO_KEY=S", "K", "0123456789abcdef0123456789abcdef"),
    "SECRET_SENDGRID_KEY": _join(
        "key: S", "G.", "aB3dE5gH7jK9mN1pQ3sT5v.", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7sU9"
    ),
    "SECRET_NPM_TOKEN": _join("token: npm", "_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"),
    "SECRET_NPMRC_AUTH_TOKEN": "//registry.example.org/:_authToken=aB3dE5gH7jK9mN1pQ3sT5vX7",
    "SECRET_HEROKU_KEY": "HEROKU_API_KEY=01234567-89ab-cdef-0123-456789abcdef",
    "SECRET_MAILGUN_KEY": _join("mailgun: ke", "y-", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI"),
    "SECRET_SQUARE_TOKEN": _join("token: sq0", "atp-", "aB3dE5gH7jK9mN1pQ3sT5vX"),
    "SECRET_SHOPIFY_TOKEN": _join("token: shp", "at_", "0123456789abcdef0123456789abcdef"),
    "SECRET_DATABRICKS_TOKEN": _join("token: da", "pi", "0123456789abcdef0123456789abcdef"),
    "SECRET_LINEAR_KEY": _join("key: lin", "_api_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7s"),
    "SECRET_GENERIC_PASSWORD": '{K}: "Tr0ub4dor&3xKcd77"',
    "SECRET_GENERIC_API_KEY": '{K}: "aB3dE5gH7jK9mN1pQ3sT5vX7zA"',
    "SECRET_GENERIC_SECRET": '{K}: "aB3dE5gH7jK9mN1pQ3sT5vX7zA"',
}

# A near miss for each rule: the same shape with the property that makes it harmless.
NEGATIVE: dict[str, str] = {
    "SECRET_AWS_ACCESS_KEY": f'key = "{AWS_KEY[:-1]}"',
    "SECRET_AWS_SECRET_KEY": 'aws_secret_access_key: "short"',
    "SECRET_GITHUB_PAT": _join("token: gh", "p_", "tooshort"),
    "SECRET_GITHUB_FINE_GRAINED": _join("token: github", "_pat_", "short"),
    "SECRET_GITLAB_PAT": _join("token: gl", "pat-", "short"),
    "SECRET_SLACK_TOKEN": _join("token: xo", "xb-", "short"),
    "SECRET_SLACK_WEBHOOK": "url: https://hooks.slack.com/services/docs",
    "SECRET_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
    "SECRET_JWT": "t: eyJhbGciOiJIUzI1NiJ9.notatoken",
    "SECRET_DB_CONNECTION_STRING": "url: postgres://admin:Zx9fQ2mLp7@localhost:5432/app",
    "SECRET_URL_CREDENTIALS": "url: https://git.internal/team/repo.git",
    "SECRET_AUTHORIZATION_HEADER": 'curl -H "Authorization: Bearer ${API_TOKEN}"',
    "SECRET_CONNECTION_STRING_PASSWORD": "Server=db;Database=x;User Id=sa;Password=${DB_PASS};",
    "SECRET_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}",
    "SECRET_AZURE_STORAGE_KEY": "AccountKey=short==",
    "SECRET_GCP_SERVICE_ACCOUNT": '{"type": "service_account", "project_id": "demo"}',
    "SECRET_GOOGLE_API_KEY": "key: AIzaShort",
    "SECRET_ANTHROPIC_KEY": _join("key: sk", "-ant-", "api03-short"),
    "SECRET_OPENAI_KEY": _join("key: sk", "-proj-", "short"),
    "SECRET_HUGGINGFACE_TOKEN": _join("token: hf", "_", "short"),
    "SECRET_STRIPE_KEY": _join("key: sk", "_test_", "AbCdEfGhIjKlMnOpQrStUvWx"),
    "SECRET_TWILIO_KEY": _join("TWILIO_KEY=S", "K", "nothex"),
    "SECRET_SENDGRID_KEY": _join("key: S", "G.", "short"),
    "SECRET_NPM_TOKEN": _join("token: npm", "_", "short"),
    "SECRET_NPMRC_AUTH_TOKEN": "//registry.example.org/:_authToken=${NPM_TOKEN}",
    "SECRET_HEROKU_KEY": "HEROKU_API_KEY=not-a-uuid",
    "SECRET_MAILGUN_KEY": _join("mailgun: ke", "y-", "short"),
    "SECRET_SQUARE_TOKEN": _join("token: sq0", "atp-", "short"),
    "SECRET_SHOPIFY_TOKEN": _join("token: shp", "at_", "short"),
    "SECRET_DATABRICKS_TOKEN": _join("token: da", "pi", "short"),
    "SECRET_LINEAR_KEY": _join("key: lin", "_api_", "short"),
    "SECRET_GENERIC_PASSWORD": '{K}: "changeme"',
    "SECRET_GENERIC_API_KEY": '{K}: "${API_KEY}"',
    "SECRET_GENERIC_SECRET": '{K}: "MY_APP_SECRET_NAME"',
}

# The key a keyed sample uses, and the same key in capitals
KEYS: dict[str, str] = {
    "SECRET_AWS_SECRET_KEY": "aws_secret_access_key",
    "SECRET_GENERIC_PASSWORD": "DbPassword",
    "SECRET_GENERIC_API_KEY": "api_key",
    "SECRET_GENERIC_SECRET": "client_secret",
}


def _render(sample: str, rule_id: str, *, upper_key: bool = False) -> str:
    key = KEYS.get(rule_id, "")
    return sample.replace("{K}", key.upper() if upper_key else key)


def _ids(text: str, path: str = "sample.txt") -> list[str]:
    return [m.rule.id for m in SecretScanner().scan_text(text, path=path).matches]


@pytest.fixture(scope="module")
def rules() -> dict[str, SecretRule]:
    return {r.id: r for r in get_builtin_rules()}


class TestBuiltinRules:
    def test_rules_loaded(self, rules: dict[str, SecretRule]) -> None:
        assert len(rules) >= 30

    def test_all_rules_have_required_fields(self, rules: dict[str, SecretRule]) -> None:
        for rule in rules.values():
            assert rule.id.startswith("SECRET_")
            assert rule.category, f"Rule {rule.id} missing category"
            assert rule.title, f"Rule {rule.id} missing title"
            assert rule.severity in ("critical", "high", "medium", "low")
            assert rule.kind in ("provider", "structure", "generic")

    def test_unique_rule_ids(self) -> None:
        ids = [r.id for r in get_builtin_rules()]
        assert len(ids) == len(set(ids))

    def test_every_regex_captures_the_secret_in_a_named_group(
        self, rules: dict[str, SecretRule]
    ) -> None:
        for rule in rules.values():
            assert "secret" in rule.regex.groupindex, rule.id

    def test_keywords_are_lower_case_at_construction(self, rules: dict[str, SecretRule]) -> None:
        for rule in rules.values():
            assert all(kw == kw.lower() for kw in rule.keywords), rule.id

    def test_every_rule_has_a_positive_and_a_negative_sample(
        self, rules: dict[str, SecretRule]
    ) -> None:
        assert set(POSITIVE) == set(rules)
        assert set(NEGATIVE) == set(rules)

    def test_rule_construction_lowercases_keywords(self) -> None:
        rule = SecretRule("SECRET_X", "x", "X", "low", re.compile("x"), keywords=["AKIA", "Foo"])
        assert rule.keywords == ("akia", "foo")


class TestEveryRuleDetectsItsSample:
    @pytest.mark.parametrize("rule_id", sorted(POSITIVE))
    def test_positive(self, rule_id: str) -> None:
        found = _ids(_render(POSITIVE[rule_id], rule_id))
        assert rule_id in found, (rule_id, found)

    @pytest.mark.parametrize("rule_id", sorted(NEGATIVE))
    def test_negative(self, rule_id: str) -> None:
        found = _ids(_render(NEGATIVE[rule_id], rule_id))
        assert rule_id not in found, (rule_id, found)

    @pytest.mark.parametrize("rule_id", sorted(KEYS))
    def test_keys_match_in_capitals_like_in_lower_case(self, rule_id: str) -> None:
        """The keyword prefilter is as case-insensitive as the (?i) regexes behind it."""
        lower = _ids(_render(POSITIVE[rule_id], rule_id))
        upper = _ids(_render(POSITIVE[rule_id], rule_id, upper_key=True))
        assert rule_id in lower
        assert rule_id in upper

    @pytest.mark.parametrize(
        "rule_id",
        sorted(
            r.id
            for r in get_builtin_rules()
            if r.regex.flags & re.IGNORECASE and r.id in POSITIVE and "{K}" in POSITIVE[r.id]
        ),
    )
    def test_every_case_insensitive_keyed_rule_is_exercised_in_capitals(self, rule_id: str) -> None:
        assert rule_id in KEYS


class TestProviderShapes:
    def test_aws_temporary_keys_are_found_next_to_long_lived_ones(self) -> None:
        text = f'a = "{AWS_KEY}"\nb = "{AWS_STS_KEY}"\n'
        matches = SecretScanner().scan_text(text).matches
        assert [m.line for m in matches] == [1, 2]
        assert {m.rule.id for m in matches} == {"SECRET_AWS_ACCESS_KEY"}

    @pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
    def test_github_token_prefixes(self, prefix: str) -> None:
        text = f"token: {prefix}{GITHUB_TAIL}"
        assert "SECRET_GITHUB_PAT" in _ids(text)

    @pytest.mark.parametrize(
        "label",
        [
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ],
    )
    def test_private_key_blocks(self, label: str) -> None:
        assert "SECRET_PRIVATE_KEY" in _ids(pem(label))

    @pytest.mark.parametrize(
        "label", ["CERTIFICATE", "PUBLIC KEY", "CERTIFICATE REQUEST", "X509 CRL"]
    )
    def test_public_material_is_not_a_private_key(self, label: str) -> None:
        assert "SECRET_PRIVATE_KEY" not in _ids(pem(label))

    def test_openai_legacy_key_shape(self) -> None:
        legacy = _join("key: sk", "-", "A" * 20, "T3Blbk", "FJ", "B" * 20)
        assert "SECRET_OPENAI_KEY" in _ids(legacy)

    def test_service_account_stub_without_a_private_key_is_not_a_credential(self) -> None:
        stub = '{"type": "service_account", "client_email": "x@y.iam.gserviceaccount.com"}'
        assert _ids(stub, "sa.json") == []

    def test_service_account_key_file_is_found_once_with_its_key(self) -> None:
        full = (
            '{\n  "type": "service_account",\n  "private_key_id": "0123456789abcdef",\n'
            f'  "private_key": "-----BEGIN PRIVATE KEY-----\\n{KEY_BODY}\\n'
            '-----END PRIVATE KEY-----\\n"\n}'
        )
        ids = _ids(full, "sa.json")
        assert ids.count("SECRET_GCP_SERVICE_ACCOUNT") == 1
        assert "SECRET_PRIVATE_KEY" in ids

    def test_stripe_test_mode_keys_are_deliberately_not_matched(self) -> None:
        for prefix in ("sk_test_", "pk_test_", "rk_test_", "pk_live_"):
            assert "SECRET_STRIPE_KEY" not in _ids(
                _join("key: ", prefix[:3], prefix[3:], "AbCdEfGhIjKlMnOpQrStUvWx")
            )

    def test_aws_documentation_example_key_is_allow_listed(self) -> None:
        assert _ids('key = "AKIAIOSFODNN7EXAMPLE"') == []

    def test_a_token_run_longer_than_the_shape_is_not_cut_in_the_middle(self) -> None:
        assert _ids(f"x = A{AWS_KEY}") == []


class TestAllowListsApplyToTheValue:
    def test_key_name_containing_test_does_not_suppress(self) -> None:
        assert "SECRET_GENERIC_PASSWORD" in _ids('TestPassword: "Zx9fQ2mLp7Tr0ub4"')

    def test_latest_prod_host_does_not_suppress_a_connection_string(self) -> None:
        text = "postgres://admin:Zx9fQ2mLp7@db.latest-prod.internal:5432/app"
        assert "SECRET_DB_CONNECTION_STRING" in _ids(text)

    def test_localhost_elsewhere_in_the_url_does_not_suppress(self) -> None:
        text = "postgres://admin:Zx9fQ2mLp7@db.prod.internal/localhost"
        assert "SECRET_DB_CONNECTION_STRING" in _ids(text)

    def test_localhost_host_is_allow_listed(self) -> None:
        for host in ("localhost", "127.0.0.1", "[::1]", "db.localhost"):
            assert _ids(f"postgres://admin:Zx9fQ2mLp7@{host}:5432/app") == [], host

    @pytest.mark.parametrize("word", ["your", "sample", "test", "example", "dummy", "fake"])
    def test_placeholder_words_inside_a_real_looking_value_do_not_suppress(self, word: str) -> None:
        assert "SECRET_GENERIC_PASSWORD" in _ids(f'password: "Zx9{word}Q2mLp7"')

    @pytest.mark.parametrize(
        "value",
        [
            "changeme",
            "CHANGE_ME_BEFORE_DEPLOY",
            "example",
            "your_password_here",
            "your-api-key",
            "<REPLACE_WITH_SECRETS_MANAGER_REF>",
            "xxxxxxxxxx",
            "**********",
            "replace_me_1234",
            "insert_password_here",
            "(sensitive)",
            "(known after apply)",
            "sensitive",
        ],
    )
    def test_whole_value_placeholders_are_suppressed(self, value: str) -> None:
        assert _ids(f'password: "{value}"') == []

    def test_user_allow_patterns_are_searched_in_the_value_only(self) -> None:
        from threatcode.engine.secrets.config import SecretScanConfig

        scanner = SecretScanner(SecretScanConfig(allow_patterns=[r"^Zx9"]))
        assert scanner.scan_text('password: "Zx9fQ2mLp7Tr0ub4"').matches == []
        # The same pattern aimed at the key must not suppress anything
        keyed = SecretScanner(SecretScanConfig(allow_patterns=["password"]))
        assert keyed.scan_text('password: "Zx9fQ2mLp7Tr0ub4"').matches


class TestTemplatesAndReferences:
    @pytest.mark.parametrize(
        "line",
        [
            'password: "{{ .Values.db.password }}"',
            'db_password: "{{ vault_db_password }}"',
            "password: {{ .Values.db.password }}",
            'password: "{% raw %}secret{% endraw %}"',
            "password: ${DB_PASSWORD}",
            'DB_PASSWORD="${DB_PASSWORD}"',
            'password = "$(cat /run/secrets/db)"',
            "password: ${{ secrets.DB_PASSWORD }}",
            "password: ANTHROPIC_AUTH_TOKEN",
            "auth_token: ANTHROPIC_AUTH_TOKEN",
            "password = var.database_password",
            "master_password = random_password.db.result",
            "password = data.aws_secretsmanager_secret_version.db.secret_string",
            "password: /run/secrets/db_password",
            "PWD=/home/user/work",
            'password: "https://vault.internal/db"',
            'password: ""',
            'MasterUserPassword: "{{resolve:secretsmanager:db:SecretString:password}}"',
            "MasterUserPassword: !Ref DbPassword",
        ],
    )
    def test_not_a_literal_secret(self, line: str) -> None:
        assert _ids(line) == [], line

    def test_helpers(self) -> None:
        assert has_template_marker("a{{b}}") and has_template_marker("${X}")
        assert has_template_marker("$(cat x)") and not has_template_marker("plain")
        assert is_env_var_name("ANTHROPIC_AUTH_TOKEN") and not is_env_var_name("hunter22")
        assert is_reference("var.db_password") and is_reference("a.b[0].c")
        assert not is_reference("Zx9f.Q2mLp7!") and not is_reference("plain")
        assert is_placeholder("changeme") and is_placeholder("<TOKEN>")
        assert not is_placeholder("Zx9changeme7")
        assert char_classes("my_secret_value") == 1
        assert char_classes("Tr0ub4dor&3xKcd77") == 4


class TestGenericShapes:
    @pytest.mark.parametrize(
        ("line", "path"),
        [
            ("ADMIN_PASSWORD=Zx9fQ2mLp7Tr0ub4", "app.env"),
            ("export DB_PASSWORD=Zx9fQ2mLp7Tr0ub4", "run.sh"),
            ("  POSTGRES_PASSWORD: Zx9fQ2mLp7Tr0ub4", "compose.yml"),
            ('{"password": "Zx9fQ2mLp7Tr0ub4"}', "config.json"),
            ('{"Password": "Zx9fQ2mLp7Tr0ub4"}', "config.json"),
            ('administrator_login_password = "Zx9fQ2mLp7Tr0ub4"', "main.tf"),
            ('master_password = "Zx9fQ2mLp7Tr0ub4"', "main.tf"),
            ('MasterUserPassword: "WarehouseP@ss2026"', "stack.yaml"),
            ("password='Zx9fQ2mLp7Tr0ub4'", "settings.py"),
            ("password => 'Zx9fQ2mLp7Tr0ub4'", "init.pp"),
            ("Password=Zx9fQ2mLp7Tr0ub4;", "app.config"),
        ],
    )
    def test_value_forms(self, line: str, path: str) -> None:
        assert "SECRET_GENERIC_PASSWORD" in _ids(line, path), line

    @pytest.mark.parametrize(
        "line",
        [
            'password: "short1!"',
            'password: "alllowercaseletters"',
            "password: 12345678901",
            'password == "Zx9fQ2mLp7Tr0ub4"',
            "password_policy: Zx9fQ2mLp7Tr0ub4",
            'api_key: "abcdefghijklmnopqrstuv"',
            'token: "this is a sentence with spaces"',
        ],
    )
    def test_generic_rules_need_length_and_character_mix(self, line: str) -> None:
        assert not [i for i in _ids(line) if i.startswith("SECRET_GENERIC")], line

    def test_overlapping_matches_report_the_more_specific_rule(self) -> None:
        ids = _ids("Server=db;Database=x;User Id=sa;Password=Zx9fQ2mLp7Tr;")
        assert ids == ["SECRET_CONNECTION_STRING_PASSWORD"]
        assert _ids(f'api_key = "{AWS_KEY}"') == ["SECRET_AWS_ACCESS_KEY"]

    def test_entropy_fallback_is_off_by_default_and_opt_in(self) -> None:
        from threatcode.engine.secrets.config import SecretScanConfig

        line = 'session_key: "q8Zk3vN1xT7mWb4RpL9sYd2HcFa6JeUg"'
        assert SecretScanner().scan_text(line).matches == []
        on = SecretScanner(SecretScanConfig(entropy_threshold=3.5))
        assert [m.rule.id for m in on.scan_text(line).matches] == ["SECRET_HIGH_ENTROPY"]
        assert entropy_rule(3.0).min_entropy == 3.0
        flat = 'session_key: "aaaaaaaaaaaaaaaaaaaaBBBBBBBBBB1"'
        assert on.scan_text(flat).matches == []


def _scan(text: str, path: str = "values.yaml", *, templated: bool = False) -> list[str]:
    outcome = SecretScanner().scan_text(text, path=path, templated=templated)
    return [m.rule.id for m in outcome.matches]


class TestPrivateKeysNeedAWholeBlock:
    """RW-03: a comment that names the header is not a key, a block with a body is."""

    # The two lines of bitnami/nginx values.yaml that were reported as critical
    NGINX_COMMENTS = (
        "  ## key and certificate should start with -----BEGIN CERTIFICATE----- or\n"
        "  ## -----BEGIN RSA PRIVATE KEY-----\n"
        "  ##\n"
        "  ## name should line up with a tlsSecret set further up\n"
    )

    def test_the_header_in_a_comment_is_not_a_key(self) -> None:
        assert _scan(self.NGINX_COMMENTS) == []

    def test_a_header_with_nothing_after_it_is_not_a_key(self) -> None:
        assert _scan("-----BEGIN RSA PRIVATE KEY-----") == []

    @pytest.mark.parametrize(
        "block",
        [
            pem(body=["..."]),
            pem(body=["# elided"]),
            pem(body=["<paste your key here>"]),
            pem(body=["{{ .Values.tls.key | nindent 4 }}"]),
            pem(body=["${TLS_KEY}"]),
            pem(body=["MIIEow"]),
            pem(body=[]),
        ],
        ids=["ellipsis", "comment", "placeholder", "template", "variable", "too-short", "empty"],
    )
    def test_a_block_with_no_real_body_is_not_a_key(self, block: str) -> None:
        assert "SECRET_PRIVATE_KEY" not in _scan(block)

    def test_a_header_without_a_footer_is_not_a_key(self) -> None:
        text = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(KEY_BODY_LINES) + "\n"
        assert _scan(text) == []

    def test_a_documented_example_with_prose_between_the_markers_is_not_a_key(self) -> None:
        text = (
            "# -----BEGIN RSA PRIVATE KEY-----\n"
            "# paste the base64 of your key on the next line, then close with\n"
            "# -----END RSA PRIVATE KEY-----\n"
        )
        assert _scan(text) == []

    def test_a_block_in_a_yaml_literal_is_a_key_on_its_header_line(self) -> None:
        text = "tls:\n  key: |\n" + "\n".join("    " + line for line in pem().split("\n")) + "\n"
        outcome = SecretScanner().scan_text(text, path="values.yaml")
        (match,) = outcome.matches
        assert match.rule.id == "SECRET_PRIVATE_KEY"
        assert match.line == 3
        assert match.column == 5

    def test_a_commented_out_block_is_still_a_key(self) -> None:
        commented = "\n".join("# " + line for line in pem().split("\n"))
        assert "SECRET_PRIVATE_KEY" in _scan(commented)

    def test_a_block_in_a_json_string_is_found_with_its_escaped_line_breaks(self) -> None:
        text = '{"private_key": "' + pem().replace("\n", "\\n") + '\\n"}'
        assert "SECRET_PRIVATE_KEY" in _scan(text, "key.json")

    def test_a_block_on_one_line_is_found(self) -> None:
        assert "SECRET_PRIVATE_KEY" in _scan('KEY="' + pem().replace("\n", "") + '"', ".env")

    def test_a_terraform_heredoc_is_found(self) -> None:
        text = f"private_key = <<EOT\n{pem()}\nEOT\n"
        assert "SECRET_PRIVATE_KEY" in _scan(text, "main.tf")

    def test_windows_line_endings_do_not_hide_a_block(self) -> None:
        assert "SECRET_PRIVATE_KEY" in _scan(pem().replace("\n", "\r\n"))

    def test_an_encrypted_key_with_its_armor_headers_is_found(self) -> None:
        block = pem(
            "RSA PRIVATE KEY",
            [
                "Proc-Type: 4,ENCRYPTED",
                "DEK-Info: AES-128-CBC,0123456789ABCDEF",
                "",
                *KEY_BODY_LINES,
            ],
        )
        assert "SECRET_PRIVATE_KEY" in _scan(block)

    def test_a_pgp_block_with_its_headers_and_checksum_is_found(self) -> None:
        block = pem("PGP PRIVATE KEY BLOCK", ["Version: GnuPG v2", "", *KEY_BODY_LINES, "=aB3d"])
        assert "SECRET_PRIVATE_KEY" in _scan(block)

    def test_two_blocks_are_two_findings_on_their_own_lines(self) -> None:
        text = pem() + "\n\n" + pem("RSA PRIVATE KEY")
        matches = SecretScanner().scan_text(text).matches
        assert [m.line for m in matches] == [1, 6]

    def test_the_preview_holds_no_character_of_the_key(self) -> None:
        (match,) = SecretScanner().scan_text(pem()).matches
        assert KEY_BODY[:12] not in match.preview
        assert match.preview == f"[REDACTED SECRET_PRIVATE_KEY len={match.length}]"
        assert match.length > len(KEY_BODY)

    def test_a_file_of_unfinished_headers_is_scanned_in_bounded_time(self) -> None:
        text = ("-----BEGIN PRIVATE KEY-----\n" + "A" * 4000 + "\n") * 2000
        started = time.monotonic()
        assert _scan(text) == []
        assert time.monotonic() - started < 20

    def test_a_header_far_from_its_footer_is_not_joined_to_it(self) -> None:
        text = pem(body=[KEY_BODY]).replace("\n" + KEY_BODY, "\n" + KEY_BODY + "\n" + "A" * 20000)
        assert _scan(text) == []


class TestShellVariablesAreNotSecrets:
    """RW-03: a script reads a password from the environment, which is where it is kept."""

    @pytest.mark.parametrize(
        "line",
        [
            "MASTER_PASSWORD='$MARIADB_NEW_REPLICATION_PASSWORD'",
            'export MONGODB_INITIAL_PRIMARY_ROOT_PASSWORD="$MONGODB_ROOT_PASSWORD"',
            'PGPASSWORD="$POSTGRESQL_PASSWORD" psql -w -U app',
            'password: "${DB_PASSWORD}"',
            'DB_PASSWORD="$USER:$PASS"',
            "client_secret: $OIDC_CLIENT_SECRET_VALUE",
        ],
    )
    def test_a_value_that_is_only_variables_is_not_reported(self, line: str) -> None:
        assert _scan(line, "script.sh") == []

    def test_a_url_password_that_is_a_variable_is_not_reported(self) -> None:
        assert _scan("url: https://deploy:$DEPLOY_PASSWORD@git.internal/repo.git") == []

    @pytest.mark.parametrize(
        "line",
        [
            'password: "Hunter2$x9Qz"',
            "DB_PASSWORD='$2y$10$9L4Tc0DJbFFMB6RdSCunrOpTHdwhid4ktBJmLD00bYgqkkGOvll3m'",
            'password: "prod-$ENVIRONMENT-Zx9fQ2mLp7"',
        ],
    )
    def test_a_literal_that_contains_a_dollar_is_still_reported(self, line: str) -> None:
        assert "SECRET_GENERIC_PASSWORD" in _scan(line, "script.sh")


class TestTemplateCodeIsNotASecret:
    """RW-03: ``range $index, $secret := ...`` is Go template code, not a hardcoded secret."""

    ACTION = "{{- range $index, $secret := .Values.tls.hidden.existingSecrets }}\n"
    WITH_LITERAL = (
        "kind: Deployment\n"
        + "env:\n  - name: X\n    value: ok\n"
        + ACTION
        + "  api_key: aB3dE5gH7jK9mN1pQ3sT5vX7zA\n"
    )

    def test_the_action_is_reported_when_the_file_is_not_known_to_be_a_template(self) -> None:
        assert "SECRET_GENERIC_SECRET" in _scan(self.ACTION, "statefulset.yaml")

    def test_the_action_is_dropped_in_a_template(self) -> None:
        assert _scan(self.ACTION, "statefulset.yaml", templated=True) == []

    @pytest.mark.parametrize(
        "action",
        [
            "{{- $userSecret := .Values.auth.acl.userSecret -}}",
            '{{ $token := include "x.token" . }}',
            "{{- if and .Values.secret $secret := .Values.secretName }}",
        ],
    )
    def test_assignments_inside_an_action_are_dropped(self, action: str) -> None:
        assert _scan(action + "\n", "x.tpl", templated=True) == []

    def test_a_literal_outside_any_action_is_still_reported_in_a_template(self) -> None:
        assert "SECRET_GENERIC_API_KEY" in _scan(self.WITH_LITERAL, "dep.yaml", templated=True)

    def test_an_action_spanning_lines_is_one_action(self) -> None:
        text = '{{- $secret := dict\n  "token" "aB3dE5gH7jK9mN1pQ3sT5vX7zA"\n}}\n'
        assert _scan(text, "x.tpl", templated=True) == []

    def test_a_provider_token_inside_an_action_is_still_reported(self) -> None:
        token = _join("gh", "p_", GITHUB_TAIL)
        assert "SECRET_GITHUB_PAT" in _scan('{{ "' + token + '" }}\n', "x.tpl", templated=True)
