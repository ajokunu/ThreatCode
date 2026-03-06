"""Tests for image config misconfiguration checks."""

from __future__ import annotations

from threatcode.image.misconfig import check_image_config

_BASE_CONFIG: dict = {
    "config": {
        "User": "nginx",
        "Healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost"]},
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin"],
        "ExposedPorts": {"8080/tcp": {}},
        "Labels": {"maintainer": "team@example.com"},
    }
}


def _config(**overrides: object) -> dict:
    import copy

    c = copy.deepcopy(_BASE_CONFIG)
    c["config"].update(overrides)
    return c


class TestCheckImageConfig:
    def test_clean_image_no_findings(self) -> None:
        findings = check_image_config(_BASE_CONFIG)
        ids = [f["id"] for f in findings]
        assert "IMG_ROOT_USER" not in ids
        assert "IMG_NO_HEALTHCHECK" not in ids
        assert "IMG_SECRET_IN_ENV" not in ids

    def test_root_user_flagged(self) -> None:
        c = _config(User="root")
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_ROOT_USER" for f in findings)

    def test_empty_user_flagged(self) -> None:
        c = _config(User="")
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_ROOT_USER" for f in findings)

    def test_uid_zero_flagged(self) -> None:
        c = _config(User="0")
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_ROOT_USER" for f in findings)

    def test_no_healthcheck_flagged(self) -> None:
        c = _config()
        del c["config"]["Healthcheck"]
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_NO_HEALTHCHECK" for f in findings)

    def test_secret_in_env_flagged(self) -> None:
        c = _config(Env=["PATH=/usr/bin", "DATABASE_PASSWORD=s3cret"])
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_SECRET_IN_ENV" for f in findings)

    def test_api_key_in_env_flagged(self) -> None:
        c = _config(Env=["STRIPE_API_KEY=sk_live_abc"])
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_SECRET_IN_ENV" for f in findings)

    def test_privileged_port_flagged(self) -> None:
        c = _config(ExposedPorts={"80/tcp": {}})
        findings = check_image_config(c)
        assert any(f["id"] == "IMG_PRIVILEGED_PORT" for f in findings)

    def test_non_privileged_port_not_flagged(self) -> None:
        c = _config(ExposedPorts={"8080/tcp": {}})
        findings = check_image_config(c)
        assert not any(f["id"] == "IMG_PRIVILEGED_PORT" for f in findings)

    def test_findings_have_required_fields(self) -> None:
        c = _config(User="")
        findings = check_image_config(c)
        for f in findings:
            assert "id" in f
            assert "title" in f
            assert "severity" in f
            assert "description" in f
