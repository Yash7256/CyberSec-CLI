import importlib

import pytest
from fastapi.testclient import TestClient


def _reload_main(monkeypatch, origins: str):
    """Reload web.main with a specific ALLOWED_ORIGINS value."""

    monkeypatch.setenv("ALLOWED_ORIGINS", origins)
    import web.main as main

    return importlib.reload(main)


def test_cors_allows_configured_origin(monkeypatch):
    main = _reload_main(monkeypatch, "https://app.cybersec-cli.com")

    client = TestClient(main.app)
    response = client.options(
        "/api/scans",
        headers={
            "Origin": "https://app.cybersec-cli.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.headers.get("access-control-allow-origin") == "https://app.cybersec-cli.com"


def test_cors_blocks_unknown_origin(monkeypatch):
    main = _reload_main(monkeypatch, "https://app.cybersec-cli.com")

    client = TestClient(main.app)
    response = client.options(
        "/api/scans",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_cors_rejects_wildcard_in_env(monkeypatch):
    import web.main as main

    monkeypatch.setenv("ALLOWED_ORIGINS", "*")

    with pytest.raises(ValueError, match="Wildcard"):
        main.get_allowed_origins()
