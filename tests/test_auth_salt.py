import importlib
import json
from types import SimpleNamespace

import pytest


def _reload_auth(monkeypatch, primary: str = "", previous: str = ""):
    """Reload auth module with specific salt environment."""

    monkeypatch.delenv("API_KEY_SALT", raising=False)
    monkeypatch.delenv("API_KEY_SALT_PREVIOUS", raising=False)

    if primary:
        monkeypatch.setenv("API_KEY_SALT", primary)
    if previous:
        monkeypatch.setenv("API_KEY_SALT_PREVIOUS", previous)

    import src.cybersec_cli.core.auth as auth

    auth.clear_api_key_salt_cache()
    return importlib.reload(auth)


def test_missing_api_key_salt_fails_fast(monkeypatch):
    auth = _reload_auth(monkeypatch, primary="")

    with pytest.raises(RuntimeError):
        auth.APIKeyAuth().generate_api_key(user_id="u1")


def test_placeholder_salt_rejected(monkeypatch):
    auth = _reload_auth(monkeypatch, primary="changeme")

    with pytest.raises(RuntimeError):
        auth.APIKeyAuth()._hash_key("dummy")


def test_previous_salt_migration(monkeypatch):
    primary = "a" * 32
    previous = "b" * 32
    auth = _reload_auth(monkeypatch, primary=primary, previous=previous)

    # Minimal in-memory store to mimic redis_client interface
    class DummyStore:
        def __init__(self):
            self.store = {}

        def get(self, key):
            return self.store.get(key)

        def set(self, key, value, ttl=3600):
            self.store[key] = value
            return True

        def delete(self, key):
            return 1 if self.store.pop(key, None) is not None else 0

    client = DummyStore()
    auth_manager = auth.APIKeyAuth()
    auth_manager.redis_client = client

    api_key = "cs_dummykey"
    old_hash = auth._hash_with_salt(api_key, previous)
    key_data = {
        "user_id": "user-123",
        "created_at": "2024-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "scopes": ["read"],
        "api_metadata": {},
    }
    client.set(f"api_key:{old_hash}", json.dumps(key_data))

    result = auth_manager.verify_api_key(api_key)

    assert result is not None
    new_hash = auth._hash_with_salt(api_key, primary)
    assert f"api_key:{new_hash}" in client.store
    assert f"api_key:{old_hash}" not in client.store
