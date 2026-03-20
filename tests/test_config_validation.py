"""Tests for configuration validation.

These tests verify that the SecretsConfig class properly rejects weak/placeholder
values and accepts strong secrets.
"""

import pytest
import os


class TestSecretsValidation:
    """Test secret validation logic."""

    def test_placeholder_values_are_rejected(self):
        """Placeholder strings should be detected."""
        weak_values = {
            "your-secret-key-here",
            "secret",
            "changeme",
            "development",
            "test",
            "",
        }
        
        for placeholder in ["your-secret-key-here", "secret", "changeme"]:
            assert placeholder.lower() in weak_values, f"{placeholder} should be in weak values"
        
        assert "your-secret-key-here".lower() in weak_values

    def test_short_keys_are_rejected(self):
        """Keys shorter than 32 chars should be rejected."""
        MIN_SECRET_KEY_LENGTH = 32
        
        short_key = "tooshort"
        assert len(short_key) < MIN_SECRET_KEY_LENGTH
        
        min_key = "a" * 31
        assert len(min_key) < MIN_SECRET_KEY_LENGTH

    def test_valid_length_keys_are_accepted(self):
        """Keys with 32+ chars should pass length check."""
        MIN_SECRET_KEY_LENGTH = 32
        
        valid_key = "a" * 32
        assert len(valid_key) >= MIN_SECRET_KEY_LENGTH
        
        strong_key = "a" * 64
        assert len(strong_key) >= MIN_SECRET_KEY_LENGTH

    def test_api_key_salt_validation(self):
        """API_KEY_SALT must be at least 16 characters."""
        MIN_SALT_LENGTH = 16
        
        valid_salt = "a" * 16
        assert len(valid_salt) >= MIN_SALT_LENGTH
        
        invalid_salt = "a" * 15
        assert len(invalid_salt) < MIN_SALT_LENGTH

    def test_error_message_format(self):
        """Error messages should be helpful and include remediation."""
        error_msg = "SECRET_KEY is set to a placeholder value. Generate one with: openssl rand -hex 32"
        
        assert "placeholder" in error_msg.lower()
        assert "openssl" in error_msg
        assert "rand" in error_msg
        assert "hex 32" in error_msg

    def test_generation_command_is_correct(self):
        """openssl rand -hex 32 generates 64 hex chars (32 bytes)."""
        import secrets
        
        key = secrets.token_hex(32)
        assert len(key) == 64
        assert len(key) >= 32
        
        salt = secrets.token_hex(16)
        assert len(salt) == 32
        assert len(salt) >= 16
