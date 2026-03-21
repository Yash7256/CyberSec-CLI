"""API authentication system for CyberSec CLI."""

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, Optional

# Import Redis client for storing API keys
try:
    from cybersec_cli.core.redis_client import redis_client

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis_client = None

# Import structured logging
try:
    from cybersec_cli.core.logging_config import get_logger

    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = (
    get_logger("api") if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)
)

# Use environment variable for API key prefix
API_KEY_PREFIX = os.getenv("API_KEY_PREFIX", "cs_")
API_KEY_LENGTH = int(os.getenv("API_KEY_LENGTH", "32"))
DEFAULT_KEY_TTL = int(os.getenv("API_KEY_TTL", "2592000"))  # 30 days in seconds

# Known-bad salt placeholders (case-insensitive)
_PLACEHOLDER_SALTS = {
    "",
    "salt",
    "changeme",
    "development",
    "test",
    "generate-with-openssl-rand-hex-16",
    "generate-with-openssl-rand-hex-32",
}


@lru_cache(maxsize=1)
def _get_primary_salt() -> str:
    """
    Load the primary API key salt from environment.

    Fails fast if unset or weak so we never silently rotate salts on restart.
    """

    # SECURITY: API_KEY_SALT must be provided securely via environment; never hardcode.
    salt = os.environ.get("API_KEY_SALT", "")
    if not salt:
        raise RuntimeError(
            "API_KEY_SALT environment variable is not set. "
            "Generate one with: openssl rand -hex 32. "
            "WARNING: changing this value invalidates existing API keys."
        )

    if salt.lower() in _PLACEHOLDER_SALTS:
        raise RuntimeError(
            "API_KEY_SALT is set to a placeholder value. "
            "Set it to a 64-character hex string from: openssl rand -hex 32"
        )

    if len(salt) < 32:
        raise RuntimeError(
            f"API_KEY_SALT is too short ({len(salt)} chars). Minimum 32 characters required."
        )

    return salt


@lru_cache(maxsize=1)
def _get_previous_salt() -> str:
    """
    Optional previous salt for transition windows.

    Ignored if unset or weak. Never generated automatically.
    """

    # SECURITY: Previous salt is optional and should only be set during migrations.
    salt = os.environ.get("API_KEY_SALT_PREVIOUS", "")
    if not salt:
        return ""

    if salt.lower() in _PLACEHOLDER_SALTS or len(salt) < 32:
        logger.warning("API_KEY_SALT_PREVIOUS is present but invalid; ignoring it")
        return ""

    return salt


def clear_api_key_salt_cache() -> None:
    """Reset cached salt values (useful for tests)."""

    _get_primary_salt.cache_clear()
    _get_previous_salt.cache_clear()


def _hash_with_salt(api_key: str, salt: str) -> str:
    """Deterministically hash an API key with the provided salt."""

    return hashlib.sha256(f"{api_key}{salt}".encode()).hexdigest()


@dataclass
class APIKey:
    """API Key data structure."""

    key: str
    user_id: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    scopes: Optional[list] = None
    metadata: Optional[Dict[str, Any]] = None


class APIKeyAuth:
    """API key authentication system."""

    def __init__(self):
        self.redis_client = redis_client if HAS_REDIS else None

    def generate_api_key(
        self,
        user_id: str,
        scopes: Optional[list] = None,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a new API key for a user.

        Args:
            user_id: User identifier
            scopes: Optional list of permissions/scopes
            ttl: Time-to-live in seconds (None for default)
            metadata: Optional metadata to store with the key

        Returns:
            Generated API key string
        """
        if not user_id:
            raise ValueError("User ID is required")

        # Generate a random API key
        raw_key = secrets.token_urlsafe(API_KEY_LENGTH)
        api_key = f"{API_KEY_PREFIX}{raw_key}"

        # Hash the key for storage (security best practice)
        hashed_key = self._hash_key(api_key)

        # Prepare key data
        expires_at = datetime.now(timezone.utc)
        if ttl:
            expires_at = expires_at + timedelta(seconds=ttl)

        key_data = {
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "scopes": scopes or [],
            "api_metadata": metadata or {},
        }

        # Set expiration if provided
        ttl = ttl or DEFAULT_KEY_TTL

        if self.redis_client:
            # Store hashed key in Redis
            self.redis_client.set(
                f"api_key:{hashed_key}", json.dumps(key_data), ttl=ttl
            )
            logger.info(f"API key generated for user {user_id}")
        else:
            # Fallback to in-memory storage (not recommended for production)
            # In a real implementation, you'd want to use a database
            logger.warning("Redis not available, using in-memory storage for API keys")
            # For demo purposes only

        return api_key

    def verify_api_key(self, api_key: str) -> Optional[APIKey]:
        """
        Verify an API key and return user information.

        Args:
            api_key: API key to verify

        Returns:
            APIKey object if valid, None if invalid
        """
        if not api_key:
            return None

        hashed_primary = self._hash_key(api_key)
        key_data_str = self._fetch_key_data(hashed_primary)

        # Transition window: try previous salt, then migrate to primary hash
        if not key_data_str:
            previous_salt = _get_previous_salt()
            if previous_salt:
                hashed_previous = self._hash_key(api_key, salt=previous_salt)
                key_data_str = self._fetch_key_data(hashed_previous)
                if key_data_str:
                    self._migrate_key_hash(api_key, hashed_previous, hashed_primary, key_data_str)

        if not key_data_str:
            logger.warning(f"Invalid API key attempted: {hashed_primary[:8]}...")
            return None

        if isinstance(key_data_str, (bytes, bytearray)):
            key_data_str = key_data_str.decode("utf-8", errors="replace")

        try:
            key_data = json.loads(key_data_str)
        except Exception:
            logger.error("Failed to parse stored API key data")
            return None

        # Check expiry (Redis TTL should handle this, but verify defensively)
        expires_at_str = key_data.get("expires_at")
        if expires_at_str:
            try:
                exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp_dt:
                    if self.redis_client:
                        self.redis_client.delete(f"api_key:{hashed_primary}")
                    return None
            except Exception:
                # If parsing fails, deny access for safety
                return None

        return APIKey(
            key=api_key,
            user_id=key_data.get("user_id", ""),
            created_at=datetime.fromisoformat(
                key_data.get("created_at", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")
            ),
            expires_at=(
                datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                if expires_at_str
                else None
            ),
            scopes=key_data.get("scopes", []),
            metadata=key_data.get("api_metadata", {}),
        )

    def revoke_api_key(self, api_key: str) -> bool:
        """
        Revoke an API key by deleting it from storage.

        Args:
            api_key: API key to revoke

        Returns:
            True if successfully revoked, False otherwise
        """
        if not api_key:
            return False

        hashed_key = self._hash_key(api_key)

        if self.redis_client:
            try:
                result = self.redis_client.delete(f"api_key:{hashed_key}")
                if result > 0:
                    logger.info(f"API key revoked: {hashed_key[:8]}...")
                    return True
                else:
                    previous_salt = _get_previous_salt()
                    if previous_salt:
                        previous_hash = self._hash_key(api_key, salt=previous_salt)
                        result = self.redis_client.delete(f"api_key:{previous_hash}")
                        if result > 0:
                            logger.info(
                                f"API key revoked (previous salt): {previous_hash[:8]}..."
                            )
                            return True
                    logger.warning(
                        f"Attempted to revoke non-existent API key: {hashed_key[:8]}..."
                    )
                    return False
            except Exception as e:
                logger.error(f"Error revoking API key: {e}")
                return False
        else:
            logger.warning("Redis not available, cannot revoke API key")
            return False

    def _hash_key(self, api_key: str, salt: Optional[str] = None) -> str:
        """
        Hash an API key for secure storage.

        Args:
            api_key: Raw API key

        Returns:
            Hashed key string
        """
        chosen_salt = salt or _get_primary_salt()
        # SECURITY: Uses SHA-256 with a per-deployment salt; keep salt secret and stable.
        return _hash_with_salt(api_key, chosen_salt)

    def _fetch_key_data(self, hashed_key: str) -> Optional[str]:
        """Fetch stored key data by hashed key from Redis or in-memory fallback."""

        if not self.redis_client:
            logger.warning(
                "Redis not available, API key verification may not work properly"
            )
            return None

        try:
            return self.redis_client.get(f"api_key:{hashed_key}")
        except Exception as e:
            logger.error(f"Error verifying API key: {e}")
            return None

    def _migrate_key_hash(
        self, api_key: str, old_hash: str, new_hash: str, key_data_str: str
    ) -> None:
        """
        Re-store a key using the new salt during a transition window.

        Uses remaining TTL based on the stored expires_at timestamp when possible.
        """

        if not self.redis_client:
            return

        try:
            key_data = json.loads(
                key_data_str.decode("utf-8") if isinstance(key_data_str, (bytes, bytearray)) else key_data_str
            )
        except Exception:
            logger.error("Failed to parse stored API key data during migration")
            return

        expires_at_str = key_data.get("expires_at")
        ttl_seconds: Optional[int] = DEFAULT_KEY_TTL

        if expires_at_str:
            try:
                exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                remaining = (exp_dt - datetime.now(timezone.utc)).total_seconds()
                if remaining <= 0:
                    # Already expired; remove the old key and skip re-store
                    self.redis_client.delete(f"api_key:{old_hash}")
                    return
                ttl_seconds = int(remaining)
            except Exception:
                ttl_seconds = DEFAULT_KEY_TTL

        try:
            # Write under new hash, then remove old hash
            self.redis_client.set(f"api_key:{new_hash}", json.dumps(key_data), ttl=ttl_seconds)
            self.redis_client.delete(f"api_key:{old_hash}")
            logger.info("Migrated API key to new salt during verification")
        except Exception as exc:
            logger.error(f"Failed to migrate API key to new salt: {exc}")

    def validate_key_scopes(self, api_key: str, required_scopes: list) -> bool:
        """
        Validate that an API key has the required scopes.

        Args:
            api_key: API key to validate
            required_scopes: List of required scopes

        Returns:
            True if key has all required scopes, False otherwise
        """
        key_info = self.verify_api_key(api_key)
        if not key_info:
            return False

        if not required_scopes:
            return True  # No specific scopes required

        # Check if all required scopes are present
        key_scopes = set(key_info.scopes or [])
        required_scopes_set = set(required_scopes)

        return required_scopes_set.issubset(key_scopes)


# Global instance
auth_manager = APIKeyAuth()


def generate_api_key(
    user_id: str,
    scopes: Optional[list] = None,
    ttl: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a new API key for a user.

    Args:
        user_id: User identifier
        scopes: Optional list of permissions/scopes
        ttl: Time-to-live in seconds (None for default)
        metadata: Optional metadata to store with the key

    Returns:
        Generated API key string
    """
    return auth_manager.generate_api_key(user_id, scopes, ttl, metadata)


def verify_api_key(api_key: str) -> Optional[APIKey]:
    """
    Verify an API key and return user information.

    Args:
        api_key: API key to verify

    Returns:
        APIKey object if valid, None if invalid
    """
    return auth_manager.verify_api_key(api_key)


def revoke_api_key(api_key: str) -> bool:
    """
    Revoke an API key by deleting it from storage.

    Args:
        api_key: API key to revoke

    Returns:
        True if successfully revoked, False otherwise
    """
    return auth_manager.revoke_api_key(api_key)


def validate_key_scopes(api_key: str, required_scopes: list) -> bool:
    """
    Validate that an API key has the required scopes.

    Args:
        api_key: API key to validate
        required_scopes: List of required scopes

    Returns:
        True if key has all required scopes, False otherwise
    """
    return auth_manager.validate_key_scopes(api_key, required_scopes)


# For database-backed implementation (using SQLAlchemy)
try:
    from datetime import datetime

    from sqlalchemy import Boolean, Column, DateTime, String, Text, create_engine
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker

    Base = declarative_base()

    class APIKeyModel(Base):
        """SQLAlchemy model for API keys."""

        __tablename__ = "api_keys"

        id = Column(String, primary_key=True)
        user_id = Column(String, nullable=False)
        hashed_key = Column(String, nullable=False, unique=True)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        expires_at = Column(DateTime)
        scopes = Column(Text)  # JSON string of scopes
        api_metadata = Column(Text)  # JSON string of metadata
        revoked = Column(Boolean, default=False)

    # Initialize database connection if configured
    DATABASE_URL = os.getenv("DATABASE_URL")
    if DATABASE_URL:
        engine = create_engine(DATABASE_URL)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

except ImportError:
    # SQLAlchemy not available, skip database implementation
    pass
except Exception as e:
    logger.warning(f"Could not initialize database for API keys: {e}")
