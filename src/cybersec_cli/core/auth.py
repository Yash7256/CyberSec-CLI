"""API authentication system for CyberSec CLI."""

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
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
        expires_at = datetime.utcnow()
        if ttl:
            expires_at = expires_at + timedelta(seconds=ttl)

        key_data = {
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
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

        # Hash the provided key for comparison
        hashed_key = self._hash_key(api_key)

        if self.redis_client:
            try:
                # Retrieve key data from Redis
                key_data_str = self.redis_client.get(f"api_key:{hashed_key}")
                if not key_data_str:
                    logger.warning(f"Invalid API key attempted: {hashed_key[:8]}...")
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
                        exp_dt = datetime.fromisoformat(
                            expires_at_str.replace("Z", "+00:00")
                        )
                        if datetime.utcnow() > exp_dt.replace(tzinfo=None):
                            self.redis_client.delete(f"api_key:{hashed_key}")
                            return None
                    except Exception:
                        # If parsing fails, deny access for safety
                        return None

                return APIKey(
                    key=api_key,
                    user_id=key_data.get("user_id", ""),
                    created_at=datetime.fromisoformat(
                        key_data.get("created_at", datetime.utcnow().isoformat())
                    ),
                    expires_at=(
                        datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                        if expires_at_str
                        else None
                    ),
                    scopes=key_data.get("scopes", []),
                    metadata=key_data.get("api_metadata", {}),
                )
            except Exception as e:
                logger.error(f"Error verifying API key: {e}")
                return None
        else:
            # Fallback implementation without Redis
            # In a real system, you'd need persistent storage
            logger.warning(
                "Redis not available, API key verification may not work properly"
            )
            return None

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

    def _hash_key(self, api_key: str) -> str:
        """
        Hash an API key for secure storage.

        Args:
            api_key: Raw API key

        Returns:
            Hashed key string
        """
        # Use SHA-256 with salt for secure hashing
        salt = os.getenv("API_KEY_SALT", "cybersec_default_salt")
        return hashlib.sha256(f"{api_key}{salt}".encode()).hexdigest()

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
        created_at = Column(DateTime, default=datetime.utcnow)
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
