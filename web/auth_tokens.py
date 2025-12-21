"""Token management for WebSocket authentication.

Provides endpoints to create, revoke, and list authentication tokens.
"""
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = Path(BASE_DIR).parent / 'reports'
# Move tokens database to a more secure location not directly accessible via web
TOKENS_DB = Path(BASE_DIR).parent / '.secrets' / 'tokens.db'


def init_tokens_db():
    """Initialize the tokens database."""
    # Create the secure directory for tokens database
    TOKENS_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(TOKENS_DB)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS auth_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        name TEXT,
        created_at TEXT,
        expires_at TEXT,
        last_used TEXT,
        revoked BOOLEAN DEFAULT 0
    )
    ''')
    conn.commit()
    conn.close()


def create_token(name: Optional[str] = None, expires_in_days: int = 30) -> Optional[str]:
    """Create a new authentication token.
    
    Args:
        name: Optional name for the token (for user reference)
        expires_in_days: Days until token expires (default 30)
    
    Returns:
        The generated token, or None if creation failed
    """
    max_attempts = 5  # Maximum number of attempts to generate a unique token
    
    for attempt in range(max_attempts):
        try:
            token = secrets.token_urlsafe(32)
            now = datetime.utcnow().isoformat() + 'Z'
            expires_at = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat() + 'Z'
            
            conn = sqlite3.connect(TOKENS_DB)
            c = conn.cursor()
            
            # Check if token already exists (unlikely but possible)
            c.execute('SELECT COUNT(*) FROM auth_tokens WHERE token = ?', (token,))
            count = c.fetchone()[0]
            
            if count > 0:
                # Token collision, try again (if we have attempts left)
                if attempt < max_attempts - 1:
                    conn.close()
                    continue
                else:
                    # Too many collisions, give up
                    conn.close()
                    logger.warning(f"Too many token collisions after {max_attempts} attempts")
                    return None
            
            # Insert the new token
            c.execute('''
            INSERT INTO auth_tokens (token, name, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            ''', (token, name or f'Token-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}', now, expires_at))
            conn.commit()
            conn.close()
            
            logger.info(f'Created new auth token: {name}')
            return token
        except sqlite3.IntegrityError as e:
            # This could happen if there's a race condition or duplicate token
            logger.warning(f'Token creation attempt {attempt + 1} failed due to integrity error: {e}')
            if attempt < max_attempts - 1:
                continue
            else:
                logger.exception(f'Failed to create token after {max_attempts} attempts: {e}')
                return None
        except Exception as e:
            logger.exception(f'Failed to create token: {e}')
            return None
    
    return None


def validate_token(token: str) -> bool:
    """Check if a token is valid (exists, not revoked, not expired).
    
    Returns True if valid, False otherwise.
    Updates last_used timestamp on valid tokens.
    """
    try:
        conn = sqlite3.connect(TOKENS_DB)
        c = conn.cursor()
        c.execute('''
        SELECT id, expires_at, revoked FROM auth_tokens WHERE token = ?
        ''', (token,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return False
        
        token_id, expires_at, revoked = row
        
        if revoked:
            conn.close()
            return False
        
        if expires_at:
            exp_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if datetime.utcnow() > exp_dt.replace(tzinfo=None):
                conn.close()
                return False
        
        # Update last_used
        now = datetime.utcnow().isoformat() + 'Z'
        c.execute('UPDATE auth_tokens SET last_used = ? WHERE id = ?', (now, token_id))
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        logger.exception(f'Error validating token: {e}')
        return False


def revoke_token(token: str) -> bool:
    """Revoke a token, making it invalid."""
    try:
        conn = sqlite3.connect(TOKENS_DB)
        c = conn.cursor()
        c.execute('UPDATE auth_tokens SET revoked = 1 WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        logger.info(f'Revoked token')
        return True
    except Exception as e:
        logger.exception(f'Failed to revoke token: {e}')
        return False


def list_tokens(include_secrets: bool = False) -> List[Dict]:
    """List all tokens (optionally including full secrets).
    
    Args:
        include_secrets: If True, include full token value; otherwise show masked
    
    Returns:
        List of token records
    """
    try:
        conn = sqlite3.connect(TOKENS_DB)
        c = conn.cursor()
        c.execute('''
        SELECT id, token, name, created_at, expires_at, last_used, revoked
        FROM auth_tokens ORDER BY created_at DESC
        ''')
        rows = c.fetchall()
        conn.close()
        
        tokens = []
        for r in rows:
            token_val = r[1] if include_secrets else f'{r[1][:8]}...{r[1][-4:]}'
            tokens.append({
                'id': r[0],
                'token': token_val,
                'name': r[2],
                'created_at': r[3],
                'expires_at': r[4],
                'last_used': r[5],
                'revoked': bool(r[6])
            })
        
        return tokens
    except Exception as e:
        logger.exception(f'Failed to list tokens: {e}')
        return []


def delete_token(token: str) -> bool:
    """Delete a token record entirely."""
    try:
        conn = sqlite3.connect(TOKENS_DB)
        c = conn.cursor()
        c.execute('DELETE FROM auth_tokens WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        logger.info(f'Deleted token')
        return True
    except Exception as e:
        logger.exception(f'Failed to delete token: {e}')
        return False
