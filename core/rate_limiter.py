import time
import asyncio
from typing import List, Dict, Optional
from redis import Redis
from datetime import datetime, timedelta
import logging

from src.cybersec_cli.utils.exceptions import RateLimitError

# Import structured logging
try:
    from core.logging_config import get_logger
    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = get_logger('scanner') if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)


class SmartRateLimiter:
    """
    Advanced multi-layer rate limiting system with sliding window, 
    exponential backoff, and abuse detection
    """
    
    def __init__(self, redis_client: Redis, config: Dict):
        self.redis = redis_client
        self.config = config
        # Rate limit settings
        self.client_limit = config.get('CLIENT_RATE_LIMIT', 10)
        self.client_window = config.get('CLIENT_RATE_WINDOW', 3600)  # 1 hour in seconds
        self.target_limit = config.get('TARGET_RATE_LIMIT', 50)
        self.target_window = config.get('TARGET_RATE_WINDOW', 3600)  # 1 hour in seconds
        self.port_limit = config.get('PORT_LIMIT_PER_SCAN', 1000)
        self.global_limit = config.get('GLOBAL_CONCURRENT_LIMIT', 1000)
        self.warn_port_threshold = config.get('PORT_WARN_THRESHOLD', 100)
        
        # Exponential backoff settings
        self.cooldown_periods = [
            0,  # First violation: warning only
            300,  # Second: 5 minutes
            3600,  # Third: 1 hour
            86400,  # Fourth: 24 hours
        ]

    def check_client_limit(self, client_id: str) -> bool:
        """
        Check if client has exceeded rate limit (10 scans per hour per client)
        Uses Redis counter with sliding window
        """
        key = f"rate_limit:client:{client_id}"
        current_time = time.time()
        
        # Remove expired entries
        self.redis.zremrangebyscore(key, 0, current_time - self.client_window)
        
        # Count current entries
        count = self.redis.zcard(key)
        
        if count >= self.client_limit:
            return False
        
        # Add current request
        self.redis.zadd(key, {str(current_time): current_time})
        # Set expiration to clean up automatically
        self.redis.expire(key, self.client_window)
        
        return True
    
    def check_target_limit(self, target: str) -> bool:
        """
        Check if target has exceeded rate limit (50 scans per hour per target)
        Track across all clients to prevent harassment
        """
        key = f"rate_limit:target:{target}"
        current_time = time.time()
        
        # Remove expired entries
        self.redis.zremrangebyscore(key, 0, current_time - self.target_window)
        
        # Count current entries
        count = self.redis.zcard(key)
        
        if count >= self.target_limit:
            return False
        
        # Add current request
        self.redis.zadd(key, {str(current_time): current_time})
        # Set expiration to clean up automatically
        self.redis.expire(key, self.target_window)
        
        return True
    
    def check_port_range_limit(self, ports: List[int]) -> tuple[bool, str]:
        """
        Check if port range exceeds limits (Max 1000 ports per single scan)
        Return (is_valid, warning_message)
        """
        port_count = len(ports)
        
        if port_count > self.port_limit:
            return False, f"Port range too large: {port_count} ports (max {self.port_limit})"
        elif port_count > self.warn_port_threshold:
            return True, f"Warning: {port_count} ports selected (suggestion: use fewer ports for better performance)"
        
        return True, ""
    
    def check_global_limit(self) -> tuple[bool, int]:
        """
        Check global concurrent scan limit (Max 1000 concurrent scans)
        Returns (is_allowed, available_slots)
        """
        key = "rate_limit:global:concurrent"
        current_count = int(self.redis.get(key) or 0)
        available_slots = max(0, self.global_limit - current_count)
        
        return available_slots > 0, available_slots
    
    def increment_concurrent_scan(self) -> bool:
        """Increment global concurrent scan counter"""
        key = "rate_limit:global:concurrent"
        current_count = self.redis.incr(key)
        self.redis.expire(key, 3600)  # Expire after 1 hour if not decremented
        
        return current_count <= self.global_limit
    
    def decrement_concurrent_scan(self):
        """Decrement global concurrent scan counter"""
        key = "rate_limit:global:concurrent"
        current_count = int(self.redis.get(key) or 0)
        if current_count > 0:
            self.redis.decr(key)
    
    def get_violation_count(self, client_id: str) -> int:
        """Get the number of violations for a client"""
        key = f"rate_limit:violations:{client_id}"
        count = int(self.redis.get(key) or 0)
        return count
    
    def record_violation(self, client_id: str) -> int:
        """Record a rate limit violation and return the violation count"""
        key = f"rate_limit:violations:{client_id}"
        violation_count = self.redis.incr(key)
        self.redis.expire(key, 86400 * 30)  # Keep violation count for 30 days
        
        # Log the violation
        logger.warning(f"Rate limit violation for client {client_id}, violation #{violation_count}")
        
        return violation_count
    
    def get_cooldown_period(self, client_id: str) -> int:
        """Get the current cooldown period for a client based on violation count"""
        violation_count = self.get_violation_count(client_id)
        if violation_count >= len(self.cooldown_periods):
            # For violations beyond the defined periods, use the maximum
            return self.cooldown_periods[-1]
        return self.cooldown_periods[violation_count]
    
    def is_on_cooldown(self, client_id: str) -> bool:
        """Check if client is currently on cooldown"""
        cooldown_key = f"rate_limit:cooldown:{client_id}"
        return self.redis.exists(cooldown_key) > 0
    
    def apply_cooldown(self, client_id: str):
        """Apply cooldown to client based on violation count"""
        violation_count = self.get_violation_count(client_id)
        if violation_count >= len(self.cooldown_periods):
            cooldown_period = self.cooldown_periods[-1]  # Max cooldown
        else:
            cooldown_period = self.cooldown_periods[violation_count]
        
        if cooldown_period > 0:
            cooldown_key = f"rate_limit:cooldown:{client_id}"
            self.redis.setex(cooldown_key, cooldown_period, "1")
            logger.info(f"Applied {cooldown_period}s cooldown to client {client_id}")
    
    def get_rate_limit_headers(self, client_id: str) -> Dict[str, str]:
        """Generate RFC 6585 compliant rate limit headers"""
        client_key = f"rate_limit:client:{client_id}"
        current_time = time.time()
        
        # Remove expired entries
        self.redis.zremrangebyscore(client_key, 0, current_time - self.client_window)
        remaining = max(0, self.client_limit - self.redis.zcard(client_key))
        
        headers = {
            'X-RateLimit-Limit': str(self.client_limit),
            'X-RateLimit-Remaining': str(remaining),
            'X-RateLimit-Reset': str(int(current_time + self.client_window)),
        }
        
        # Add Retry-After if client is on cooldown
        if self.is_on_cooldown(client_id):
            cooldown_key = f"rate_limit:cooldown:{client_id}"
            ttl = self.redis.ttl(cooldown_key)
            headers['Retry-After'] = str(ttl)
        
        return headers
    
    def reset_client_limits(self, client_id: str):
        """Reset rate limits for a specific client (admin function)"""
        # Remove client rate limit entries
        client_key = f"rate_limit:client:{client_id}"
        self.redis.delete(client_key)
        
        # Remove target rate limit entries for this client (if tracking by client)
        # This would require a more complex implementation to track by client
        
        # Remove violation count
        violation_key = f"rate_limit:violations:{client_id}"
        self.redis.delete(violation_key)
        
        # Remove cooldown
        cooldown_key = f"rate_limit:cooldown:{client_id}"
        self.redis.delete(cooldown_key)
        
        logger.info(f"Reset rate limits for client {client_id}")
    
    def get_all_violations(self) -> Dict[str, int]:
        """Get all violation counts for monitoring"""
        keys = self.redis.keys("rate_limit:violations:*")
        violations = {}
        for key in keys:
            client_id = key.decode().split(":")[-1]
            count = int(self.redis.get(key) or 0)
            violations[client_id] = count
        return violations
    
    def get_abuse_patterns(self) -> List[Dict]:
        """Detect and return abuse patterns"""
        violations = self.get_all_violations()
        abuse_patterns = []
        
        for client_id, count in violations.items():
            if count >= 2:  # At least 2 violations
                abuse_patterns.append({
                    'client_id': client_id,
                    'violation_count': count,
                    'is_on_cooldown': self.is_on_cooldown(client_id)
                })
        
        return abuse_patterns