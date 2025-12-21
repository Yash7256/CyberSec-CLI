"""
Adaptive Concurrency Control for Cybersec CLI.

This module implements adaptive concurrency control that automatically adjusts
scanning speed based on network performance.
"""

import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveScanConfig:
    """
    Configuration class for adaptive concurrency control.
    
    Automatically adjusts scanning parameters based on network performance
    by monitoring success rates and adjusting concurrency and timeout values.
    """
    
    # Starting values
    concurrency: int = 50
    timeout: float = 1.0
    
    # Performance tracking
    success_rate: float = 1.0
    failed_connections: int = 0
    total_attempts: int = 0
    
    # Limits
    max_concurrency: int = 500
    min_timeout: float = 0.5
    
    def adjust_parameters(self) -> None:
        """
        Adjust concurrency and timeout parameters based on success rate.
        
        Adjustment rules:
        - If success_rate < 0.7: reduce concurrency by 50%, increase timeout by 0.5s
        - If success_rate > 0.9: increase concurrency by 50% (max 500), reduce timeout by 0.2s (min 0.5s)
        - All changes are logged with reasoning
        """
        # Calculate success rate if we have attempts
        if self.total_attempts > 0:
            self.success_rate = 1 - (self.failed_connections / self.total_attempts)
        else:
            self.success_rate = 1.0
            
        old_concurrency = self.concurrency
        old_timeout = self.timeout
        
        # Adjust parameters based on success rate
        if self.success_rate < 0.7:
            # Network is struggling, reduce concurrency and increase timeout
            self.concurrency = max(1, int(self.concurrency * 0.5))
            self.timeout += 0.5
            logger.info(
                f"Low success rate ({self.success_rate:.2f}), reducing concurrency "
                f"from {old_concurrency} to {self.concurrency} and increasing timeout "
                f"from {old_timeout}s to {self.timeout}s"
            )
            
        elif self.success_rate > 0.9:
            # Network is performing well, increase concurrency and reduce timeout
            self.concurrency = min(self.max_concurrency, int(self.concurrency * 1.5))
            self.timeout = max(self.min_timeout, self.timeout - 0.2)
            logger.info(
                f"High success rate ({self.success_rate:.2f}), increasing concurrency "
                f"from {old_concurrency} to {self.concurrency} and decreasing timeout "
                f"from {old_timeout}s to {self.timeout}s"
            )
        else:
            # Success rate is in acceptable range, no adjustment needed
            logger.debug(
                f"Success rate {self.success_rate:.2f} is in acceptable range, "
                f"keeping concurrency at {self.concurrency} and timeout at {self.timeout}s"
            )

    def record_attempt(self, success: bool) -> None:
        """
        Record a connection attempt for performance tracking.
        
        Args:
            success: Whether the connection attempt was successful
        """
        self.total_attempts += 1
        if not success:
            self.failed_connections += 1

    def reset_stats(self) -> None:
        """Reset performance statistics."""
        self.failed_connections = 0
        self.total_attempts = 0
        self.success_rate = 1.0