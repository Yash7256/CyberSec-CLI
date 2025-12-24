"""Custom exceptions for Cybersec CLI"""


class RateLimitError(Exception):
    """Exception raised when rate limit is exceeded"""

    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message)
        self.retry_after = retry_after


class ScanError(Exception):
    """Exception raised for scan-related errors"""

    pass


class ValidationError(Exception):
    """Exception raised for validation errors"""

    pass


class ConfigurationError(Exception):
    """Exception raised for configuration errors"""

    pass


class ScanTimeoutError(ScanError):
    """Exception raised when a scan times out"""

    def __init__(self, message: str = "Scan timed out", timeout: float = None):
        super().__init__(message)
        self.timeout = timeout


class InvalidTargetError(ScanError):
    """Exception raised when a target is invalid"""

    def __init__(self, target: str, message: str = None):
        if message is None:
            message = f"Invalid target: {target}"
        super().__init__(message)
        self.target = target


class ServiceUnavailableError(Exception):
    """Exception raised when a service is unavailable"""

    def __init__(self, service: str, message: str = None):
        if message is None:
            message = f"Service unavailable: {service}"
        super().__init__(message)
        self.service = service


class DatabaseError(Exception):
    """Exception raised for database-related errors"""

    def __init__(self, message: str, operation: str = None):
        super().__init__(message)
        self.operation = operation
