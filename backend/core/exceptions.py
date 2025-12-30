from __future__ import annotations

from typing import Any, Dict, Optional

class ShieldEyeError(Exception):
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }

class ScannerConfigError(ShieldEyeError):
    pass

class ScannerError(ShieldEyeError):
    pass

class NetworkError(ShieldEyeError):
    pass

class ValidationError(ShieldEyeError):
    pass

class ReportGenerationError(ShieldEyeError):
    pass

class DatabaseError(ShieldEyeError):
    pass

class AuthenticationError(ShieldEyeError):
    pass

class RateLimitError(ShieldEyeError):
    
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after

class TimeoutError(ShieldEyeError):
    pass

class ResourceNotFoundError(ShieldEyeError):
    pass
