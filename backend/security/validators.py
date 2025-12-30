from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse
from ..core.exceptions import ValidationError

class URLValidator:
    ALLOWED_SCHEMES = {"http", "https"}
    MAX_URL_LENGTH = 2048
    
    @classmethod
    def validate(cls, url: str, allow_localhost: bool = True) -> str:
        if not url or not isinstance(url, str):
            raise ValidationError("URL must be a non-empty string")
        
        url = url.strip()
        
        if len(url) > cls.MAX_URL_LENGTH:
            raise ValidationError(
                f"URL exceeds maximum length of {cls.MAX_URL_LENGTH} characters",
                details={"url_length": len(url)}
            )
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {e}")
        
        if parsed.scheme not in cls.ALLOWED_SCHEMES:
            raise ValidationError(
                f"URL scheme must be one of {cls.ALLOWED_SCHEMES}",
                details={"scheme": parsed.scheme}
            )
        
        if not parsed.netloc:
            raise ValidationError("URL must have a valid domain")
        
        if not allow_localhost:
            hostname = parsed.hostname or ""
            if hostname in ("localhost", "127.0.0.1", "::1") or hostname.startswith("192.168."):
                raise ValidationError(
                    "Localhost and private IP addresses are not allowed",
                    details={"hostname": hostname}
                )
        
        if parsed.netloc.startswith(".") or parsed.netloc.endswith("."):
            raise ValidationError("Invalid domain format")
        
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            if not domain_pattern.match(hostname):
                raise ValidationError(
                    "Invalid domain name format",
                    details={"hostname": hostname}
                )
        
        return url

class ScanConfigValidator:
    VALID_MODES = {"Quick/Safe", "Aggressive/Full", "Deep/Thorough"}
    VALID_STANDARDS = {"GDPR", "PCI-DSS", "ISO 27001", "HIPAA"}
    
    @classmethod
    def validate_mode(cls, mode: str) -> str:
        if mode not in cls.VALID_MODES:
            raise ValidationError(
                f"Invalid scan mode. Must be one of {cls.VALID_MODES}",
                details={"provided_mode": mode}
            )
        return mode
    
    @classmethod
    def validate_standards(cls, standards: Optional[List[str]]) -> List[str]:
        if standards is None:
            return []
        
        if not isinstance(standards, list):
            raise ValidationError("Standards must be a list")
        
        invalid_standards = set(standards) - cls.VALID_STANDARDS
        if invalid_standards:
            raise ValidationError(
                f"Invalid standards: {invalid_standards}. Must be from {cls.VALID_STANDARDS}",
                details={"invalid_standards": list(invalid_standards)}
            )
        
        return list(set(standards))
    
    @classmethod
    def validate_max_pages(cls, max_pages: Optional[int]) -> Optional[int]:
        if max_pages is None:
            return None
        
        if not isinstance(max_pages, int):
            raise ValidationError("max_pages must be an integer")
        
        if max_pages <= 0:
            raise ValidationError("max_pages must be positive")
        
        if max_pages > 1000:
            raise ValidationError(
                "max_pages cannot exceed 1000 for safety",
                details={"requested": max_pages}
            )
        
        return max_pages
    
    @classmethod
    def validate_max_depth(cls, max_depth: Optional[int]) -> Optional[int]:
        if max_depth is None:
            return None
        
        if not isinstance(max_depth, int):
            raise ValidationError("max_depth must be an integer")
        
        if max_depth <= 0:
            raise ValidationError("max_depth must be positive")
        
        if max_depth > 10:
            raise ValidationError(
                "max_depth cannot exceed 10 for safety",
                details={"requested": max_depth}
            )
        
        return max_depth
    
    @classmethod
    def validate_timeout(cls, timeout: int) -> int:
        if not isinstance(timeout, int):
            raise ValidationError("timeout must be an integer")
        
        if timeout <= 0:
            raise ValidationError("timeout must be positive")
        
        if timeout > 300:
            raise ValidationError(
                "timeout cannot exceed 300 seconds",
                details={"requested": timeout}
            )
        
        return timeout

class PathValidator:
    @classmethod
    def validate_output_path(cls, path: str) -> str:
        if not path or not isinstance(path, str):
            raise ValidationError("Output path must be a non-empty string")
        
        path = path.strip()
        
        if len(path) > 4096:
            raise ValidationError("Path is too long")
        
        dangerous_patterns = ["../", "..\\", "~"]
        for pattern in dangerous_patterns:
            if pattern in path:
                raise ValidationError(
                    f"Path contains dangerous pattern: {pattern}",
                    details={"path": path}
                )
        
        valid_extensions = (".pdf", ".json", ".html", ".csv", ".xml", ".md", ".sarif")
        if not path.endswith(valid_extensions):
            raise ValidationError(
                f"Output file must have one of these extensions: {valid_extensions}",
                details={"path": path}
            )
        
        return path
