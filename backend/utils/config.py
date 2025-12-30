from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

@dataclass
class ScannerConfig:
    
    default_timeout: int = 10
    default_max_pages_quick: int = 10
    default_max_pages_full: int = 50
    default_max_depth_quick: int = 2
    default_max_depth_full: int = 5
    verify_ssl: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    )
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_pool_size: int = 10
    rate_limit_requests_per_second: float = 5.0

@dataclass
class DatabaseConfig:
    
    db_path: Path = field(default_factory=lambda: Path.home() / ".shieldeye" / "scans.db")
    backup_enabled: bool = True
    backup_count: int = 5
    auto_vacuum: bool = True

@dataclass
class LoggingConfig:
    
    level: str = "INFO"
    log_dir: Optional[Path] = field(default_factory=lambda: Path.home() / ".shieldeye" / "logs")
    structured: bool = False
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5

@dataclass
class SecurityConfig:
    
    enable_rate_limiting: bool = True
    max_requests_per_minute: int = 100
    enable_authentication: bool = True
    session_timeout_minutes: int = 30
    allowed_hosts: list[str] = field(default_factory=lambda: ["*"])

@dataclass
class ReportConfig:
    
    default_format: str = "pdf"
    include_raw_data: bool = False
    compress_reports: bool = True
    reports_dir: Path = field(default_factory=lambda: Path.home() / ".shieldeye" / "reports")

@dataclass
class AppConfig:
    
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    
    @classmethod
    def from_env(cls) -> AppConfig:
        config = cls()
        
        if timeout := os.getenv("SHIELDEYE_TIMEOUT"):
            config.scanner.default_timeout = int(timeout)
        
        if max_pages := os.getenv("SHIELDEYE_MAX_PAGES"):
            config.scanner.default_max_pages_full = int(max_pages)
        
        if max_depth := os.getenv("SHIELDEYE_MAX_DEPTH"):
            config.scanner.default_max_depth_full = int(max_depth)
        
        if verify_ssl := os.getenv("SHIELDEYE_VERIFY_SSL"):
            config.scanner.verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
        
        if user_agent := os.getenv("SHIELDEYE_USER_AGENT"):
            config.scanner.user_agent = user_agent
        
        if db_path := os.getenv("SHIELDEYE_DB_PATH"):
            config.database.db_path = Path(db_path)
        
        if log_level := os.getenv("SHIELDEYE_LOG_LEVEL"):
            config.logging.level = log_level.upper()
        
        if log_dir := os.getenv("SHIELDEYE_LOG_DIR"):
            config.logging.log_dir = Path(log_dir)
        
        if structured := os.getenv("SHIELDEYE_STRUCTURED_LOGS"):
            config.logging.structured = structured.lower() in ("true", "1", "yes")
        
        if rate_limit := os.getenv("SHIELDEYE_RATE_LIMIT"):
            config.security.enable_rate_limiting = rate_limit.lower() in ("true", "1", "yes")
        
        if reports_dir := os.getenv("SHIELDEYE_REPORTS_DIR"):
            config.report.reports_dir = Path(reports_dir)
        
        return config
    
    def ensure_directories(self) -> None:
        if self.database.db_path:
            self.database.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        if self.logging.log_dir:
            self.logging.log_dir.mkdir(parents=True, exist_ok=True)
        
        if self.report.reports_dir:
            self.report.reports_dir.mkdir(parents=True, exist_ok=True)

_global_config: Optional[AppConfig] = None

def get_config() -> AppConfig:
    global _global_config
    if _global_config is None:
        _global_config = AppConfig.from_env()
        _global_config.ensure_directories()
    return _global_config

def set_config(config: AppConfig) -> None:
    global _global_config
    _global_config = config
