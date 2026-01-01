"""
Configuration management using Pydantic Settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

_cached_active_domains: Optional[List[str]] = None


class Settings(BaseSettings):
    """Application settings"""
    
    mailcow_url: str = Field(..., description="Mailcow instance URL")
    mailcow_api_key: str = Field(..., description="Mailcow API key")
    mailcow_api_timeout: int = Field(default=30, description="API request timeout in seconds")
    
    # Blacklist Configuration
    blacklist_emails: str = Field(
        default="",
        description="Comma-separated list of email addresses to hide from logs"
    )
    
    # Fetch Configuration
    fetch_interval: int = Field(default=60, description="Seconds between log fetches")
    fetch_count_postfix: int = Field(
        default=2000, 
        description="Postfix logs to fetch per request"
    )
    fetch_count_rspamd: int = Field(
        default=500, 
        description="Rspamd logs to fetch per request"
    )
    fetch_count_netfilter: int = Field(
        default=500, 
        description="Netfilter logs to fetch per request"
    )
    retention_days: int = Field(default=7, description="Days to keep logs")
    
    # Correlation Configuration
    max_correlation_age_minutes: int = Field(
        default=10,
        description="Stop searching for correlations older than this (minutes)"
    )
    correlation_check_interval: int = Field(
        default=120,
        description="Seconds between correlation completion checks"
    )
    
    # Database Configuration
    postgres_host: str = Field(default="db", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_user: str = Field(..., description="PostgreSQL username")
    postgres_password: str = Field(..., description="PostgreSQL password")
    postgres_db: str = Field(..., description="PostgreSQL database name")
    
    # Application Configuration
    app_port: int = Field(default=8080, description="Application port")
    log_level: str = Field(
        default="WARNING",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    tz: str = Field(
        default="UTC",
        description="Timezone"
    )
    app_title: str = Field(default="Mailcow Logs Viewer", description="Application title")
    app_logo_url: str = Field(default="", description="Application logo URL (optional)")
    
    # Advanced Configuration
    debug: bool = Field(default=False, description="Debug mode")
    max_search_results: int = Field(default=1000, description="Max search results")
    csv_export_limit: int = Field(default=10000, description="CSV export row limit")
    scheduler_workers: int = Field(default=4, description="Background job workers")
    
    # Authentication Configuration
    auth_enabled: bool = Field(
        default=False,
        description="Enable basic authentication"
    )
    auth_username: str = Field(
        default="admin",
        description="Basic auth username"
    )
    auth_password: str = Field(
        default="",
        description="Basic auth password (required if auth_enabled=True)"
    )
    
    @validator('mailcow_url')
    def validate_mailcow_url(cls, v):
        """Ensure URL doesn't end with slash"""
        return v.rstrip('/')
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Ensure valid log level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        v = v.upper()
        if v not in valid_levels:
            logger.warning(f"Invalid log level '{v}', using WARNING")
            return 'WARNING'
        return v
    
    @property
    def local_domains_list(self) -> List[str]:
        """Get active domains from Mailcow API cache"""
        global _cached_active_domains
        if _cached_active_domains is None:
            logger.warning("Local domains cache not yet populated")
            return []
        return _cached_active_domains
    
    @property
    def blacklist_emails_list(self) -> List[str]:
        """Parse blacklisted emails into a list"""
        if not self.blacklist_emails:
            return []
        return [e.strip().lower() for e in self.blacklist_emails.split(',') if e.strip()]
    
    @property
    def database_url(self) -> str:
        """Construct PostgreSQL connection URL"""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    @property
    def async_database_url(self) -> str:
        """Construct async PostgreSQL connection URL"""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()


def setup_logging():
    """Configure application logging"""
    log_format = '%(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format=log_format
    )
    
    logging.getLogger('httpx').setLevel(logging.ERROR)
    logging.getLogger('httpcore').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    
    if settings.debug:
        logger.warning("Debug mode is enabled")


# Initialize logging
setup_logging()


def set_cached_active_domains(domains: List[str]) -> None:
    """Set the cached active domains list"""
    global _cached_active_domains
    _cached_active_domains = domains
    logger.info(f"Cached {len(domains)} active domains from Mailcow API")


def get_cached_active_domains() -> Optional[List[str]]:
    """Get the cached active domains list"""
    return _cached_active_domains