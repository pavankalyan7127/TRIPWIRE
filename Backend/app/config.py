"""Application configuration."""

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # API configuration
    api_v1_prefix: str = "/api/v1"

    # Application metadata
    app_name: str = "Tripwire"
    app_version: str = "0.1.0"

    # Environment
    environment: str = "development"

    # Database
    database_url: str = "sqlite:///./tripwire.db"

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
    )


settings = Settings()
