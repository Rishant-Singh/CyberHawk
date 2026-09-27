"""
Application Configuration — reads from environment variables.
"""

from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    POSTGRES_URL: str = (
        "postgresql+asyncpg://cti_user:cti_secure_pass@postgres:5432/cti_db"
    )

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    ES_INDEX_LOGS: str = "cti_logs"
    ES_INDEX_THREATS: str = "cti_threats"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "kafka:29092"
    KAFKA_SCORED_TOPIC: str = "scored-threats"
    KAFKA_GROUP_ID: str = "cti-backend-group"

    # JWT
    JWT_SECRET_KEY: str = "change-this-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://frontend:3000",
    ]

    # Admin seed
    ADMIN_EMAIL: str = "admin@cti.local"
    ADMIN_PASSWORD: str = "Admin@CTI2024!"
    ADMIN_USERNAME: str = "admin"

    # AI / External APIs (optional)
    GEMINI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True

    def model_post_init(self, __context):
        # Handle comma-separated CORS_ORIGINS from env string
        if isinstance(self.CORS_ORIGINS, str):
            self.CORS_ORIGINS = [o.strip() for o in self.CORS_ORIGINS.split(",")]


settings = Settings()
