from pydantic import BaseSettings
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGO_URL: str
    JWT_SECRET: str
    EMAIL: str
    EMAIL_PASS: str
    BASE_URL: str

    class Config:
        env_file = ".env"


settings = Settings()

settings = Settings()
