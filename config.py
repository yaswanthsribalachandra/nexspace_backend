from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    mongo_uri: str
    secret_key: str
    algorithm: str = "HS256"
    email_pass: str
    email_address: str = "dasariyaswanthsribalachandra@gmail.com"
    base_url: str = "https://nexspacefrontend-dsfjgrc4auccheeu.centralindia-01.azurewebsites.net/"

    class Config:
        env_file = ".env"

settings = Settings()