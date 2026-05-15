from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    mongo_uri: str
    secret_key: str
    algorithm: str = "HS256"
    email_pass: str
    email_address: str = "yaswanth.dev@gmail.com"
    
    class Config:
        env_file = ".env"

settings = Settings()
