from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    '''
        - Reads from .env then uses yung default value na nilagay natin as fallback
    '''
    APP_NAME : str = "URL Scanner API"
    DESCRIPTION : str = "Scans URLs for vulnerabilities"
    VERSION : str = "1.0.0"
    DEBUG : bool = False

    ALLOWED_ORIGINS: list = ["*"] 

    class Config:
        env_file =".env"
        extra = "ignore"


settings = Settings()