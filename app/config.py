from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    CHROMA_PATH: str = "./data/chroma"
    ANTHROPIC_API_KEY: str = ""
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    LLM_MODEL: str = "claude-sonnet-4-6"
    MAX_ITERATIONS: int = 3
    TOP_K_VECTOR: int = 10
    TOP_K_GRAPH: int = 10
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000


settings = Settings()
