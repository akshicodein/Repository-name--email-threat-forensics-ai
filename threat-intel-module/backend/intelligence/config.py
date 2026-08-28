import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Threat intel API keys — all OPTIONAL. Module falls back to mock/basic
    # data if a key is missing, so you can start coding before keys exist.
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # Database (SQLite for hackathon speed; schema.sql has the Postgres
    # equivalent for later migration — see database/schema.sql)
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "database/threat_memory.db")

    # Neo4j — optional. Graph output still works as a plain dict without it.
    NEO4J_URI: str = os.getenv("NEO4J_URI", "")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")

    # Correlation tuning
    DNA_SIMILARITY_THRESHOLD: float = float(os.getenv("DNA_SIMILARITY_THRESHOLD", "0.75"))
    CAMPAIGN_CONFIDENCE_THRESHOLD: float = float(os.getenv("CAMPAIGN_CONFIDENCE_THRESHOLD", "0.7"))


settings = Settings()
