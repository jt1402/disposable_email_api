from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "Disposable Email Detection API"
    app_version: str = "0.1.0"
    debug: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # PostgreSQL
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/emailapi"

    # Unkey
    unkey_root_key: str = ""
    unkey_api_id: str = ""

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_starter: str = ""
    stripe_price_growth: str = ""
    stripe_price_pro: str = ""

    # Detection timeouts (seconds)
    dns_timeout: float = 2.0
    whois_timeout: float = 5.0
    smtp_timeout: float = 5.0
    catchall_enabled: bool = False

    # Upstream DNS resolvers — bypass system resolver which can be unreliable
    # for TXT records. Comma-separated list.
    dns_nameservers: str = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4"

    # How many known-disposable domains must share an MX server before flagging it
    mx_cluster_threshold: int = 3

    # Scoring model phase: "bootstrap" (stricter thresholds, conservative for month 1)
    # or "calibrated" (steady-state thresholds, after ~1000 confirmed outcomes).
    model_phase: str = "bootstrap"
    model_version: str = "1.0.0"
    default_risk_profile: str = "balanced"  # strict | balanced | permissive

    # Monthly request limits per tier (-1 = unlimited)
    tier_limit_free: int = 500
    tier_limit_starter: int = 10_000
    tier_limit_growth: int = 50_000
    tier_limit_pro: int = 250_000
    tier_limit_enterprise: int = -1

    def tier_limit(self, tier: str) -> int:
        return {
            "free": self.tier_limit_free,
            "starter": self.tier_limit_starter,
            "growth": self.tier_limit_growth,
            "pro": self.tier_limit_pro,
            "enterprise": self.tier_limit_enterprise,
        }.get(tier, self.tier_limit_free)


@lru_cache
def get_settings() -> Settings:
    return Settings()
