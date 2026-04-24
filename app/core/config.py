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

    # Stripe — credit bundles (one-time purchases, mode=payment)
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_bundle_10k: str = ""
    stripe_price_bundle_25k: str = ""
    stripe_price_bundle_50k: str = ""
    stripe_price_bundle_100k: str = ""

    # Email (Resend) — magic links, verification mails
    resend_api_key: str = ""
    resend_from_email: str = "VerifyMail <noreply@verifymailapi.com>"

    # Auth / session
    # Base URL of the Next.js frontend — magic-link emails embed this.
    app_base_url: str = "http://localhost:3000"
    # Session cookie TTL in days. 30 days is a typical dashboard session.
    session_ttl_days: int = 30
    # Magic-link token TTL in minutes.
    magic_link_ttl_minutes: int = 15
    # Comma-separated list of origins allowed by CORS in production.
    # Empty string → wildcard (dev default). Lock this down before going live.
    cors_allow_origins: str = ""

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

    # PAYG credit model — credits live on User.credit_balance_checks.
    # Every successful /v1/check decrements by 1.
    free_signup_credits: int = 100
    # Bundle sizes in checks — must match the Stripe price IDs above.
    bundle_checks_10k: int = 10_000
    bundle_checks_25k: int = 25_000
    bundle_checks_50k: int = 50_000
    bundle_checks_100k: int = 100_000

    def bundle_credits(self, bundle: str) -> int:
        return {
            "10k": self.bundle_checks_10k,
            "25k": self.bundle_checks_25k,
            "50k": self.bundle_checks_50k,
            "100k": self.bundle_checks_100k,
        }.get(bundle, 0)

    def bundle_price_id(self, bundle: str) -> str:
        return {
            "10k": self.stripe_price_bundle_10k,
            "25k": self.stripe_price_bundle_25k,
            "50k": self.stripe_price_bundle_50k,
            "100k": self.stripe_price_bundle_100k,
        }.get(bundle, "")


@lru_cache
def get_settings() -> Settings:
    return Settings()
