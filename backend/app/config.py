from pydantic_settings import BaseSettings
from pydantic import ConfigDict, Field, model_validator
from typing import Dict, List

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"

    # Observability
    SERVICE_NAME: str = "flowshield-api"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = ""
    OTEL_EXPORTER_OTLP_INSECURE: bool = True

    # Database
    DATABASE_URL: str = "postgresql://oauth2_user:oauth2_password@localhost:5432/oauth2_auth"
    
    # Temporal
    TEMPORAL_HOST: str = "localhost:7233"
    TEMPORAL_NAMESPACE: str = "default"
    TEMPORAL_TASK_QUEUE: str = "oauth2-task-queue"
    TEMPORAL_IDENTITY_OPS_TASK_QUEUE: str = "flowshield-identity-ops-v1"
    PRIVILEGED_ACCESS_APPROVAL_TIMEOUT_SECONDS: int = 86400
    
    # JWT
    JWT_SECRET_KEY: str = "your-super-secret-jwt-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # OAuth2
    OAUTH2_CLIENT_ID: str = "oauth2-client"
    OAUTH2_CLIENT_SECRET: str = "oauth2-client-secret"
    OAUTH2_CLIENT_CONFIDENTIAL: bool = True
    OAUTH2_REDIRECT_URI: str = "http://localhost:3000/callback"
    OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES: int = 10

    # OpenID Connect (private key material is mounted at runtime, never committed)
    OIDC_ISSUER: str = "http://localhost:8000"
    OIDC_SIGNING_KEY_PATH: str = ""
    OIDC_ACTIVE_KEY_ID: str = ""
    OIDC_PUBLIC_KEY_PATHS: Dict[str, str] = Field(default_factory=dict)
    OIDC_ID_TOKEN_EXPIRE_MINUTES: int = 5
    
    # Email
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "noreply@oauth2auth.com"
    EMAIL_FROM_NAME: str = "OAuth2 Auth Service"
    EMAIL_DELIVERY_MODE: str = "development_file"
    DEVELOPMENT_MAILBOX_PATH: str = ".dev-mailbox"
    SMTP_START_TLS: bool = True
    
    # URLs
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ]
    
    # Security
    PASSWORD_MIN_LENGTH: int = 8
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_EXPIRE_HOURS: int = 1
    AUTH_CHALLENGE_EXPIRE_SECONDS: int = 300
    TOTP_SETUP_EXPIRE_SECONDS: int = 600
    AUTH_SESSION_EXPIRE_DAYS: int = 7
    MFA_ENCRYPTION_KEY: str = ""
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "FlowShield"
    WEBAUTHN_ORIGINS: List[str] = ["http://localhost:3000"]
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 3600  # 1 hour
    REDIS_URL: str = "redis://localhost:6379/1"
    RATE_LIMIT_REDIS_TIMEOUT_SECONDS: float = 0.25
    TRUST_PROXY_HEADERS: bool = False

    # Explainable authentication risk policy. Deterministic policy is authoritative;
    # the local AI advisor is opt-in shadow-only and can never enforce an outcome.
    RISK_POLICY_FAIL_CLOSED: bool = True
    RISK_POLICY_BLOCKED_CIDRS: List[str] = Field(default_factory=list)
    RISK_POLICY_AI_SHADOW_ENABLED: bool = False
    RISK_POLICY_AI_HOST: str = "localhost"
    RISK_POLICY_AI_PORT: int = 11434
    RISK_POLICY_AI_MODEL: str = "llama3"
    RISK_POLICY_AI_SHADOW_TIMEOUT_SECONDS: float = 1.0
    PRIVILEGED_ACCESS_AGENT_AI_ENABLED: bool = False
    BFF_COOKIE_SECURE: bool = False
    BFF_SESSION_EXPIRE_SECONDS: int = 86400

    # Security simulation lab. Disabled by default and restricted to these exact
    # origins; requests can never supply their own target.
    SECURITY_LAB_ENABLED: bool = False
    SECURITY_LAB_BASE_URL: str = "http://localhost:8000"
    SECURITY_LAB_ALLOWED_BASE_URLS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if self.ENVIRONMENT.lower() not in {"production", "prod"}:
            return self

        errors: list[str] = []
        if self.JWT_SECRET_KEY == "your-super-secret-jwt-key-change-in-production" or len(self.JWT_SECRET_KEY) < 32:
            errors.append("JWT_SECRET_KEY must be a non-placeholder secret of at least 32 characters")
        if self.OAUTH2_CLIENT_CONFIDENTIAL and (
            self.OAUTH2_CLIENT_SECRET == "oauth2-client-secret" or len(self.OAUTH2_CLIENT_SECRET) < 32
        ):
            errors.append("OAUTH2_CLIENT_SECRET must be a non-placeholder secret of at least 32 characters")
        if not self.MFA_ENCRYPTION_KEY:
            errors.append("MFA_ENCRYPTION_KEY must be configured")
        if not self.BFF_COOKIE_SECURE:
            errors.append("BFF_COOKIE_SECURE must be enabled")
        secure_urls = {
            "OIDC_ISSUER": self.OIDC_ISSUER,
            "OAUTH2_REDIRECT_URI": self.OAUTH2_REDIRECT_URI,
            "FRONTEND_URL": self.FRONTEND_URL,
            "BACKEND_URL": self.BACKEND_URL,
        }
        for name, value in secure_urls.items():
            if not value.startswith("https://"):
                errors.append(f"{name} must use HTTPS")
        if not self.OIDC_SIGNING_KEY_PATH or not self.OIDC_ACTIVE_KEY_ID:
            errors.append("OIDC signing key path and active key ID must be configured")
        if self.EMAIL_DELIVERY_MODE == "development_file":
            errors.append("development email delivery is not allowed")
        if self.SECURITY_LAB_ENABLED:
            errors.append("SECURITY_LAB_ENABLED must be disabled")
        if "oauth2_password" in self.DATABASE_URL:
            errors.append("the local database credential is not allowed")
        if self.OTEL_EXPORTER_OTLP_INSECURE:
            errors.append("OTLP transport must be secure")
        if errors:
            raise ValueError("Invalid production security configuration: " + "; ".join(errors))
        return self
    
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True
    )

settings = Settings()