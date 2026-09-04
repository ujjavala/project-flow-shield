CREATE TABLE IF NOT EXISTS  users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    role VARCHAR(20) DEFAULT 'user',
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    totp_secret_encrypted TEXT,
    totp_pending_secret_encrypted TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP,
    last_login TIMESTAMP,
    profile_picture VARCHAR(255),
    bio TEXT
);

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id VARCHAR PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255),
    client_name VARCHAR(255) NOT NULL,
    redirect_uris JSON NOT NULL,
    grant_types JSON DEFAULT '["authorization_code", "refresh_token"]',
    response_types JSON DEFAULT '["code"]',
    scope VARCHAR(255) DEFAULT 'read write',
    logo_uri TEXT,                          
    homepage_uri TEXT,                      
    description TEXT,                      
    is_active BOOLEAN DEFAULT TRUE,
    is_confidential BOOLEAN DEFAULT TRUE,  
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP                  
);



CREATE TABLE IF NOT EXISTS  oauth2_authorization_codes (
    id VARCHAR PRIMARY KEY,
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    scope VARCHAR(255),
    state VARCHAR(255),
    nonce VARCHAR(512),
    auth_time TIMESTAMPTZ,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS  oauth2_access_tokens (
    id VARCHAR PRIMARY KEY,
    access_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token_hash VARCHAR(64),
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR NOT NULL,
    scope VARCHAR(255),
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(100),
    user_agent TEXT,
    ip_address VARCHAR(64),
    authentication_method VARCHAR(32) NOT NULL DEFAULT 'password',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    family_id VARCHAR NOT NULL,
    session_id VARCHAR NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    parent_id VARCHAR,
    replaced_by_id VARCHAR,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_revoked BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR REFERENCES auth_sessions(id) ON DELETE CASCADE,
    purpose VARCHAR(40) NOT NULL,
    challenge TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id VARCHAR(1024) UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name VARCHAR(100) NOT NULL DEFAULT 'Passkey',
    transports JSON,
    aaguid VARCHAR(64),
    device_type VARCHAR(32),
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- Behavioral Analytics Tables
CREATE TABLE IF NOT EXISTS behavior_analytics (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL,
    session_id VARCHAR NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP,
    geolocation JSONB,
    device_fingerprint JSONB,
    additional_context JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL,
    risk_score DECIMAL(3,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level VARCHAR(20) NOT NULL,
    risk_factors JSONB,
    anomalies JSONB,
    analysis_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_baselines (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR UNIQUE NOT NULL,
    baseline_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fraud_alerts (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL,
    session_id VARCHAR,
    alert_type VARCHAR(50) NOT NULL,
    risk_score DECIMAL(3,2),
    risk_level VARCHAR(20),
    risk_factors JSONB,
    anomalies JSONB,
    status VARCHAR(20) DEFAULT 'active',
    severity VARCHAR(20) DEFAULT 'medium',
    resolved_at TIMESTAMP,
    resolved_by VARCHAR,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Versioned deterministic authentication risk policies and decision audit.
CREATE TABLE IF NOT EXISTS risk_policies (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    status VARCHAR(16) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'retired')),
    policy_document JSONB NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    description TEXT,
    created_by VARCHAR REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    CONSTRAINT uq_risk_policy_name_version UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS risk_decisions (
    id VARCHAR PRIMARY KEY,
    correlation_id VARCHAR(100) NOT NULL UNIQUE,
    user_id VARCHAR REFERENCES users(id) ON DELETE SET NULL,
    context VARCHAR(50) NOT NULL,
    policy_id VARCHAR NOT NULL REFERENCES risk_policies(id) ON DELETE RESTRICT,
    policy_name VARCHAR(100) NOT NULL,
    policy_version INTEGER NOT NULL,
    policy_checksum VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL CHECK (outcome IN ('allow', 'step_up', 'deny', 'review')),
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    input_features JSONB NOT NULL,
    contributions JSONB NOT NULL,
    reason_codes JSONB NOT NULL,
    ai_shadow JSONB,
    ai_shadow_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enforced_by VARCHAR(40) NOT NULL DEFAULT 'deterministic_policy',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_risk_policies_status ON risk_policies(status);
CREATE INDEX IF NOT EXISTS ix_risk_decisions_user_id ON risk_decisions(user_id);
CREATE INDEX IF NOT EXISTS ix_risk_decisions_outcome ON risk_decisions(outcome);
CREATE INDEX IF NOT EXISTS ix_risk_decisions_created_at ON risk_decisions(created_at);

-- Immutable evidence for explicitly enabled, sandboxed security simulations.
CREATE TABLE IF NOT EXISTS security_simulation_runs (
    id VARCHAR PRIMARY KEY,
    scenario_id VARCHAR(80) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('passed', 'failed')),
    seed INTEGER NOT NULL,
    target_origin VARCHAR(255) NOT NULL,
    evidence JSONB NOT NULL,
    evidence_digest VARCHAR(64) NOT NULL,
    requested_by VARCHAR REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_security_simulation_runs_scenario_id ON security_simulation_runs(scenario_id);
CREATE INDEX IF NOT EXISTS ix_security_simulation_runs_status ON security_simulation_runs(status);
CREATE INDEX IF NOT EXISTS ix_security_simulation_runs_created_at ON security_simulation_runs(created_at);

-- Demo identities and OAuth clients are reconciled by
-- `python -m app.database.seed` after schema migrations. Keeping seed logic in
-- one idempotent path avoids conflicting usernames and password hashes.