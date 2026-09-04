-- Durable privileged-access workflow metadata.
ALTER TABLE iam_role_requests ADD COLUMN IF NOT EXISTS scope_id VARCHAR REFERENCES iam_scopes(id);
ALTER TABLE iam_role_requests ADD COLUMN IF NOT EXISTS workflow_id VARCHAR(255);
ALTER TABLE iam_role_requests ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS ix_iam_role_requests_workflow_id
    ON iam_role_requests(workflow_id) WHERE workflow_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS iam_operation_effects (
    effect_id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR NOT NULL REFERENCES iam_role_requests(id),
    effect_type VARCHAR(50) NOT NULL,
    actor_id VARCHAR REFERENCES users(id),
    details JSON NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_iam_operation_effects_request_id
    ON iam_operation_effects(request_id);

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
-- Database migration script to handle schema updates
-- This script can be run multiple times safely (idempotent)

-- Add role column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='role') THEN
        ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user';
    END IF;
END $$;

-- Update existing users to have proper roles
UPDATE users SET role = 'user' WHERE role IS NULL;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS totp_pending_secret_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(100), user_agent TEXT, ip_address VARCHAR(64),
    authentication_method VARCHAR(32) NOT NULL DEFAULT 'password',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

-- Existing bearer refresh tokens cannot be safely migrated into session-bound
-- rotating families. Invalidate them and require one re-authentication.
DELETE FROM refresh_tokens;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='refresh_tokens' AND column_name='token') THEN
        ALTER TABLE refresh_tokens RENAME COLUMN token TO token_hash;
    END IF;
END $$;
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS family_id VARCHAR,
    ADD COLUMN IF NOT EXISTS session_id VARCHAR REFERENCES auth_sessions(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS parent_id VARCHAR,
    ADD COLUMN IF NOT EXISTS replaced_by_id VARCHAR,
    ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN session_id SET NOT NULL;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='oauth2_access_tokens' AND column_name='refresh_token') THEN
        ALTER TABLE oauth2_access_tokens RENAME COLUMN refresh_token TO refresh_token_hash;
        UPDATE oauth2_access_tokens SET refresh_token_hash = NULL;
        ALTER TABLE oauth2_access_tokens ALTER COLUMN refresh_token_hash TYPE VARCHAR(64);
    END IF;
END $$;

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
    transports JSON, aaguid VARCHAR(64), device_type VARCHAR(32),
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_used_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_auth_challenges_expiry ON auth_challenges(expires_at, used_at);
CREATE INDEX IF NOT EXISTS ix_passkey_credentials_user_id ON passkey_credentials(user_id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_session_id ON refresh_tokens(session_id);

-- OAuth 2.1 PKCE support and public-client compatibility
ALTER TABLE oauth2_clients ALTER COLUMN client_secret DROP NOT NULL;
ALTER TABLE oauth2_authorization_codes
    ADD COLUMN IF NOT EXISTS code_challenge VARCHAR(255),
    ADD COLUMN IF NOT EXISTS code_challenge_method VARCHAR(10),
    ADD COLUMN IF NOT EXISTS nonce VARCHAR(512),
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;
UPDATE oauth2_clients
SET scope = CONCAT_WS(' ', NULLIF(scope, ''), 'openid')
WHERE NOT ('openid' = ANY(string_to_array(COALESCE(scope, ''), ' ')));

-- Create behavioral analytics tables if they don't exist
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

-- Create indexes for better performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_role ON users(email, role);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_expires_revoked ON refresh_tokens(expires_at, is_revoked);

-- Behavioral analytics indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_behavior_analytics_user_id ON behavior_analytics(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_behavior_analytics_session_id ON behavior_analytics(session_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_behavior_analytics_event_type ON behavior_analytics(event_type);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_behavior_analytics_created_at ON behavior_analytics(created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risk_scores_user_id ON risk_scores(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risk_scores_risk_level ON risk_scores(risk_level);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risk_scores_created_at ON risk_scores(created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_baselines_user_id ON user_baselines(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fraud_alerts_user_id ON fraud_alerts(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fraud_alerts_status ON fraud_alerts(status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fraud_alerts_severity ON fraud_alerts(severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fraud_alerts_created_at ON fraud_alerts(created_at);