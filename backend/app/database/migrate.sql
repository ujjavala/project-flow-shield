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

-- Ensure admin user exists with correct credentials
-- Password: SecurePass123! (bcrypt hashed: $2b$12$llBIEekPiz01Z0huRnLxje0LO/BCZw8igZ4i.1wXJ7ypBxErF4w1W)
INSERT INTO users (
    id,
    email,
    username,
    hashed_password,
    first_name,
    last_name,
    is_active,
    is_verified,
    is_superuser,
    role,
    created_at
) VALUES (
    'admin-user-001',
    'admin@example.com',
    'admin',
    '$2b$12$llBIEekPiz01Z0huRnLxje0LO/BCZw8igZ4i.1wXJ7ypBxErF4w1W',
    'System',
    'Administrator',
    true,
    true,
    true,
    'admin',
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    role = 'admin',
    is_superuser = true,
    is_verified = true;

-- Ensure test user exists with correct credentials
-- Password: TestPass123! (bcrypt hashed: $2b$12$dGjMwHBqXn/ZFxdkzUGrNukDn9Nn0gTZruu4j/sEGPgJ/vH/KeApO)
INSERT INTO users (
    id,
    email,
    username,
    hashed_password,
    first_name,
    last_name,
    is_active,
    is_verified,
    is_superuser,
    role,
    created_at
) VALUES (
    'test-user-001',
    'test@example.com',
    'testuser',
    '$2b$12$dGjMwHBqXn/ZFxdkzUGrNukDn9Nn0gTZruu4j/sEGPgJ/vH/KeApO',
    'Test',
    'User',
    true,
    true,
    false,
    'user',
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    role = 'user',
    is_superuser = false,
    is_verified = true;

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