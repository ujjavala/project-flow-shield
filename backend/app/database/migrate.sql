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

-- Create indexes for better performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_role ON users(email, role);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_expires_revoked ON refresh_tokens(expires_at, is_revoked);