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
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP,
    last_login TIMESTAMP,
    profile_picture VARCHAR(255),
    bio TEXT
);

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id VARCHAR PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
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
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS  oauth2_access_tokens (
    id VARCHAR PRIMARY KEY,
    access_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255),
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR NOT NULL,
    scope VARCHAR(255),
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    is_revoked BOOLEAN DEFAULT FALSE
);

-- Insert default admin user if not exists
-- Password: SecurePass123! (bcrypt hashed)
-- Note: This hash was generated using bcrypt with cost 12
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
) ON CONFLICT (email) DO NOTHING;

-- Insert default test user if not exists
-- Password: TestPass123! (bcrypt hashed)
-- Note: This hash was generated using bcrypt with cost 12
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
) ON CONFLICT (email) DO NOTHING;