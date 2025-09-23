-- Attack Simulation Database Schema
-- Tables for Predictive Attack Simulation feature

-- Attack Surface Analysis table
CREATE TABLE IF NOT EXISTS attack_surfaces (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    system_component VARCHAR(100) NOT NULL,
    component_type VARCHAR(50) NOT NULL, -- 'api', 'database', 'network', 'application'
    vulnerability_score DECIMAL(3,2) DEFAULT 0.0,
    exposure_level VARCHAR(20) DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    attack_vectors JSON,
    security_controls JSON,
    metadata JSON,
    last_analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Attack Predictions table
CREATE TABLE IF NOT EXISTS attack_predictions (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    prediction_type VARCHAR(50) NOT NULL, -- 'brute_force', 'sql_injection', 'xss', 'csrf', etc.
    target_component VARCHAR(100) NOT NULL,
    predicted_likelihood DECIMAL(5,4) NOT NULL, -- 0.0000 to 1.0000
    confidence_score DECIMAL(5,4) NOT NULL,
    attack_vector_details JSON NOT NULL,
    ai_reasoning TEXT,
    prediction_source VARCHAR(20) DEFAULT 'ollama', -- 'ollama', 'ml_model', 'heuristic'
    model_version VARCHAR(50),
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Attack Simulations table
CREATE TABLE IF NOT EXISTS attack_simulations (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    simulation_name VARCHAR(200) NOT NULL,
    prediction_id VARCHAR REFERENCES attack_predictions(id),
    simulation_type VARCHAR(50) NOT NULL,
    target_system VARCHAR(100) NOT NULL,
    attack_scenario JSON NOT NULL,
    simulation_config JSON,

    -- Simulation Status
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'stopped'
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    -- Results
    simulation_results JSON,
    vulnerabilities_found JSON,
    security_impact_score DECIMAL(3,2),
    recommended_fixes JSON,

    -- Execution Details
    executed_by VARCHAR DEFAULT 'system',
    execution_environment VARCHAR(50) DEFAULT 'sandbox',
    safety_checks_passed BOOLEAN DEFAULT TRUE,

    -- AI Analysis
    ai_analysis JSON,
    post_simulation_recommendations JSON,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Attack Remediation table
CREATE TABLE IF NOT EXISTS attack_remediations (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    simulation_id VARCHAR REFERENCES attack_simulations(id),
    vulnerability_id VARCHAR NOT NULL,
    remediation_type VARCHAR(50) NOT NULL, -- 'patch', 'config_change', 'policy_update', 'monitoring'
    priority VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'

    -- Remediation Details
    fix_description TEXT NOT NULL,
    implementation_steps JSON,
    estimated_effort_hours INTEGER,
    required_resources JSON,

    -- Status Tracking
    status VARCHAR(20) DEFAULT 'recommended', -- 'recommended', 'planned', 'in_progress', 'completed', 'skipped'
    assigned_to VARCHAR,
    due_date TIMESTAMP,
    completed_at TIMESTAMP,

    -- Verification
    fix_verified BOOLEAN DEFAULT FALSE,
    verification_method VARCHAR(100),
    verification_results JSON,

    -- AI Recommendations
    ai_generated BOOLEAN DEFAULT TRUE,
    confidence_score DECIMAL(5,4),
    alternative_fixes JSON,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Predictive Attack Metrics table
CREATE TABLE IF NOT EXISTS predictive_attack_metrics (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    metric_date DATE NOT NULL,

    -- Prediction Metrics
    total_predictions INTEGER DEFAULT 0,
    high_risk_predictions INTEGER DEFAULT 0,
    prediction_accuracy DECIMAL(5,4), -- Calculated from past predictions vs actual incidents
    false_positive_rate DECIMAL(5,4),
    false_negative_rate DECIMAL(5,4),

    -- Simulation Metrics
    total_simulations INTEGER DEFAULT 0,
    successful_simulations INTEGER DEFAULT 0,
    vulnerabilities_discovered INTEGER DEFAULT 0,
    auto_remediated_issues INTEGER DEFAULT 0,

    -- Security Impact
    critical_vulnerabilities INTEGER DEFAULT 0,
    high_vulnerabilities INTEGER DEFAULT 0,
    medium_vulnerabilities INTEGER DEFAULT 0,
    low_vulnerabilities INTEGER DEFAULT 0,

    -- AI Performance
    ai_model_accuracy DECIMAL(5,4),
    avg_prediction_confidence DECIMAL(5,4),
    ai_processing_time_ms INTEGER,

    -- System Health
    security_posture_score DECIMAL(5,2), -- Overall security score 0.00 to 100.00
    improvement_trend VARCHAR(20), -- 'improving', 'stable', 'declining'

    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_attack_predictions_likelihood ON attack_predictions(predicted_likelihood DESC);
CREATE INDEX IF NOT EXISTS idx_attack_predictions_created ON attack_predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_simulations_status ON attack_simulations(status);
CREATE INDEX IF NOT EXISTS idx_attack_simulations_created ON attack_simulations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_remediations_priority ON attack_remediations(priority, status);
CREATE INDEX IF NOT EXISTS idx_attack_surfaces_exposure ON attack_surfaces(exposure_level);
CREATE INDEX IF NOT EXISTS idx_predictive_metrics_date ON predictive_attack_metrics(metric_date DESC);

-- Views for common queries
CREATE OR REPLACE VIEW active_high_risk_predictions AS
SELECT
    ap.*,
    as_table.component_type,
    as_table.security_controls
FROM attack_predictions ap
LEFT JOIN attack_surfaces as_table ON ap.target_component = as_table.system_component
WHERE ap.predicted_likelihood > 0.7
AND ap.expires_at > NOW()
ORDER BY ap.predicted_likelihood DESC, ap.created_at DESC;

CREATE OR REPLACE VIEW simulation_success_summary AS
SELECT
    simulation_type,
    COUNT(*) as total_simulations,
    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_simulations,
    AVG(security_impact_score) as avg_impact_score,
    SUM(COALESCE((vulnerabilities_found->>'count')::int, 0)) as total_vulnerabilities_found
FROM attack_simulations
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY simulation_type
ORDER BY avg_impact_score DESC;