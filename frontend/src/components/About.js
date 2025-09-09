import React from 'react';
import { Link } from 'react-router-dom';

const About = () => {
  return (
    <div className="auth-container">
      <div className="auth-card" style={{ maxWidth: '800px' }}>
        <div className="auth-header">
          <h1>🔐 OAuth2 Authentication with Temporal.io</h1>
          <p>A complete, production-ready authentication system demonstrating modern workflow orchestration</p>
        </div>

        <div className="about-content">
          <div className="feature-section">
            <h2>✨ What Makes This Special?</h2>
            <div className="features-grid">
              <div className="feature-item">
                <div className="feature-icon">🌊</div>
                <h3>Temporal Workflows</h3>
                <p>Every auth operation runs as a durable workflow that survives failures and provides full observability.</p>
              </div>
              
              <div className="feature-item">
                <div className="feature-icon">🔐</div>
                <h3>Complete OAuth2</h3>
                <p>Full OAuth2 authorization code flow with PKCE, JWT tokens, and proper security practices.</p>
              </div>
              
              <div className="feature-item">
                <div className="feature-icon">📧</div>
                <h3>Email Workflows</h3>
                <p>Registration, verification, and password reset emails with automatic retry logic.</p>
              </div>
              
              <div className="feature-item">
                <div className="feature-icon">⚛️</div>
                <h3>Modern Frontend</h3>
                <p>React 18 with hooks, context, protected routes, and beautiful responsive design.</p>
              </div>
            </div>
          </div>

          <div className="tech-section">
            <h2>🛠️ Technology Stack</h2>
            <div className="tech-grid">
              <div className="tech-item">
                <strong>Backend:</strong> FastAPI + PostgreSQL
              </div>
              <div className="tech-item">
                <strong>Workflows:</strong> Temporal.io
              </div>
              <div className="tech-item">
                <strong>Frontend:</strong> React 18 + React Router
              </div>
              <div className="tech-item">
                <strong>Auth:</strong> JWT + OAuth2 + bcrypt
              </div>
              <div className="tech-item">
                <strong>Database:</strong> PostgreSQL with SQLAlchemy
              </div>
              <div className="tech-item">
                <strong>Deployment:</strong> Docker + Docker Compose
              </div>
            </div>
          </div>

          <div className="workflow-section">
            <h2>🌊 Temporal Workflows in Action</h2>
            <div className="workflow-list">
              <div className="workflow-item">
                <h4>👤 UserRegistrationWorkflow</h4>
                <p>Orchestrates user creation, token generation, and verification email sending with automatic retries.</p>
              </div>
              
              <div className="workflow-item">
                <h4>📧 EmailVerificationWorkflow</h4>
                <p>Handles email verification and sends welcome emails, ensuring reliable completion.</p>
              </div>
              
              <div className="workflow-item">
                <h4>🔄 PasswordResetWorkflow</h4>
                <p>Manages secure password reset process with time-limited tokens and email delivery.</p>
              </div>
              
              <div className="workflow-item">
                <h4>🔗 OAuth2AuthorizationWorkflow</h4>
                <p>Handles OAuth2 authorization code flow with proper token management and validation.</p>
              </div>
            </div>
          </div>

          <div className="monitoring-section">
            <h2>📊 Monitoring & Observability</h2>
            <div className="monitoring-grid">
              <div className="monitoring-item">
                <h4>🎛️ Temporal UI</h4>
                <p>Real-time workflow monitoring at <a href="http://localhost:8081" target="_blank" rel="noopener noreferrer">localhost:8081</a></p>
              </div>
              
              <div className="monitoring-item">
                <h4>📚 API Documentation</h4>
                <p>Interactive Swagger docs at <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer">localhost:8000/docs</a></p>
              </div>
              
              <div className="monitoring-item">
                <h4>📝 Application Logs</h4>
                <p>Comprehensive logging with structured output for debugging and monitoring</p>
              </div>
            </div>
          </div>

          <div className="demo-section">
            <h2>🚀 Try It Now!</h2>
            <div className="demo-steps">
              <div className="demo-step">
                <span className="step-number">1</span>
                <div className="step-content">
                  <h4>Register an Account</h4>
                  <p>Create a new account with email verification</p>
                </div>
              </div>
              
              <div className="demo-step">
                <span className="step-number">2</span>
                <div className="step-content">
                  <h4>Watch Workflows</h4>
                  <p>See Temporal workflows execute in real-time</p>
                </div>
              </div>
              
              <div className="demo-step">
                <span className="step-number">3</span>
                <div className="step-content">
                  <h4>Explore Dashboard</h4>
                  <p>Access your profile and system information</p>
                </div>
              </div>
            </div>
          </div>

          <div className="security-section">
            <h2>🛡️ Security Features</h2>
            <div className="security-list">
              <div className="security-item">✅ bcrypt password hashing</div>
              <div className="security-item">✅ JWT access & refresh tokens</div>
              <div className="security-item">✅ CORS protection</div>
              <div className="security-item">✅ Input validation & sanitization</div>
              <div className="security-item">✅ Rate limiting</div>
              <div className="security-item">✅ Secure token generation</div>
              <div className="security-item">✅ SQL injection prevention</div>
              <div className="security-item">✅ HTTPS ready</div>
            </div>
          </div>

          <div className="cta-section">
            <h2>🎯 Ready to Get Started?</h2>
            <div className="cta-buttons">
              <Link to="/register" className="auth-button">
                Create Account
              </Link>
              <Link to="/login" className="auth-button" style={{ background: '#28a745' }}>
                Sign In
              </Link>
            </div>
            <div className="external-links">
              <a href="http://localhost:8081" target="_blank" rel="noopener noreferrer" className="external-link">
                📊 Temporal UI
              </a>
              <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer" className="external-link">
                📚 API Docs
              </a>
              <a href="https://github.com/temporalio/temporal" target="_blank" rel="noopener noreferrer" className="external-link">
                🌊 Learn Temporal
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;