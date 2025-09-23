import React from 'react';
import { useNavigate } from 'react-router-dom';
import FlowShieldLogo from './common/FlowShieldLogo';
import './LandingPage.css';
import './common/FlowShieldLogo.css';

const LandingPage = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: '🛡',
      title: 'AI-Powered Security',
      description: 'Advanced machine learning algorithms detect and prevent fraud in real-time'
    },
    {
      icon: '🔐',
      title: 'Multi-Factor Authentication',
      description: 'Enterprise-grade MFA with SMS, email, and app-based verification'
    },
    {
      icon: '⚡',
      title: 'Temporal Workflows',
      description: 'Reliable, fault-tolerant authentication flows powered by Temporal.io'
    },
    {
      icon: '📊',
      title: 'Behavioral Analytics',
      description: 'Monitor user patterns and detect anomalies with intelligent analysis'
    },
    {
      icon: '🔒',
      title: 'Zero Trust Security',
      description: 'Every request is verified with comprehensive security policies'
    }
  ];

  const handleUserLogin = () => {
    navigate('/login');
  };

  const handleAdminLogin = () => {
    navigate('/admin/login');
  };

  const handleRegister = () => {
    navigate('/register');
  };

  return (
    <div className="landing-page">
      {/* Hero Section */}
      <div className="hero-section">
        <div className="hero-content">
          <div className="logo-section">
            <FlowShieldLogo size={80} />
            <h1 className="hero-title">FlowShield</h1>
            <p className="hero-subtitle">AI-Powered Authentication & Fraud Detection Platform</p>
          </div>

          <p className="hero-description">
            Protect your applications with enterprise-grade security powered by artificial intelligence,
            behavioral analytics, and fault-tolerant workflows. Built for modern applications that demand
            the highest levels of security and reliability.
          </p>

          <div className="cta-buttons">
            <button className="cta-button primary" onClick={handleUserLogin}>
              <span className="btn-icon">🔑</span>
              Login as User
            </button>
            <button className="cta-button secondary" onClick={handleAdminLogin}>
              <span className="btn-icon">⚙</span>
              Admin Dashboard
            </button>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="features-section">
        <div className="section-header">
          <h2>Enterprise Security Features</h2>
          <p>Comprehensive protection for your authentication infrastructure</p>
        </div>

        <div className="features-grid">
          {features.map((feature, index) => (
            <div key={index} className="feature-card">
              <div className="feature-icon">{feature.icon}</div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-description">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Security Highlights */}
      <div className="security-section">
        <div className="section-header">
          <h2>Security First Approach</h2>
          <p>Every layer designed with security as the top priority</p>
        </div>

        <div className="security-features">
          <div className="security-feature">
            <div className="security-number">01</div>
            <div className="security-content">
              <h4>Real-time Threat Detection</h4>
              <p>AI algorithms continuously monitor for suspicious activities and anomalies</p>
            </div>
          </div>
          <div className="security-feature">
            <div className="security-number">02</div>
            <div className="security-content">
              <h4>Predictive Attack Prevention</h4>
              <p>Machine learning models predict and prevent attacks before they occur</p>
            </div>
          </div>
          <div className="security-feature">
            <div className="security-number">03</div>
            <div className="security-content">
              <h4>Comprehensive Audit Trails</h4>
              <p>Complete logging and monitoring of all authentication events</p>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="landing-footer">
        <div className="footer-content">
          <div className="footer-logo">
            <FlowShieldLogo size={32} />
            <span>FlowShield</span>
          </div>
          <p className="footer-text">
            Secure your applications with confidence. Built with enterprise-grade security standards.
          </p>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;