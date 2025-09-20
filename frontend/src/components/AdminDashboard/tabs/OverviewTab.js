import React, { useState } from 'react';
import RiskDistributionChart from '../charts/RiskDistributionChart';
import RiskFactorsChart from '../charts/RiskFactorsChart';

const OverviewTab = ({ systemHealth, fraudAnalytics }) => {
  const [expandedCards, setExpandedCards] = useState({});

  const toggleCard = (cardId) => {
    setExpandedCards(prev => ({
      ...prev,
      [cardId]: !prev[cardId]
    }));
  };

  return (
  <div className="overview-tab">
    <div className="metrics-grid">
      <div className="metric-card highlight expandable" onClick={() => toggleCard('system-status')}>
        <div className="metric-header">
          <span className="metric-icon">🛡️</span>
          <h3>System Status</h3>
        </div>
        <div className="metric-value">{systemHealth?.status || 'Unknown'}</div>
        <div className="metric-change positive">
          {systemHealth?.metrics?.services_healthy || 0}/{systemHealth?.metrics?.services_total || 0} services healthy
        </div>
        <div className="expand-toggle">
          <span className={`expand-icon ${expandedCards['system-status'] ? 'expanded' : ''}`}>▶</span>
          Details
        </div>
        <div className={`expandable-content ${expandedCards['system-status'] ? 'expanded' : ''}`}>
          <div className="feature-details">
            <strong>System Health Overview:</strong>
            <ul className="feature-list">
              <li>Real-time service monitoring</li>
              <li>Automated health checks</li>
              <li>Performance metrics tracking</li>
              <li>Alert system integration</li>
            </ul>
            <p><strong>Uptime:</strong> {systemHealth?.metrics?.uptime || 'N/A'}</p>
            <p><strong>Load Average:</strong> {systemHealth?.metrics?.load_average || 'N/A'}</p>
          </div>
        </div>
      </div>

      <div className="metric-card expandable" onClick={() => toggleCard('fraud-rate')}>
        <div className="metric-header">
          <span className="metric-icon">🚨</span>
          <h3>Fraud Rate</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.fraud_stats?.fraud_rate || 0}%</div>
        <div className="metric-change neutral">
          {fraudAnalytics?.fraud_stats?.blocked_count || 0} blocked registrations
        </div>
        <div className="expand-toggle">
          <span className={`expand-icon ${expandedCards['fraud-rate'] ? 'expanded' : ''}`}>▶</span>
          Details
        </div>
        <div className={`expandable-content ${expandedCards['fraud-rate'] ? 'expanded' : ''}`}>
          <div className="feature-details">
            <strong>Fraud Detection Analytics:</strong>
            <ul className="feature-list">
              <li>Real-time fraud scoring</li>
              <li>Machine learning detection</li>
              <li>Risk pattern analysis</li>
              <li>Automatic blocking system</li>
            </ul>
            <p><strong>High Risk:</strong> {fraudAnalytics?.risk_distribution?.high || 0} transactions</p>
            <p><strong>Medium Risk:</strong> {fraudAnalytics?.risk_distribution?.medium || 0} transactions</p>
            <p><strong>Low Risk:</strong> {fraudAnalytics?.risk_distribution?.low || 0} transactions</p>
          </div>
        </div>
      </div>

      <div className="metric-card expandable" onClick={() => toggleCard('registrations')}>
        <div className="metric-header">
          <span className="metric-icon">👥</span>
          <h3>Total Registrations</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.fraud_stats?.total_registrations || 0}</div>
        <div className="metric-change positive">Real-time monitoring</div>
        <div className="expand-toggle">
          <span className={`expand-icon ${expandedCards['registrations'] ? 'expanded' : ''}`}>▶</span>
          Details
        </div>
        <div className={`expandable-content ${expandedCards['registrations'] ? 'expanded' : ''}`}>
          <div className="feature-details">
            <strong>Registration Analytics:</strong>
            <ul className="feature-list">
              <li>User signup tracking</li>
              <li>Registration rate monitoring</li>
              <li>Geographic distribution</li>
              <li>Conversion funnel analysis</li>
            </ul>
            <p><strong>Today:</strong> {fraudAnalytics?.fraud_stats?.registrations_today || 0} new users</p>
            <p><strong>Success Rate:</strong> {fraudAnalytics?.fraud_stats?.success_rate || 0}%</p>
          </div>
        </div>
      </div>

      <div className="metric-card expandable" onClick={() => toggleCard('ai-accuracy')}>
        <div className="metric-header">
          <span className="metric-icon">🤖</span>
          <h3>AI Accuracy</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.ai_model_stats?.model_accuracy || 0}%</div>
        <div className="metric-change positive">Machine learning powered</div>
        <div className="expand-toggle">
          <span className={`expand-icon ${expandedCards['ai-accuracy'] ? 'expanded' : ''}`}>▶</span>
          Details
        </div>
        <div className={`expandable-content ${expandedCards['ai-accuracy'] ? 'expanded' : ''}`}>
          <div className="feature-details">
            <strong>AI Model Performance:</strong>
            <ul className="feature-list">
              <li>Deep learning algorithms</li>
              <li>Continuous model training</li>
              <li>False positive reduction</li>
              <li>Pattern recognition accuracy</li>
            </ul>
            <p><strong>Model Version:</strong> {fraudAnalytics?.ai_model_stats?.model_version || 'v1.0'}</p>
            <p><strong>Last Updated:</strong> {fraudAnalytics?.ai_model_stats?.last_updated || 'N/A'}</p>
            <p><strong>Confidence Score:</strong> {fraudAnalytics?.ai_model_stats?.confidence || 0}%</p>
          </div>
        </div>
      </div>
    </div>

    <div className="charts-section">
      <div className="chart-container">
        <div className="chart-title">🎯 Risk Distribution</div>
        <RiskDistributionChart data={fraudAnalytics?.risk_distribution} />
      </div>
      
      <div className="chart-container">
        <div className="chart-title">⚡ Top Risk Factors</div>
        <RiskFactorsChart data={fraudAnalytics?.top_risk_factors} />
      </div>
    </div>
  </div>
);
};

export default OverviewTab;