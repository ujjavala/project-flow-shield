import React from 'react';
import RiskDistributionChart from '../charts/RiskDistributionChart';
import RiskFactorsChart from '../charts/RiskFactorsChart';

const OverviewTab = ({ systemHealth, fraudAnalytics }) => (
  <div className="overview-tab">
    <div className="metrics-grid">
      <div className="metric-card highlight">
        <div className="metric-header">
          <span className="metric-icon">🛡️</span>
          <h3>System Status</h3>
        </div>
        <div className="metric-value">{systemHealth?.status || 'Unknown'}</div>
        <div className="metric-change positive">
          {systemHealth?.metrics?.services_healthy || 0}/{systemHealth?.metrics?.services_total || 0} services healthy
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-icon">🚨</span>
          <h3>Fraud Rate</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.fraud_stats?.fraud_rate || 0}%</div>
        <div className="metric-change neutral">
          {fraudAnalytics?.fraud_stats?.blocked_count || 0} blocked registrations
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-icon">👥</span>
          <h3>Total Registrations</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.fraud_stats?.total_registrations || 0}</div>
        <div className="metric-change positive">Real-time monitoring</div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-icon">🤖</span>
          <h3>AI Accuracy</h3>
        </div>
        <div className="metric-value">{fraudAnalytics?.ai_model_stats?.model_accuracy || 0}%</div>
        <div className="metric-change positive">Machine learning powered</div>
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

export default OverviewTab;