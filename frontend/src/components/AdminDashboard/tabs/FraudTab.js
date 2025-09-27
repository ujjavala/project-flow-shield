import React from 'react';
import { FiAlertTriangle, FiAlertCircle, FiShield, FiActivity } from 'react-icons/fi';

const FraudTab = ({ fraudAnalytics, realtimeEvents }) => (
  <div className="fraud-tab">
    <div className="fraud-stats-grid">
      <div className="stat-card high-risk">
        <div className="stat-icon"><FiAlertTriangle /></div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.high_risk_count || 0}</div>
          <div className="stat-label">High Risk</div>
        </div>
      </div>

      <div className="stat-card medium-risk">
        <div className="stat-icon"><FiAlertTriangle /></div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.medium_risk_count || 0}</div>
          <div className="stat-label">Medium Risk</div>
        </div>
      </div>

      <div className="stat-card low-risk">
        <div className="stat-icon"><FiAlertTriangle /></div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.low_risk_count || 0}</div>
          <div className="stat-label">Low Risk</div>
        </div>
      </div>

      <div className="stat-card blocked">
        <div className="stat-icon"><FiAlertTriangle /></div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.blocked_count || 0}</div>
          <div className="stat-label">Blocked</div>
        </div>
      </div>
    </div>

    <div className="activity-section">
      <h3><FiActivity /> Real-time Fraud Events</h3>
      <div className="activity-feed">
        {realtimeEvents.slice(0, 10).map((event, i) => (
          <div key={i} className={`activity-item ${event.severity || 'info'}`}>
            <div className="activity-time">{new Date(event.timestamp).toLocaleTimeString()}</div>
            <div className="activity-content">
              <div className="activity-title">{event.email}</div>
              <div className="activity-details">
                Score: {event.fraud_score?.toFixed(2)} | 
                Risk: {event.risk_level} |
                Status: {event.blocked ? 'Blocked' : 'Allowed'}
              </div>
            </div>
            <div className={`activity-indicator ${event.blocked ? 'blocked' : 'allowed'}`}></div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

export default FraudTab;