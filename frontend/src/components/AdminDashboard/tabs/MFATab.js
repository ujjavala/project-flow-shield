import React from 'react';

const MFATab = ({ mfaAnalytics, securityOverview }) => (
  <div className="mfa-tab">
    {/* MFA Overview Statistics */}
    <div className="mfa-overview-grid">
      <div className="mfa-card">
        <div className="mfa-header">
          <span className="mfa-icon">🛡️</span>
          <h3>MFA Statistics (24h)</h3>
          <span className={`status-badge ${mfaAnalytics?.system_status?.mfa_service === 'operational' ? 'healthy' : 'warning'}`}>
            {mfaAnalytics?.system_status?.mfa_service === 'operational' ? 'Operational' : 'Issues'}
          </span>
        </div>
        <div className="mfa-stats">
          <div className="stat-item">
            <div className="stat-number">{mfaAnalytics?.attempts_24h?.total_attempts || 0}</div>
            <div className="mfa-stat-label">Total Attempts</div>
          </div>
          <div className="stat-item">
            <div className="stat-number success">{mfaAnalytics?.attempts_24h?.successful_attempts || 0}</div>
            <div className="mfa-stat-label">Successful</div>
          </div>
          <div className="stat-item">
            <div className="stat-number error">{mfaAnalytics?.attempts_24h?.failed_attempts || 0}</div>
            <div className="mfa-stat-label">Failed</div>
          </div>
          <div className="stat-item">
            <div className="stat-number">{(mfaAnalytics?.attempts_24h?.success_rate * 100)?.toFixed(0) || 0}%</div>
            <div className="mfa-stat-label">Success</div>
          </div>
        </div>
      </div>

      <div className="mfa-card">
        <div className="mfa-header">
          <span className="mfa-icon">⚡</span>
          <h3>Performance Metrics</h3>
          <span className="status-badge healthy">Monitoring</span>
        </div>
        <div className="mfa-performance">
          <div className="performance-item">
            <div className="performance-label">Average Completion Time</div>
            <div className="performance-value">{mfaAnalytics?.attempts_24h?.average_time_to_complete || 0}s</div>
          </div>
          <div className="performance-item">
            <div className="performance-label">Temporal Response Time</div>
            <div className="performance-value">{mfaAnalytics?.system_status?.average_response_time || '0.3s'}</div>
          </div>
          <div className="performance-item">
            <div className="performance-label">Workflow Health</div>
            <div className="performance-value success">{mfaAnalytics?.system_status?.temporal_workflows || 'Healthy'}</div>
          </div>
        </div>
      </div>
    </div>

    {/* MFA Methods Distribution */}
    <div className="mfa-methods-section">
      <h3>🔐 MFA Methods Usage</h3>
      <div className="mfa-methods-grid">
        {mfaAnalytics?.mfa_methods && Object.entries(mfaAnalytics.mfa_methods).map(([method, data]) => (
          <div key={method} className="method-card">
            <div className="method-header">
              <span className="method-icon">
                {method === 'email' ? '📧' : 
                 method === 'totp' ? '📱' : 
                 method === 'sms' ? '💬' : 
                 method === 'push' ? '🔔' : '🔑'}
              </span>
              <div className="method-name">{method.toUpperCase()}</div>
            </div>
            <div className="method-stats">
              <div className="method-count">{data.count || 0} uses</div>
              <div className={`method-success-rate ${data.success_rate > 0.9 ? 'excellent' : data.success_rate > 0.8 ? 'good' : 'warning'}`}>
                {(data.success_rate * 100)?.toFixed(1) || 0}% success
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>

    {/* Risk Distribution */}
    <div className="risk-distribution-section">
      <h3>⚠️ Risk Assessment Distribution</h3>
      <div className="risk-cards">
        <div className="risk-card low-risk">
          <div className="risk-header">
            <span className="risk-icon">🟢</span>
            <div className="mfa-risk-label">Low Risk</div>
          </div>
          <div className="risk-stats">
            <div className="risk-count">{mfaAnalytics?.risk_distribution?.low_risk?.count || 0}</div>
            <div className="risk-percentage">{mfaAnalytics?.risk_distribution?.low_risk?.percentage?.toFixed(1) || 0}%</div>
          </div>
        </div>

        <div className="risk-card medium-risk">
          <div className="risk-header">
            <span className="risk-icon">🟡</span>
            <div className="mfa-risk-label">Medium Risk</div>
          </div>
          <div className="risk-stats">
            <div className="risk-count">{mfaAnalytics?.risk_distribution?.medium_risk?.count || 0}</div>
            <div className="risk-percentage">{mfaAnalytics?.risk_distribution?.medium_risk?.percentage?.toFixed(1) || 0}%</div>
          </div>
        </div>

        <div className="risk-card high-risk">
          <div className="risk-header">
            <span className="risk-icon">🔴</span>
            <div className="mfa-risk-label">High Risk</div>
          </div>
          <div className="risk-stats">
            <div className="risk-count">{mfaAnalytics?.risk_distribution?.high_risk?.count || 0}</div>
            <div className="risk-percentage">{mfaAnalytics?.risk_distribution?.high_risk?.percentage?.toFixed(1) || 0}%</div>
          </div>
        </div>
      </div>
    </div>

    {/* Security Events */}
    <div className="security-events-section">
      <h3>🚨 Security Events</h3>
      <div className="security-events-grid">
        <div className="security-event-card">
          <div className="event-label">Rate Limit Violations</div>
          <div className="event-count warning">{mfaAnalytics?.security_events?.rate_limit_violations || 0}</div>
        </div>
        <div className="security-event-card">
          <div className="event-label">Suspicious Patterns</div>
          <div className="event-count error">{mfaAnalytics?.security_events?.suspicious_mfa_patterns || 0}</div>
        </div>
        <div className="security-event-card">
          <div className="event-label">Blocked Attempts</div>
          <div className="event-count error">{mfaAnalytics?.security_events?.blocked_attempts || 0}</div>
        </div>
        <div className="security-event-card">
          <div className="event-label">Account Lockouts</div>
          <div className="event-count critical">{mfaAnalytics?.security_events?.account_lockouts || 0}</div>
        </div>
      </div>
    </div>

    {/* Recent Security Events from Security Overview */}
    {securityOverview?.recent_events && (
      <div className="recent-events-section">
        <h3>📋 Recent Security Events</h3>
        <div className="events-list">
          {securityOverview.recent_events.slice(0, 10).map((event, index) => (
            <div key={index} className={`event-item ${event.severity}`}>
              <div className="event-timestamp">{new Date(event.timestamp).toLocaleString()}</div>
              <div className="event-type">{event.type.replace(/_/g, ' ').toUpperCase()}</div>
              <div className="event-description">{event.description}</div>
              <div className="event-action">{event.action_taken}</div>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* Security Score */}
    {securityOverview?.overall_security_score && (
      <div className="security-score-section">
        <div className="security-score-card">
          <h3>🏆 Overall Security Score</h3>
          <div className={`security-score ${securityOverview.overall_security_score >= 90 ? 'excellent' : 
                                            securityOverview.overall_security_score >= 80 ? 'good' : 
                                            securityOverview.overall_security_score >= 70 ? 'warning' : 'critical'}`}>
            {securityOverview.overall_security_score}/100
          </div>
          <div className="score-recommendations">
            <h4>Recommendations:</h4>
            {securityOverview.recommendations?.map((recommendation, index) => (
              <div key={index} className="recommendation">{recommendation}</div>
            ))}
          </div>
        </div>
      </div>
    )}
  </div>
);

export default MFATab;