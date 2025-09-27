import React, { useState, useEffect } from 'react';
import { FiUsers, FiBarChart2, FiTarget, FiActivity, FiCpu, FiSmartphone, FiAlertTriangle, FiAlertCircle, FiGlobe, FiClock, FiCheckCircle } from 'react-icons/fi';

const BehavioralAnalyticsTab = ({ behaviorAnalytics, realtimeEvents }) => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [selectedUser, setSelectedUser] = useState('');
  const [fraudAlerts, setFraudAlerts] = useState([]);
  const [highRiskUsers, setHighRiskUsers] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadBehavioralData();
  }, [selectedTimeRange]);

  const loadBehavioralData = async () => {
    try {
      setLoading(true);
      const adminToken = localStorage.getItem('admin_token');

      const baseUrl = 'http://localhost:8000';

      // Load fraud alerts
      const alertsResponse = await fetch(`${baseUrl}/behavioral-analytics/admin/fraud-alerts?limit=20`, {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (alertsResponse.ok) {
        const alerts = await alertsResponse.json();
        setFraudAlerts(alerts);
      }

      // Load dashboard data
      const dashboardResponse = await fetch(`${baseUrl}/behavioral-analytics/admin/behavior-analytics/dashboard`, {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (dashboardResponse.ok) {
        const dashboard = await dashboardResponse.json();
        setHighRiskUsers(dashboard.high_risk_users || []);
      }

    } catch (error) {
      console.error('Error loading behavioral analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      const adminToken = localStorage.getItem('admin_token');
      const baseUrl = 'http://localhost:8000';
      const response = await fetch(`${baseUrl}/behavioral-analytics/admin/fraud-alerts/${alertId}/resolve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        // Refresh alerts
        loadBehavioralData();
      }
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 0.8) return '#dc2626';
    if (score >= 0.6) return '#ea580c';
    if (score >= 0.4) return '#d97706';
    if (score >= 0.2) return '#65a30d';
    return '#16a34a';
  };

  const getRiskLevel = (score) => {
    if (score >= 0.8) return 'Critical';
    if (score >= 0.6) return 'High';
    if (score >= 0.4) return 'Medium';
    if (score >= 0.2) return 'Low';
    return 'Minimal';
  };

  return (
    <div className="behavioral-analytics-tab">
      {/* Header Controls */}
      <div className="analytics-controls">
        <div className="time-range-selector">
          <label>Time Range:</label>
          <select value={selectedTimeRange} onChange={(e) => setSelectedTimeRange(e.target.value)}>
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="behavioral-stats-grid">
        <div className="stat-card total-users">
          <div className="stat-icon"><FiUsers /></div>
          <div className="stat-content">
            <div className="stat-value">{behaviorAnalytics?.overview?.total_users_monitored || 0}</div>
            <div className="stat-label">Users Monitored</div>
          </div>
        </div>

        <div className="stat-card total-events">
          <div className="stat-icon"><FiBarChart2 /></div>
          <div className="stat-content">
            <div className="stat-value">{behaviorAnalytics?.overview?.total_events || 0}</div>
            <div className="stat-label">Behavioral Events</div>
          </div>
        </div>

        <div className="stat-card avg-risk">
          <div className="stat-icon"><FiTarget /></div>
          <div className="stat-content">
            <div className="stat-value">
              {(behaviorAnalytics?.overview?.average_risk_score || 0).toFixed(2)}
            </div>
            <div className="stat-label">Average Risk Score</div>
          </div>
        </div>

        <div className="stat-card active-alerts">
          <div className="stat-icon"><FiAlertTriangle /></div>
          <div className="stat-content">
            <div className="stat-value">{fraudAlerts.filter(a => a.status === 'active').length}</div>
            <div className="stat-label">Active Alerts</div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="analytics-main-grid">
        {/* High Risk Users */}
        <div className="analytics-section high-risk-users">
          <h3><FiAlertCircle className="text-red-500" /> High Risk Users</h3>
          <div className="risk-users-list">
            {highRiskUsers.length > 0 ? (
              highRiskUsers.map((user, i) => (
                <div key={i} className="risk-user-item">
                  <div className="user-info">
                    <div className="user-email">{user.email}</div>
                    <div className="user-timestamp">
                      {new Date(user.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className="risk-indicator">
                    <div
                      className="risk-score"
                      style={{ color: getRiskColor(user.risk_score) }}
                    >
                      {user.risk_score.toFixed(2)}
                    </div>
                    <div className="risk-level">{getRiskLevel(user.risk_score)}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="no-data">No high-risk users detected</div>
            )}
          </div>
        </div>

        {/* Real-time Behavioral Events */}
        <div className="analytics-section behavioral-events">
          <h3><FiActivity /> Real-time Behavioral Events</h3>
          <div className="events-feed">
            {realtimeEvents.slice(0, 8).map((event, i) => (
              <div key={i} className={`event-item ${event.severity || 'info'}`}>
                <div className="event-time">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </div>
                <div className="event-content">
                  <div className="event-user">{event.user_id || event.email}</div>
                  <div className="event-details">
                    Type: {event.event_type} |
                    Risk: {(event.risk_score || 0).toFixed(2)} |
                    {event.anomalies && ` Anomalies: ${event.anomalies.length}`}
                  </div>
                </div>
              </div>
            ))}
            {realtimeEvents.length === 0 && (
              <div className="no-events">No recent behavioral events</div>
            )}
          </div>
        </div>
      </div>

      {/* Fraud Alerts Section */}
      <div className="analytics-section fraud-alerts">
        <h3><FiAlertTriangle /> Fraud Alerts Management</h3>
        <div className="alerts-grid">
          {fraudAlerts.length > 0 ? (
            fraudAlerts.map((alert) => (
              <div key={alert.id} className={`alert-card ${alert.severity} ${alert.status}`}>
                <div className="alert-header">
                  <div className="alert-severity">
                    {alert.severity === 'critical' && <FiAlertCircle className="text-red-500" />}
                    {alert.severity === 'high' && <FiAlertCircle className="text-orange-500" />}
                    {alert.severity === 'medium' && <FiAlertCircle className="text-yellow-500" />}
                    {alert.severity === 'low' && <FiCheckCircle className="text-green-500" />}
                    {alert.severity.toUpperCase()}
                  </div>
                  <div className="alert-status">{alert.status.toUpperCase()}</div>
                </div>

                <div className="alert-content">
                  <div className="alert-user">User: {alert.user_id}</div>
                  <div className="alert-type">Type: {alert.alert_type}</div>
                  <div className="alert-risk">
                    Risk Score: <span style={{ color: getRiskColor(alert.risk_score) }}>
                      {alert.risk_score.toFixed(2)}
                    </span>
                  </div>
                  <div className="alert-time">
                    {new Date(alert.created_at).toLocaleString()}
                  </div>
                </div>

                {alert.status === 'active' && (
                  <div className="alert-actions">
                    <button
                      className="resolve-btn"
                      onClick={() => resolveAlert(alert.id)}
                    >
                      Resolve Alert
                    </button>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className="no-alerts">No fraud alerts at this time</div>
          )}
        </div>
      </div>

      {/* Analytics Insights */}
      <div className="analytics-insights">
        <h3><FiCpu /> Behavioral Insights</h3>
        <div className="insights-grid">
          <div className="insight-card">
            <h4><FiGlobe /> Location Analytics</h4>
            <p>Monitoring geographic patterns and detecting impossible travel scenarios</p>
            <div className="insight-stat">
              Location anomalies detected: {behaviorAnalytics?.location_anomalies || 0}
            </div>
          </div>

          <div className="insight-card">
            <h4><FiSmartphone /> Device Analytics</h4>
            <p>Tracking device fingerprints and identifying new or suspicious devices</p>
            <div className="insight-stat">
              New devices this week: {behaviorAnalytics?.new_devices || 0}
            </div>
          </div>

          <div className="insight-card">
            <h4><FiClock /> Temporal Analytics</h4>
            <p>Analyzing login time patterns and detecting unusual activity times</p>
            <div className="insight-stat">
              Off-hours logins: {behaviorAnalytics?.off_hours_logins || 0}
            </div>
          </div>

          <div className="insight-card">
            <h4><FiCpu /> AI Analysis</h4>
            <p>Machine learning-powered risk assessment and pattern recognition</p>
            <div className="insight-stat">
              AI model accuracy: {behaviorAnalytics?.ai_accuracy || 'N/A'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BehavioralAnalyticsTab;