import React, { useState, useEffect } from 'react';
import './AdminDashboard.css';

const AdminDashboard = () => {
  const [analytics, setAnalytics] = useState(null);
  const [realtimeEvents, setRealtimeEvents] = useState([]);
  const [aiHealth, setAiHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState(24);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadRealtimeEvents, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load analytics data
      const analyticsResponse = await fetch(`/admin/fraud-analytics?hours=${timeRange}`);
      const analyticsData = await analyticsResponse.json();
      setAnalytics(analyticsData);

      // Load AI health
      const aiHealthResponse = await fetch('/admin/ai-health/detailed');
      const aiHealthData = await aiHealthResponse.json();
      setAiHealth(aiHealthData);

      setError(null);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const loadRealtimeEvents = async () => {
    try {
      const response = await fetch('/admin/fraud-events/realtime?limit=20');
      const data = await response.json();
      setRealtimeEvents(data.events);
    } catch (err) {
      console.error('Failed to load realtime events:', err);
    }
  };

  const simulateEvents = async () => {
    try {
      await fetch('/admin/fraud-events/simulate?count=10', { method: 'POST' });
      await loadDashboardData();
      await loadRealtimeEvents();
    } catch (err) {
      console.error('Failed to simulate events:', err);
    }
  };

  if (loading && !analytics) {
    return (
      <div className="admin-dashboard">
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading fraud analytics dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="admin-dashboard">
        <div className="error">
          <h2>🚨 Dashboard Error</h2>
          <p>{error}</p>
          <button onClick={loadDashboardData}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-dashboard">
      <div className="dashboard-header">
        <h1>🛡️ AI-Powered Fraud Detection Dashboard</h1>
        <div className="dashboard-controls">
          <select value={timeRange} onChange={(e) => setTimeRange(parseInt(e.target.value))}>
            <option value={1}>Last Hour</option>
            <option value={24}>Last 24 Hours</option>
            <option value={168}>Last Week</option>
          </select>
          <button onClick={loadDashboardData} className="refresh-btn">🔄 Refresh</button>
          <button onClick={simulateEvents} className="simulate-btn">⚡ Simulate Events</button>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Key Metrics */}
        <div className="metrics-row">
          <MetricCard 
            title="Total Registrations"
            value={analytics?.fraud_stats?.total_registrations || 0}
            icon="👥"
            trend="+12% from yesterday"
          />
          <MetricCard 
            title="Fraud Rate"
            value={`${analytics?.fraud_stats?.fraud_rate || 0}%`}
            icon="🚨"
            trend={analytics?.fraud_stats?.fraud_rate > 15 ? "⚠️ Above threshold" : "✅ Normal"}
            critical={analytics?.fraud_stats?.fraud_rate > 15}
          />
          <MetricCard 
            title="AI Accuracy"
            value={`${aiHealth?.model_info?.accuracy_score || 94.2}%`}
            icon="🤖"
            trend="Ollama + Fallback"
          />
          <MetricCard 
            title="Blocked Accounts"
            value={analytics?.fraud_stats?.blocked_count || 0}
            icon="🛑"
            trend="High-risk registrations"
          />
        </div>

        {/* Charts Row */}
        <div className="charts-row">
          <div className="chart-container">
            <h3>📊 Risk Distribution</h3>
            <RiskDistributionChart data={analytics?.risk_distribution} />
          </div>
          
          <div className="chart-container">
            <h3>📈 Fraud Timeline</h3>
            <FraudTimelineChart data={analytics?.fraud_timeline} />
          </div>
        </div>

        {/* AI Performance */}
        <div className="ai-performance-section">
          <h3>🤖 AI System Performance</h3>
          <div className="ai-metrics">
            <div className="ai-metric">
              <span className="label">Ollama Requests</span>
              <span className="value">{analytics?.ai_model_stats?.ollama_requests || 0}</span>
            </div>
            <div className="ai-metric">
              <span className="label">Fallback Requests</span>
              <span className="value">{analytics?.ai_model_stats?.fallback_requests || 0}</span>
            </div>
            <div className="ai-metric">
              <span className="label">Avg Response Time</span>
              <span className="value">{analytics?.ai_model_stats?.avg_response_time_ms || 0}ms</span>
            </div>
            <div className="ai-metric">
              <span className="label">AI Availability</span>
              <span className="value">{analytics?.ai_model_stats?.ai_availability || 100}%</span>
            </div>
          </div>
        </div>

        {/* Top Risk Factors */}
        <div className="risk-factors-section">
          <h3>⚠️ Top Risk Factors</h3>
          <div className="risk-factors-list">
            {analytics?.top_risk_factors?.map((factor, index) => (
              <div key={index} className="risk-factor-item">
                <span className="factor-name">{factor.factor}</span>
                <span className="factor-count">{factor.count} events</span>
                <span className="factor-percentage">{factor.percentage}%</span>
                <div className="factor-bar">
                  <div 
                    className="factor-fill"
                    style={{ width: `${factor.percentage}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Realtime Events */}
        <div className="realtime-events-section">
          <h3>⚡ Real-time Fraud Events</h3>
          <div className="events-list">
            {realtimeEvents.map((event) => (
              <div key={event.id} className={`event-item ${event.severity}`}>
                <div className="event-time">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </div>
                <div className="event-email">{event.email}</div>
                <div className="event-score">
                  Score: {event.fraud_score.toFixed(2)}
                </div>
                <div className="event-level">{event.risk_level}</div>
                <div className="event-factors">
                  {event.risk_factors.slice(0, 2).map(factor => (
                    <span key={factor} className="factor-tag">{factor}</span>
                  ))}
                </div>
                {event.blocked && <span className="blocked-badge">BLOCKED</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Recent High-Risk Events */}
        <div className="high-risk-events-section">
          <h3>🚨 Recent High-Risk Events</h3>
          <div className="high-risk-list">
            {analytics?.recent_high_risk_events?.map((event, index) => (
              <div key={index} className="high-risk-item">
                <div className="event-header">
                  <span className="event-email">{event.email}</span>
                  <span className={`event-score ${event.fraud_score > 0.8 ? 'critical' : 'high'}`}>
                    {event.fraud_score.toFixed(3)}
                  </span>
                </div>
                <div className="event-time">
                  {new Date(event.timestamp).toLocaleString()}
                </div>
                <div className="event-factors">
                  {event.risk_factors.map(factor => (
                    <span key={factor} className="risk-tag">{factor}</span>
                  ))}
                </div>
                {event.blocked && (
                  <div className="blocked-status">🛑 Registration Blocked</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Temporal Workflow Link */}
      <div className="temporal-link">
        <a 
          href="http://localhost:8081" 
          target="_blank" 
          rel="noopener noreferrer"
          className="temporal-button"
        >
          🌊 View in Temporal UI
        </a>
        <p>Monitor AI-powered workflows and search by fraud scores</p>
      </div>
    </div>
  );
};

const MetricCard = ({ title, value, icon, trend, critical = false }) => (
  <div className={`metric-card ${critical ? 'critical' : ''}`}>
    <div className="metric-icon">{icon}</div>
    <div className="metric-content">
      <h4>{title}</h4>
      <div className="metric-value">{value}</div>
      <div className="metric-trend">{trend}</div>
    </div>
  </div>
);

const RiskDistributionChart = ({ data }) => {
  if (!data) return <div className="no-data">No data available</div>;

  const total = Object.values(data).reduce((sum, count) => sum + count, 0);
  
  return (
    <div className="risk-chart">
      {Object.entries(data).map(([level, count]) => {
        const percentage = total > 0 ? (count / total) * 100 : 0;
        return (
          <div key={level} className="risk-bar">
            <span className="risk-label">{level}</span>
            <div className="risk-progress">
              <div 
                className={`risk-fill ${level}`}
                style={{ width: `${percentage}%` }}
              ></div>
            </div>
            <span className="risk-count">{count} ({percentage.toFixed(1)}%)</span>
          </div>
        );
      })}
    </div>
  );
};

const FraudTimelineChart = ({ data }) => {
  if (!data || data.length === 0) return <div className="no-data">No timeline data available</div>;

  const maxValue = Math.max(...data.map(point => point.value));

  return (
    <div className="timeline-chart">
      {data.map((point, index) => {
        const height = maxValue > 0 ? (point.value / maxValue) * 100 : 0;
        return (
          <div key={index} className="timeline-bar" title={`${point.timestamp}: ${point.value} (${point.label})`}>
            <div 
              className="timeline-fill"
              style={{ height: `${height}%` }}
            ></div>
            <span className="timeline-time">
              {new Date(point.timestamp).getHours()}:00
            </span>
          </div>
        );
      })}
    </div>
  );
};

export default AdminDashboard;