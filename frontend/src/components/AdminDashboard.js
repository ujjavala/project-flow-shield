import React, { useState, useEffect } from 'react';
import './AdminDashboard.css';

const AdminDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [userStats, setUserStats] = useState(null);
  const [serviceStatus, setServiceStatus] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [temporalStatus, setTemporalStatus] = useState(null);
  const [fraudAnalytics, setFraudAnalytics] = useState(null);
  const [realtimeEvents, setRealtimeEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  useEffect(() => {
    loadAllData();
    if (autoRefresh) {
      const interval = setInterval(loadAllData, 30000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const loadAllData = async () => {
    try {
      setLoading(true);
      
      const baseUrl = 'http://localhost:8000';
      
      const [
        healthResponse,
        usersResponse,
        servicesResponse,
        aiResponse,
        temporalResponse,
        fraudAnalyticsResponse,
        realtimeEventsResponse
      ] = await Promise.allSettled([
        fetch(`${baseUrl}/admin/health`),
        fetch(`${baseUrl}/admin/users`),
        fetch(`${baseUrl}/admin/services`),
        fetch(`${baseUrl}/admin/ai-status`),
        fetch(`${baseUrl}/admin/temporal-status`),
        fetch(`${baseUrl}/admin/fraud-analytics`),
        fetch(`${baseUrl}/admin/fraud-events/realtime?limit=20`)
      ]);

      if (healthResponse.status === 'fulfilled') {
        setSystemHealth(await healthResponse.value.json());
      }
      
      if (usersResponse.status === 'fulfilled') {
        setUserStats(await usersResponse.value.json());
      }
      
      if (servicesResponse.status === 'fulfilled') {
        setServiceStatus(await servicesResponse.value.json());
      }
      
      if (aiResponse.status === 'fulfilled') {
        setAiStatus(await aiResponse.value.json());
      }
      
      if (temporalResponse.status === 'fulfilled') {
        setTemporalStatus(await temporalResponse.value.json());
      }
      
      if (fraudAnalyticsResponse.status === 'fulfilled') {
        setFraudAnalytics(await fraudAnalyticsResponse.value.json());
      }
      
      if (realtimeEventsResponse.status === 'fulfilled') {
        const eventsData = await realtimeEventsResponse.value.json();
        setRealtimeEvents(eventsData?.events || []);
      }

      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError('Failed to load dashboard data: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const performAction = async (action, target, parameters = {}) => {
    try {
      const response = await fetch('http://localhost:8000/admin/actions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action, target, parameters })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        alert(`✅ ${action} successful!\n${JSON.stringify(result.result, null, 2)}`);
      } else {
        alert(`❌ ${action} failed: ${result.error}`);
      }
      
      await loadAllData();
    } catch (err) {
      alert(`❌ Action failed: ${err.message}`);
    }
  };

  if (loading && !dashboardData) {
    return (
      <div className="admin-dashboard">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <div className="loading-text">
            <h2>🚀 Loading Admin Dashboard...</h2>
            <p>Fetching system status, metrics, and analytics</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="admin-dashboard">
        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <h2>Dashboard Error</h2>
          <p>{error}</p>
          <button onClick={loadAllData} className="retry-btn">
            🔄 Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-title">
          <h1>🛡️ Fraud Detection Admin Dashboard</h1>
          <p>Real-time monitoring and fraud analytics</p>
        </div>
        
        <div className="header-controls">
          <div className="status-indicator">
            <span className={`status-dot ${systemHealth?.status || 'unknown'}`}></span>
            <span>System {systemHealth?.status || 'Unknown'}</span>
          </div>
          
          <div className="last-updated">
            Last: {lastUpdated.toLocaleTimeString()}
          </div>
          
          <label className="auto-refresh-toggle">
            <input 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh
          </label>
          
          <button onClick={loadAllData} className="refresh-btn" disabled={loading}>
            {loading ? '⏳' : '🔄'}
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="dashboard-tabs">
        <button 
          className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={`tab-button ${activeTab === 'fraud' ? 'active' : ''}`}
          onClick={() => setActiveTab('fraud')}
        >
          🚨 Fraud Analytics
        </button>
        <button 
          className={`tab-button ${activeTab === 'services' ? 'active' : ''}`}
          onClick={() => setActiveTab('services')}
        >
          🔧 Services
        </button>
        <button 
          className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          👥 Users
        </button>
        <button 
          className={`tab-button ${activeTab === 'ai' ? 'active' : ''}`}
          onClick={() => setActiveTab('ai')}
        >
          🤖 AI System
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'overview' && <OverviewTab systemHealth={systemHealth} fraudAnalytics={fraudAnalytics} />}
        {activeTab === 'fraud' && <FraudTab fraudAnalytics={fraudAnalytics} realtimeEvents={realtimeEvents} />}
        {activeTab === 'services' && <ServicesTab serviceStatus={serviceStatus} temporalStatus={temporalStatus} />}
        {activeTab === 'users' && <UsersTab userStats={userStats} />}
        {activeTab === 'ai' && <AITab aiStatus={aiStatus} fraudAnalytics={fraudAnalytics} />}
      </div>
    </div>
  );
};

// Overview Tab
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

// Fraud Analytics Tab
const FraudTab = ({ fraudAnalytics, realtimeEvents }) => (
  <div className="fraud-tab">
    <div className="fraud-stats-grid">
      <div className="stat-card high-risk">
        <div className="stat-icon">🔴</div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.high_risk_count || 0}</div>
          <div className="stat-label">High Risk</div>
        </div>
      </div>

      <div className="stat-card medium-risk">
        <div className="stat-icon">🟡</div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.medium_risk_count || 0}</div>
          <div className="stat-label">Medium Risk</div>
        </div>
      </div>

      <div className="stat-card low-risk">
        <div className="stat-icon">🟢</div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.low_risk_count || 0}</div>
          <div className="stat-label">Low Risk</div>
        </div>
      </div>

      <div className="stat-card blocked">
        <div className="stat-icon">⛔</div>
        <div className="stat-content">
          <div className="stat-value">{fraudAnalytics?.fraud_stats?.blocked_count || 0}</div>
          <div className="stat-label">Blocked</div>
        </div>
      </div>
    </div>

    <div className="activity-section">
      <h3>🔄 Real-time Fraud Events</h3>
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

// Services Tab
const ServicesTab = ({ serviceStatus, temporalStatus }) => (
  <div className="services-tab">
    <div className="services-grid">
      <div className="service-card">
        <div className="service-header">
          <span className="service-icon">🖥️</span>
          <h3>Simple Server</h3>
          <span className={`status-badge ${serviceStatus?.simple_server?.status || 'unknown'}`}>
            {serviceStatus?.simple_server?.status || 'Unknown'}
          </span>
        </div>
        <div className="service-details">
          <p>Port: {serviceStatus?.simple_server?.port || 'N/A'}</p>
          <p>Features: {serviceStatus?.simple_server?.features?.join(', ') || 'None'}</p>
        </div>
      </div>

      <div className="service-card">
        <div className="service-header">
          <span className="service-icon">🔧</span>
          <h3>Main Backend</h3>
          <span className={`status-badge ${serviceStatus?.main_backend?.status || 'unknown'}`}>
            {serviceStatus?.main_backend?.status || 'Unknown'}
          </span>
        </div>
        <div className="service-details">
          <p>Port: {serviceStatus?.main_backend?.port || 'N/A'}</p>
          <p>Features: {serviceStatus?.main_backend?.features?.join(', ') || 'None'}</p>
        </div>
      </div>

      <div className="service-card">
        <div className="service-header">
          <span className="service-icon">🌊</span>
          <h3>Temporal</h3>
          <span className={`status-badge ${temporalStatus?.temporal_connected ? 'healthy' : 'critical'}`}>
            {temporalStatus?.temporal_connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <div className="service-details">
          <p>Server: {temporalStatus?.temporal_server || 'N/A'}</p>
          <p>Namespace: {temporalStatus?.namespace || 'default'}</p>
          <p>Task Queue: {temporalStatus?.task_queue || 'N/A'}</p>
        </div>
      </div>
    </div>
  </div>
);

// Users Tab
const UsersTab = ({ userStats }) => (
  <div className="users-tab">
    <div className="user-stats-grid">
      <div className="user-stat-card">
        <div className="stat-icon">👥</div>
        <div className="stat-value">{userStats?.total_users || 0}</div>
        <div className="stat-label">Total Users</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon">✅</div>
        <div className="stat-value">{userStats?.verified_users || 0}</div>
        <div className="stat-label">Verified Users</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon">⏳</div>
        <div className="stat-value">{userStats?.pending_verification || 0}</div>
        <div className="stat-label">Pending Verification</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon">🔄</div>
        <div className="stat-value">{userStats?.recent_registrations_24h || 0}</div>
        <div className="stat-label">New Today</div>
      </div>
    </div>
  </div>
);

// AI System Tab
const AITab = ({ aiStatus, fraudAnalytics }) => (
  <div className="ai-tab">
    <div className="ai-metrics-grid">
      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">🤖</span>
          <h3>Ollama Status</h3>
          <span className={`status-badge ${aiStatus?.ollama_available ? 'healthy' : 'critical'}`}>
            {aiStatus?.ollama_available ? 'Online' : 'Offline'}
          </span>
        </div>
        <div className="ai-details">
          <p>Model: {aiStatus?.model_name || 'llama3'}</p>
          <p>Endpoint: {aiStatus?.endpoint || 'localhost:11434'}</p>
        </div>
      </div>

      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">⚡</span>
          <h3>Performance</h3>
          <span className="status-badge healthy">Active</span>
        </div>
        <div className="ai-details">
          <p>Response Time: {fraudAnalytics?.ai_model_stats?.avg_response_time_ms || 0}ms</p>
          <p>Accuracy: {fraudAnalytics?.ai_model_stats?.model_accuracy || 0}%</p>
        </div>
      </div>

      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">📊</span>
          <h3>Usage Stats</h3>
          <span className="status-badge healthy">Monitoring</span>
        </div>
        <div className="ai-details">
          <p>Total Requests: {fraudAnalytics?.ai_model_stats?.total_ai_requests || 0}</p>
          <p>Availability: {fraudAnalytics?.ai_model_stats?.ai_availability || 0}%</p>
        </div>
      </div>
    </div>
  </div>
);

// Chart Components
const RiskDistributionChart = ({ data }) => {
  if (!data) return <div className="no-data">No data available</div>;
  
  const total = Object.values(data).reduce((sum, val) => sum + val, 0);
  
  return (
    <div className="risk-chart">
      {Object.entries(data).map(([key, value]) => (
        <div key={key} className="risk-bar">
          <span className="risk-label">{key}</span>
          <div className="risk-bar-container">
            <div 
              className={`risk-bar-fill ${key}`}
              style={{ width: `${(value / total) * 100}%` }}
            ></div>
          </div>
          <span className="risk-value">{value}</span>
        </div>
      ))}
    </div>
  );
};

const RiskFactorsChart = ({ data }) => {
  if (!data) return <div className="no-data">No data available</div>;
  
  return (
    <div className="risk-factors-chart">
      {data.slice(0, 5).map((factor, i) => (
        <div key={i} className="factor-item">
          <span className="factor-name">{factor.factor.replace(/_/g, ' ')}</span>
          <div className="factor-bar">
            <div 
              className="factor-fill"
              style={{ width: `${factor.percentage}%` }}
            ></div>
          </div>
          <span className="factor-percentage">{factor.percentage}%</span>
        </div>
      ))}
    </div>
  );
};

export default AdminDashboard;