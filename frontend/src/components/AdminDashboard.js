import React, { useState, useEffect } from 'react';
import './AdminDashboard.css';
import OverviewTab from './AdminDashboard/tabs/OverviewTab';
import FraudTab from './AdminDashboard/tabs/FraudTab';
import ServicesTab from './AdminDashboard/tabs/ServicesTab';
import UsersTab from './AdminDashboard/tabs/UsersTab';
import AITab from './AdminDashboard/tabs/AITab';
import MFATab from './AdminDashboard/tabs/MFATab';
import FlowShieldLogo from './common/FlowShieldLogo';
import './common/FlowShieldLogo.css';

const AdminDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [userStats, setUserStats] = useState(null);
  const [serviceStatus, setServiceStatus] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [temporalStatus, setTemporalStatus] = useState(null);
  const [fraudAnalytics, setFraudAnalytics] = useState(null);
  const [mfaAnalytics, setMfaAnalytics] = useState(null);
  const [securityOverview, setSecurityOverview] = useState(null);
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
        mfaAnalyticsResponse,
        securityOverviewResponse,
        realtimeEventsResponse
      ] = await Promise.allSettled([
        fetch(`${baseUrl}/admin/health`),
        fetch(`${baseUrl}/admin/users`),
        fetch(`${baseUrl}/admin/services`),
        fetch(`${baseUrl}/admin/ai-status`),
        fetch(`${baseUrl}/admin/temporal-status`),
        fetch(`${baseUrl}/admin/fraud-analytics`),
        fetch(`${baseUrl}/admin/mfa-analytics`),
        fetch(`${baseUrl}/admin/security-overview`),
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
      
      if (mfaAnalyticsResponse.status === 'fulfilled') {
        setMfaAnalytics(await mfaAnalyticsResponse.value.json());
      }
      
      if (securityOverviewResponse.status === 'fulfilled') {
        setSecurityOverview(await securityOverviewResponse.value.json());
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <FlowShieldLogo size={36} />
            <h1>FlowShield Admin Dashboard</h1>
          </div>
          <p>AI-Powered Security Platform • Temporal-Reliable Authentication</p>
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
        <button 
          className={`tab-button ${activeTab === 'mfa' ? 'active' : ''}`}
          onClick={() => setActiveTab('mfa')}
        >
          <FlowShieldLogo size={18} /> MFA Security
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'overview' && <OverviewTab systemHealth={systemHealth} fraudAnalytics={fraudAnalytics} />}
        {activeTab === 'fraud' && <FraudTab fraudAnalytics={fraudAnalytics} realtimeEvents={realtimeEvents} />}
        {activeTab === 'services' && <ServicesTab serviceStatus={serviceStatus} temporalStatus={temporalStatus} />}
        {activeTab === 'users' && <UsersTab userStats={userStats} />}
        {activeTab === 'ai' && <AITab aiStatus={aiStatus} fraudAnalytics={fraudAnalytics} />}
        {activeTab === 'mfa' && <MFATab mfaAnalytics={mfaAnalytics} securityOverview={securityOverview} />}
      </div>
    </div>
  );
};




export default AdminDashboard;