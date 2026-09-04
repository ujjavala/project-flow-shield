import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { TriangleAlert as FiAlertTriangle } from 'lucide-react';
import './AdminDashboard.css';
import OverviewTab from './AdminDashboard/tabs/OverviewTab';
import FraudTab from './AdminDashboard/tabs/FraudTab';
import ServicesTab from './AdminDashboard/tabs/ServicesTab';
import UsersTab from './AdminDashboard/tabs/UsersTab';
import AITab from './AdminDashboard/tabs/AITab';
import MFATab from './AdminDashboard/tabs/MFATab';
import BehavioralAnalyticsTab from './AdminDashboard/tabs/BehavioralAnalyticsTab';
import PredictiveAttackTab from './AdminDashboard/tabs/PredictiveAttackTab';
import FlowShieldLogo from './common/FlowShieldLogo';
import './common/FlowShieldLogo.css';
import { authenticatedFetch } from '../services/bffService';
import { useAuth } from '../context/AuthContext';

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
  const [behaviorAnalytics, setBehaviorAnalytics] = useState(null);
  const [realtimeEvents, setRealtimeEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const navigate = useNavigate();
  const { logout } = useAuth();

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

      const baseUrl = '';
      const headers = { 'Content-Type': 'application/json' };
      
      const [
        healthResponse,
        usersResponse,
        servicesResponse,
        aiResponse,
        temporalResponse,
        fraudAnalyticsResponse,
        mfaAnalyticsResponse,
        securityOverviewResponse,
        behaviorAnalyticsResponse,
        realtimeEventsResponse
      ] = await Promise.allSettled([
        authenticatedFetch(`${baseUrl}/admin/health`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/users`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/services`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/ai-status`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/temporal-status`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/fraud-analytics`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/mfa-analytics`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/security-overview`, { headers }),
        authenticatedFetch(`${baseUrl}/behavioral-analytics/admin/behavior-analytics/dashboard`, { headers }),
        authenticatedFetch(`${baseUrl}/admin/fraud-events/realtime?limit=20`, { headers })
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

      if (behaviorAnalyticsResponse.status === 'fulfilled') {
        setBehaviorAnalytics(await behaviorAnalyticsResponse.value.json());
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

  const handleAdminLogout = async () => {
    setLogoutLoading(true);
    try {
      await logout();
    } catch (error) {
      console.error('Admin logout error:', error);
    } finally {
      // Small delay to show loading state
      setTimeout(() => {
        toast.success('Admin session ended successfully');
        navigate('/admin/login');
      }, 800);
    }
  };

  const performAction = async (action, target, parameters = {}) => {
    try {
      const response = await authenticatedFetch('/admin/actions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action, target, parameters })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        alert(`${action} successful!\n${JSON.stringify(result.result, null, 2)}`);
      } else {
        alert(`${action} failed: ${result.error}`);
      }
      
      await loadAllData();
    } catch (err) {
      alert(`Action failed: ${err.message}`);
    }
  };

  if (loading && !dashboardData) {
    return (
      <div className="admin-dashboard">
        <div className="loading-container">
          <div className="loading-text">
            <h2>Loading Admin Dashboard...</h2>
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
          <div className="error-icon icon-warning icon-large"><FiAlertTriangle /></div>
          <h2>Dashboard Error</h2>
          <p>{error}</p>
          <button onClick={loadAllData} className="retry-btn">
            Retry
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
            <FlowShieldLogo size={48} />
            <div>
              <h1>FlowShield Admin Dashboard</h1>
            </div>
          </div>
          <p>AI-Powered Security Platform • Administrative Control Center</p>
        </div>
        
        <div className="header-controls">
          <button onClick={loadAllData} className="refresh-btn" disabled={loading}>
            {loading ? 'Loading...' : 'Refresh'}
          </button>

          <button onClick={handleAdminLogout} className="logout-btn" disabled={logoutLoading}>
            {logoutLoading ? 'Logging you out...' : 'Logout'}
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="dashboard-tabs">
        <button
          className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`tab-button ${activeTab === 'services' ? 'active' : ''}`}
          onClick={() => setActiveTab('services')}
        >
          Services
        </button>
        <button
          className={`tab-button ${activeTab === 'fraud' ? 'active' : ''}`}
          onClick={() => setActiveTab('fraud')}
        >
          Fraud Analytics
        </button>
        <button
          className={`tab-button ${activeTab === 'behavior' ? 'active' : ''}`}
          onClick={() => setActiveTab('behavior')}
        >
          AI Behavior
        </button>
        <button
          className={`tab-button ${activeTab === 'predictive' ? 'active' : ''}`}
          onClick={() => setActiveTab('predictive')}
        >
          Predictive Attack
        </button>
        <button
          className={`tab-button ${activeTab === 'mfa' ? 'active' : ''}`}
          onClick={() => setActiveTab('mfa')}
        >
          MFA Security
        </button>
        <button
          className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          Users
        </button>
        <button
          className={`tab-button ${activeTab === 'ai' ? 'active' : ''}`}
          onClick={() => setActiveTab('ai')}
        >
          AI System
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'overview' && <OverviewTab systemHealth={systemHealth} fraudAnalytics={fraudAnalytics} />}
        {activeTab === 'fraud' && <FraudTab fraudAnalytics={fraudAnalytics} realtimeEvents={realtimeEvents} />}
        {activeTab === 'behavior' && <BehavioralAnalyticsTab behaviorAnalytics={behaviorAnalytics} realtimeEvents={realtimeEvents} />}
        {activeTab === 'services' && <ServicesTab serviceStatus={serviceStatus} temporalStatus={temporalStatus} />}
        {activeTab === 'users' && <UsersTab userStats={userStats} />}
        {activeTab === 'ai' && <AITab aiStatus={aiStatus} fraudAnalytics={fraudAnalytics} onRefresh={loadAllData} />}
        {activeTab === 'mfa' && <MFATab mfaAnalytics={mfaAnalytics} securityOverview={securityOverview} />}
        {activeTab === 'predictive' && <PredictiveAttackTab />}
      </div>
    </div>
  );
};




export default AdminDashboard;