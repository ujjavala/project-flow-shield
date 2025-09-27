import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import './Dashboard.css';
import LineChart from './Dashboard/components/LineChart';
import MetricCard from './Dashboard/components/MetricCard';
import HealthCard from './Dashboard/components/HealthCard';
import FlowShieldLogo from './common/FlowShieldLogo';
import './common/FlowShieldLogo.css';
import {
  FiSettings,
  FiLock,
  FiUnlock,
  FiAlertTriangle,
  FiCheckCircle,
  FiMail,
  FiGlobe,
  FiFileText
} from 'react-icons/fi';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [systemStats, setSystemStats] = useState({
    uptime: '00:00:00',
    activeUsers: 0,
    totalRequests: 0,
    successRate: 0,
    responseTime: 0,
    cpuUsage: 0,
    memoryUsage: 0,
    networkActivity: 0
  });
  const [realtimeData, setRealtimeData] = useState([]);
  const [chartData, setChartData] = useState([]);
  const chartRef = useRef(null);
  const canvasRef = useRef(null);

  useEffect(() => {
    fetchUserProfile();
    startRealtimeUpdates();
    initializeCharts();
    return () => {
      clearInterval(window.dashboardInterval);
      clearInterval(window.chartIntervalRef);
    };
  }, []);


  const initializeCharts = () => {
    // Initialize chart data
    const initialData = Array.from({ length: 20 }, (_, i) => ({
      time: new Date(Date.now() - (19 - i) * 2000).toLocaleTimeString(),
      cpu: Math.random() * 100,
      memory: Math.random() * 100,
      network: Math.random() * 100,
      requests: Math.floor(Math.random() * 100) + 20
    }));
    setChartData(initialData);

    // Update charts periodically
    const chartInterval = setInterval(() => {
      const newPoint = {
        time: new Date().toLocaleTimeString(),
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 100,
        requests: Math.floor(Math.random() * 100) + 20
      };

      setChartData(prev => [...prev.slice(-19), newPoint]);
    }, 2000);

    // Store interval reference for cleanup
    window.chartIntervalRef = chartInterval;
  };

  const startRealtimeUpdates = () => {
    // Simulate real-time data updates
    window.dashboardInterval = setInterval(() => {
      const newDataPoint = {
        timestamp: new Date().toLocaleTimeString(),
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 100,
        requests: Math.floor(Math.random() * 50) + 10
      };
      
      setRealtimeData(prev => [...prev.slice(-19), newDataPoint]);
      
      // Update system stats with realistic small variations
      setSystemStats(prev => ({
        ...prev,
        // Keep active users more stable (you + maybe a few others)
        activeUsers: Math.max(1, Math.min(5, prev.activeUsers + Math.floor(Math.random() * 3) - 1)),
        totalRequests: prev.totalRequests + Math.floor(Math.random() * 3), // Slow growth
        successRate: Math.max(95, Math.min(100, prev.successRate + (Math.random() - 0.5) * 0.5)), // Very stable
        responseTime: Math.max(10, Math.min(200, prev.responseTime + (Math.random() - 0.5) * 5)), // Small variations
        cpuUsage: Math.max(0, Math.min(100, prev.cpuUsage + (Math.random() - 0.5) * 5)),
        memoryUsage: Math.max(0, Math.min(100, prev.memoryUsage + (Math.random() - 0.5) * 3)),
        networkActivity: Math.max(0, Math.min(100, prev.networkActivity + (Math.random() - 0.5) * 8))
      }));
    }, 2000);
  };

  const fetchUserProfile = async () => {
    setLoading(true);
    try {
      setUserProfile(user);

      // Fetch user-specific data from backend
      const token = localStorage.getItem('token');
      if (!token) {
        console.warn('No authentication token found');
        setLoading(false);
        return;
      }

      const baseUrl = 'http://localhost:8000';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      try {
        const [profileResponse, activityResponse, securityResponse] = await Promise.allSettled([
          fetch(`${baseUrl}/dashboard/profile`, { headers }),
          fetch(`${baseUrl}/dashboard/activity`, { headers }),
          fetch(`${baseUrl}/dashboard/security`, { headers })
        ]);

        if (profileResponse.status === 'fulfilled' && profileResponse.value.ok) {
          const profileData = await profileResponse.value.json();
          setUserProfile(profileData);
        }

        if (activityResponse.status === 'fulfilled' && activityResponse.value.ok) {
          const activityData = await activityResponse.value.json();
          setSystemStats(prev => ({
            ...prev,
            activeUsers: 1, // Current user
            totalRequests: activityData.total_requests || 0,
            successRate: activityData.success_rate || 95,
            responseTime: activityData.avg_response_time || Math.random() * 50 + 10,
            cpuUsage: Math.random() * 30 + 10,
            memoryUsage: Math.random() * 40 + 30,
            networkActivity: Math.random() * 60 + 20
          }));
        }

        if (securityResponse.status === 'fulfilled' && securityResponse.value.ok) {
          const securityData = await securityResponse.value.json();
          // Update any security-related stats if needed
          console.log('User security data:', securityData);
        }
      } catch (fetchError) {
        console.warn('Could not fetch real data, using fallback:', fetchError);
        // Fallback to reasonable defaults
        setSystemStats(prev => ({
          ...prev,
          activeUsers: 1, // Just the current user
          totalRequests: 145,
          successRate: 98.5,
          responseTime: 35
        }));
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLogoutLoading(true);
    setTimeout(() => {
      logout();
    }, 800); // Small delay to show the loading state
  };

  const getHealthStatus = (value, inverted = false) => {
    const threshold = inverted ? 70 : 30;
    if (inverted) {
      return value > 80 ? 'critical' : value > threshold ? 'warning' : 'healthy';
    }
    return value < 30 ? 'critical' : value < threshold ? 'warning' : 'healthy';
  };

  if (loading) {
    return (
      <div className="dashboard-loading-container">
          <div className="loading-text">Loading dashboard...</div>
      </div>
    );
  }


  return (
    <div className="modern-dashboard">
      
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="welcome-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <FlowShieldLogo size={40} />
              <h1>FlowShield Security Center</h1>
            </div>
            <p className="status-line">
              AI-Powered intelligent authentication and fraud detection ecosystem
            </p>
          </div>
          <div className="header-actions">
            <div className="user-info">
              <div className="avatar">{userProfile?.email?.[0]?.toUpperCase() || 'U'}</div>
              <span>{userProfile?.email || 'User'}</span>
            </div>
            <button onClick={handleLogout} className="logout-btn" disabled={logoutLoading}>
              {logoutLoading ? (
                <span>Logging you out...</span>
              ) : (
                <>
                  <span className="icon-white"><FiSettings /></span>
                  <span>Log Out</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* User Security Dashboard */}
      <div className="metrics-grid">
        <MetricCard
          icon={<FiSettings />}
          title="Security Score"
          value="98.5"
          change={{ text: "Excellent protection level", type: "positive" }}
          highlight={true}
        />
        <MetricCard
          icon={<FiUnlock />}
          title="Login Sessions"
          value={systemStats.totalRequests.toLocaleString()}
          change={{ text: `${Math.floor(Math.random() * 5 + 1)} successful today`, type: "positive" }}
        />
        <MetricCard
          icon={<FiLock />}
          title="MFA Status"
          value="Active"
          change={{ text: "Two-factor enabled", type: "positive" }}
        />
        <MetricCard
          icon={<FiAlertTriangle />}
          title="Threat Detection"
          value="0 Alerts"
          change={{ text: "No threats detected", type: "positive" }}
        />
      </div>

      {/* Account Security Overview */}
      <div className="monitoring-section">
        <div className="section-header">
          <h2>Account Security Overview</h2>
          <div className="refresh-indicator">
            <div className="pulse"></div>
            Protected Account
          </div>
        </div>

        <div className="health-grid">
          <HealthCard
            icon={<FiLock />}
            title="Password Strength"
            value={85}
            status="healthy"
            chartData={chartData.map(() => ({ cpu: 85 }))}
            chartColor="#4facfe"
            chartLabel="Strong"
            getHealthStatus={getHealthStatus}
          />
          <HealthCard
            icon={<FiMail />}
            title="Device Trust Score"
            value={92}
            status="healthy"
            chartData={chartData.map(() => ({ cpu: 92 }))}
            chartColor="#00f2fe"
            chartLabel="Trusted"
            getHealthStatus={getHealthStatus}
          />
          <HealthCard
            icon={<FiGlobe />}
            title="Location Security"
            value={98}
            status="healthy"
            chartData={chartData.map(() => ({ cpu: 98 }))}
            chartColor="#00ff88"
            chartLabel="Secure"
            getHealthStatus={getHealthStatus}
          />
        </div>

        {/* Security Activity Timeline */}
        <div className="network-section">
          <div className="section-header">
            <h3>Recent Security Activity</h3>
            <div className="topology-stats">
              <span className="stat-item">
                <span className="stat-dot active"></span>
                3 Recent Logins
              </span>
              <span className="stat-item">
                <span className="stat-dot active"></span>
                0 Security Alerts
              </span>
            </div>
          </div>
          <div className="activity-timeline">
            <div className="activity-item">
              <div className="activity-icon"><FiUnlock /></div>
              <div className="activity-content">
                <div className="activity-title">Successful Login</div>
                <div className="activity-details">Chrome on MacOS • 2 hours ago</div>
              </div>
            </div>
            <div className="activity-item">
              <div className="activity-icon"><FiMail /></div>
              <div className="activity-content">
                <div className="activity-title">MFA Verification</div>
                <div className="activity-details">SMS code verified • 2 hours ago</div>
              </div>
            </div>
            <div className="activity-item">
              <div className="activity-icon"><FiCheckCircle /></div>
              <div className="activity-content">
                <div className="activity-title">Security Scan Complete</div>
                <div className="activity-details">No threats detected • 1 day ago</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Account Actions */}
      <div className="user-actions">
        <div className="section-header">
          <h3>Account Management</h3>
          <p>Manage your security settings and preferences</p>
        </div>

        <div className="actions-grid">
          <div className="action-card">
            <div className="action-icon"><FiLock /></div>
            <div className="action-content">
              <h4>Change Password</h4>
              <p>Update your account password for enhanced security</p>
              <button className="action-btn outline">Update Password</button>
            </div>
          </div>

          <div className="action-card">
            <div className="action-icon"><FiMail /></div>
            <div className="action-content">
              <h4>MFA Settings</h4>
              <p>Configure two-factor authentication methods</p>
              <button className="action-btn outline">Manage MFA</button>
            </div>
          </div>

          <div className="action-card">
            <div className="action-icon"><FiFileText /></div>
            <div className="action-content">
              <h4>Security Reports</h4>
              <p>View detailed security reports and login history</p>
              <button className="action-btn outline">View Reports</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;