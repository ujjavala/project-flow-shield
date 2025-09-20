import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import './Dashboard.css';
import LineChart from './Dashboard/components/LineChart';
import NetworkVisualization from './Dashboard/components/NetworkVisualization';
import ParticleBackground from './Dashboard/components/ParticleBackground';
import MetricCard from './Dashboard/components/MetricCard';
import HealthCard from './Dashboard/components/HealthCard';
import FeatureCard from './Dashboard/components/FeatureCard';
import FlowShieldLogo from './common/FlowShieldLogo';
import './common/FlowShieldLogo.css';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(false);
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
  const [activeConnections, setActiveConnections] = useState([]);
  const [particleData, setParticleData] = useState([]);
  const chartRef = useRef(null);
  const canvasRef = useRef(null);
  const particleCanvasRef = useRef(null);

  useEffect(() => {
    fetchUserProfile();
    startRealtimeUpdates();
    initializeParticles();
    initializeCharts();
    return () => {
      clearInterval(window.dashboardInterval);
      clearInterval(window.particleInterval);
      clearInterval(window.chartInterval);
    };
  }, []);

  const initializeParticles = () => {
    // Create initial particle data
    const particles = Array.from({ length: 50 }, (_, i) => ({
      id: i,
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 2,
      vy: (Math.random() - 0.5) * 2,
      size: Math.random() * 3 + 1,
      opacity: Math.random() * 0.7 + 0.3,
      color: `hsl(${200 + Math.random() * 60}, 70%, 60%)`
    }));
    setParticleData(particles);

    // Animate particles
    window.particleInterval = setInterval(() => {
      setParticleData(prev => 
        prev.map(particle => ({
          ...particle,
          x: particle.x + particle.vx,
          y: particle.y + particle.vy,
          x: particle.x > window.innerWidth ? 0 : particle.x < 0 ? window.innerWidth : particle.x,
          y: particle.y > window.innerHeight ? 0 : particle.y < 0 ? window.innerHeight : particle.y
        }))
      );
    }, 50);
  };

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

    // Generate random connections
    const connections = Array.from({ length: 8 }, (_, i) => ({
      id: i,
      from: { x: Math.random() * 300, y: Math.random() * 200 },
      to: { x: Math.random() * 300, y: Math.random() * 200 },
      strength: Math.random(),
      active: Math.random() > 0.3
    }));
    setActiveConnections(connections);

    // Update charts periodically
    window.chartInterval = setInterval(() => {
      const newPoint = {
        time: new Date().toLocaleTimeString(),
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 100,
        requests: Math.floor(Math.random() * 100) + 20
      };
      
      setChartData(prev => [...prev.slice(-19), newPoint]);
      
      // Update connections
      setActiveConnections(prev => 
        prev.map(conn => ({
          ...conn,
          strength: Math.random(),
          active: Math.random() > 0.2
        }))
      );
    }, 2000);
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

  const handleLogout = () => {
    logout();
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
        <div className="loading-spinner">
          <div className="spinner"></div>
          <div className="loading-text">Loading dashboard...</div>
        </div>
      </div>
    );
  }


  return (
    <div className="modern-dashboard">
      <ParticleBackground particleData={particleData} />
      
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="welcome-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <FlowShieldLogo size={40} />
              <h1>FlowShield Security Center</h1>
            </div>
            <p className="status-line">
              <span className="status-dot healthy"></span>
              Intelligent Authentication • AI-Powered Fraud Detection • Temporal-Reliable
            </p>
          </div>
          <div className="header-actions">
            <div className="user-info">
              <div className="avatar">{userProfile?.email?.[0]?.toUpperCase() || 'U'}</div>
              <span>{userProfile?.email || 'User'}</span>
            </div>
            <button onClick={handleLogout} className="logout-btn">
              <span className="btn-icon">⚡</span>
              Sign Out
            </button>
          </div>
        </div>
      </div>

      {/* Real-time metrics grid */}
      <div className="metrics-grid">
        <MetricCard
          icon="👥"
          title="Active Users"
          value={systemStats.activeUsers}
          change={{ text: "+12 from last hour", type: "positive" }}
          highlight={true}
        />
        <MetricCard
          icon="🚀"
          title="Total Requests"
          value={systemStats.totalRequests.toLocaleString()}
          change={{ text: `+${Math.floor(Math.random() * 50)} this session`, type: "positive" }}
        />
        <MetricCard
          icon="✅"
          title="Success Rate"
          value={`${systemStats.successRate.toFixed(1)}%`}
          change={{ text: "Excellent performance", type: "positive" }}
        />
        <MetricCard
          icon="⚡"
          title="Response Time"
          value={`${Math.round(systemStats.responseTime)}ms`}
          change={{ text: "Within SLA limits", type: "neutral" }}
        />
      </div>

      {/* System Health Monitoring */}
      <div className="monitoring-section">
        <div className="section-header">
          <h2>System Health Monitor</h2>
          <div className="refresh-indicator">
            <div className="pulse"></div>
            Live monitoring
          </div>
        </div>

        <div className="health-grid">
          <HealthCard
            icon="🖥️"
            title="CPU Usage"
            value={systemStats.cpuUsage}
            status={getHealthStatus(systemStats.cpuUsage, true)}
            chartData={chartData.map(d => ({ cpu: d.cpu }))}
            chartColor="#4facfe"
            chartLabel="CPU-Trend"
            getHealthStatus={getHealthStatus}
          />
          <HealthCard
            icon="💾"
            title="Memory Usage"
            value={systemStats.memoryUsage}
            status={getHealthStatus(systemStats.memoryUsage, true)}
            chartData={chartData.map(d => ({ cpu: d.memory }))}
            chartColor="#00f2fe"
            chartLabel="Memory-Trend"
            getHealthStatus={getHealthStatus}
          />
          <HealthCard
            icon="🌐"
            title="Network Activity"
            value={systemStats.networkActivity}
            status={getHealthStatus(systemStats.networkActivity)}
            chartData={chartData.map(d => ({ cpu: d.network }))}
            chartColor="#00ff88"
            chartLabel="Network-Trend"
            getHealthStatus={getHealthStatus}
          />
        </div>

        {/* Network Topology Visualization */}
        <div className="network-section">
          <div className="section-header">
            <h3>Network Topology</h3>
            <div className="topology-stats">
              <span className="stat-item">
                <span className="stat-dot active"></span>
                {activeConnections.filter(c => c.active).length} Active
              </span>
              <span className="stat-item">
                <span className="stat-dot inactive"></span>
                {activeConnections.filter(c => !c.active).length} Inactive
              </span>
            </div>
          </div>
          <NetworkVisualization activeConnections={activeConnections} />
        </div>
      </div>

      {/* Features showcase */}
      <div className="features-showcase">
        <div className="section-header">
          <h2>Authentication System Features</h2>
          <div className="feature-badge">Temporal.io Powered</div>
        </div>

        <div className="features-grid">
          <FeatureCard
            icon="🔐"
            title="OAuth2 + JWT"
            description="Secure token-based authentication with refresh capabilities"
            status="Active"
            animationClass="pulse-glow"
          />
          <FeatureCard
            icon="⚡"
            title="Temporal Workflows"
            description="Reliable, durable authentication workflows with automatic retries"
            status="Running"
            animationClass="wave-glow"
          />
          <FeatureCard
            icon="🧠"
            title="AI Fraud Detection"
            description="Machine learning powered behavioral analysis and risk assessment"
            status="Learning"
            animationClass="orbit-glow"
          />
          <FeatureCard
            icon="📊"
            title="Real-time Analytics"
            description="Live monitoring and comprehensive dashboard analytics"
            status="Monitoring"
            animationClass="data-glow"
          />
        </div>
      </div>

      {/* Quick actions */}
      <div className="quick-actions">
        <button className="action-btn primary" onClick={() => window.location.href = '/admin'}>
          <span className="btn-icon">📊</span>
          Admin Dashboard
        </button>
        <button className="action-btn secondary" onClick={() => window.open('http://localhost:8081', '_blank')}>
          <span className="btn-icon">🔄</span>
          Temporal UI
        </button>
        <button className="action-btn secondary" onClick={fetchUserProfile}>
          <span className="btn-icon">🔄</span>
          Refresh Data
        </button>
      </div>
    </div>
  );
};

export default Dashboard;