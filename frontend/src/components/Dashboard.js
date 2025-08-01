import React, { useState, useEffect } from 'react';

import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { user, logout } = useAuth
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    setLoading(true);
    try {
      setUserProfile(user);
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Welcome to Your Dashboard</h1>
        <p>You have successfully authenticated with our OAuth2 system!</p>
      </div>

      <div className="dashboard-content">
        <div className="dashboard-card">
          <div className="card-header">
            <h3>User Profile</h3>
          </div>
          <div className="card-content">
            {userProfile ? (
              <div className="profile-info">
                <div className="profile-item">
                  <label>User ID:</label>
                  <span>{userProfile.id}</span>
                </div>
                <div className="profile-item">
                  <label>Email:</label>
                  <span>{userProfile.email}</span>
                </div>
                <div className="profile-item">
                  <label>Status:</label>
                  <span className="status-badge verified">Verified</span>
                </div>
              </div>
            ) : (
              <p>No profile information available</p>
            )}
          </div>
        </div>

        <div className="dashboard-card">
          <div className="card-header">
            <h3>OAuth2 Information</h3>
          </div>
          <div className="card-content">
            <div className="oauth-info">
              <div className="info-item">
                <h4>Authentication Method</h4>
                <p>OAuth2 Authorization Code Flow with PKCE</p>
              </div>
              <div className="info-item">
                <h4>Token Type</h4>
                <p>JWT Bearer Token</p>
              </div>
              <div className="info-item">
                <h4>Workflow Engine</h4>
                <p>Temporal.io for reliable authentication workflows</p>
              </div>
            </div>
          </div>
        </div>

        <div className="dashboard-card">
          <div className="card-header">
            <h3>System Features</h3>
          </div>
          <div className="card-content">
            <div className="features-grid">
              <div className="feature-item">
                <div className="feature-icon">✉️</div>
                <h4>Email Verification</h4>
                <p>Automated email verification using Temporal workflows</p>
              </div>
              <div className="feature-item">
                <div className="feature-icon">🔒</div>
                <h4>Password Reset</h4>
                <p>Secure password reset with time-limited tokens</p>
              </div>
              <div className="feature-item">
                <div className="feature-icon">🔑</div>
                <h4>JWT Tokens</h4>
                <p>Access and refresh token management</p>
              </div>
              <div className="feature-item">
                <div className="feature-icon">⚡</div>
                <h4>Temporal Workflows</h4>
                <p>Reliable, durable authentication processes</p>
              </div>
            </div>
          </div>
        </div>

        <div className="dashboard-actions">
          <button 
            onClick={handleLogout}
            className="logout-button"
          >
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;