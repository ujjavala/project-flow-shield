import React from 'react';
import { FiUsers, FiCheckCircle, FiClock, FiUserPlus } from 'react-icons/fi';

const UsersTab = ({ userStats }) => (
  <div className="users-tab">
    <div className="user-stats-grid">
      <div className="user-stat-card">
        <div className="stat-icon"><FiUsers /></div>
        <div className="stat-value">{userStats?.total_users || 0}</div>
        <div className="stat-label">Total Users</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon"><FiCheckCircle /></div>
        <div className="stat-value">{userStats?.verified_users || 0}</div>
        <div className="stat-label">Verified Users</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon"><FiClock /></div>
        <div className="stat-value">{userStats?.pending_verification || 0}</div>
        <div className="stat-label">Pending Verification</div>
      </div>

      <div className="user-stat-card">
        <div className="stat-icon"><FiUserPlus /></div>
        <div className="stat-value">{userStats?.recent_registrations_24h || 0}</div>
        <div className="stat-label">New Today</div>
      </div>
    </div>
  </div>
);

export default UsersTab;