import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// Regular user protected route
export const UserProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  // Must be authenticated
  if (!user) {
    return <Navigate to="/login" />;
  }

  // Check if user has admin token (they should use admin routes)
  const adminToken = localStorage.getItem('admin_token');
  const adminRole = localStorage.getItem('admin_role');

  if (adminToken && adminRole) {
    return <Navigate to="/admin" />;
  }

  return children;
};

// Admin protected route
export const AdminProtectedRoute = ({ children }) => {
  const { loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  // Check for admin authentication
  const adminToken = localStorage.getItem('admin_token');
  const adminRole = localStorage.getItem('admin_role');

  if (!adminToken || !adminRole) {
    return <Navigate to="/admin/login" />;
  }

  // Verify admin role
  const validAdminRoles = ['admin', 'moderator', 'superuser'];
  if (!validAdminRoles.includes(adminRole)) {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_refresh_token');
    localStorage.removeItem('admin_role');
    localStorage.removeItem('admin_permissions');
    return <Navigate to="/admin/login" />;
  }

  return children;
};

// Public route that redirects based on authentication
export const PublicRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  // Check for admin authentication first
  const adminToken = localStorage.getItem('admin_token');
  const adminRole = localStorage.getItem('admin_role');

  if (adminToken && adminRole) {
    return <Navigate to="/admin" />;
  }

  // Then check for regular user authentication
  if (user) {
    return <Navigate to="/dashboard" />;
  }

  return children;
};

// Admin public route (for admin login page)
export const AdminPublicRoute = ({ children }) => {
  const { loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  // Check if already authenticated as admin
  const adminToken = localStorage.getItem('admin_token');
  const adminRole = localStorage.getItem('admin_role');

  if (adminToken && adminRole) {
    return <Navigate to="/admin" />;
  }

  return children;
};