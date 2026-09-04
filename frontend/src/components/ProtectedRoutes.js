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

  if (user.is_admin) {
    return <Navigate to="/admin" />;
  }

  return children;
};

// Admin protected route
export const AdminProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  if (!user?.is_admin) {
    return <Navigate to="/admin/login" />;
  }

  return children;
};

// Public route that redirects based on authentication
export const PublicRoute = ({ children }) => {
  const { loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  // Keep sign-in reachable so a person can replace an existing session and
  // deliberately switch between the admin and user demo accounts.
  return children;
};

// Admin public route (for admin login page)
export const AdminPublicRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) return <div className="loading">Loading...</div>;

  if (user?.is_admin) {
    return <Navigate to="/admin" />;
  }

  return children;
};