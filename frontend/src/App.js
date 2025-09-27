import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './context/AuthContext';

// Components
import LandingPage from './components/LandingPage';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import AdminDashboard from './components/AdminDashboard';
import AdminLogin from './components/AdminLogin';
import ResetPassword from './components/ResetPassword';
import VerifyEmail from './components/VerifyEmail';
import About from './components/About';

// Protected Route Components
import {
  UserProtectedRoute,
  AdminProtectedRoute,
  PublicRoute,
  AdminPublicRoute
} from './components/ProtectedRoutes';

// Styles
import './styles/App.css';

function AppContent() {
  const { loading, backendOnline } = useAuth();

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  if (!backendOnline) {
    return (
      <div className="backend-offline">
        <h2>Backend is currently offline</h2>
        <p>Some features may not work. Please try again later.</p>
      </div>
    );
  }

  return (
    <div className="App">
      <main className="main-content">
        <Routes>
          {/* Public Routes */}
          <Route
            path="/login"
            element={
              <PublicRoute>
                <Login />
              </PublicRoute>
            }
          />
          <Route
            path="/register"
            element={
              <PublicRoute>
                <Register />
              </PublicRoute>
            }
          />
          <Route
            path="/reset-password"
            element={
              <PublicRoute>
                <ResetPassword />
              </PublicRoute>
            }
          />
          <Route
            path="/verify-email"
            element={
              <VerifyEmail />
            }
          />

          {/* Admin Public Routes */}
          <Route
            path="/admin/login"
            element={
              <AdminPublicRoute>
                <AdminLogin />
              </AdminPublicRoute>
            }
          />

          {/* User Protected Routes */}
          <Route
            path="/dashboard"
            element={
              <UserProtectedRoute>
                <Dashboard />
              </UserProtectedRoute>
            }
          />

          {/* Admin Protected Routes */}
          <Route
            path="/admin"
            element={
              <AdminProtectedRoute>
                <AdminDashboard />
              </AdminProtectedRoute>
            }
          />
          <Route
            path="/admin/dashboard"
            element={
              <AdminProtectedRoute>
                <AdminDashboard />
              </AdminProtectedRoute>
            }
          />

          {/* Public Info Routes */}
          <Route path="/about" element={<About />} />

          {/* Default Route - Landing Page */}
          <Route path="/" element={<LandingPage />} />
        </Routes>
      </main>
      <Toaster position="top-right" />
    </div>
  );
}

function App() {
  return (
    <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}

export default App;
