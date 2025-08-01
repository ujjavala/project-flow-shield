import React, { createContext, useContext, useState, useEffect } from 'react';
import { authService } from '../services/auth';
import toast from 'react-hot-toast';

export const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);
  const [backendOnline, setBackendOnline] = useState(true);

  const checkAuthStatus = async () => {
    try {
      const token = authService.getAccessToken();
      if (token) {
        const userData = await authService.getCurrentUser();
        setUser(userData);
      }
    } catch (error) {
      console.error('Auth check failed:', error.message || error);
      // Graceful handling: Do not logout unless token is bad
      if (error.message.includes("Network Error") || !error.response) {
        setBackendOnline(false);
        console.warn("Backend is offline.");
      }
      if (error.message === 'No valid access token') {
        authService.logout(); // expected
      } else {
        console.warn('Backend might be down. Continuing in offline mode.');
      }
    } finally {
      setLoading(false);
    }
  };


  const login = async (email, password) => {
    try {
      const response = await authService.login(email, password);
      setUser(response.user);
      toast.success('Login successful!');
      return response;
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
      throw error;
    }
  };

  const register = async (userData) => {
    try {
      const response = await authService.register(userData);
      toast.success('Registration successful! Please check your email to verify your account.');
      return response;
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
      throw error;
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    toast.success('Logged out successfully');
  };

  const requestPasswordReset = async (email) => {
    try {
      await authService.requestPasswordReset(email);
      toast.success('Password reset email sent! Please check your inbox.');
    } catch (error) {
      toast.error('Failed to send password reset email');
      throw error;
    }
  };

  const resetPassword = async (token, newPassword) => {
    try {
      await authService.resetPassword(token, newPassword);
      toast.success('Password reset successful! You can now login with your new password.');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Password reset failed');
      throw error;
    }
  };

  const verifyEmail = async (token) => {
    try {
      await authService.verifyEmail(token);
      toast.success('Email verified successfully!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Email verification failed');
      throw error;
    }
  };

  const refreshToken = async () => {
    try {
      const response = await authService.refreshToken();
      return response;
    } catch (error) {
      logout();
      throw error;
    }
  };

  const value = {
    user,
    loading,
    backendOnline,
    login,
    register,
    logout,
    requestPasswordReset,
    resetPassword,
    verifyEmail,
    refreshToken,
    checkAuthStatus
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};