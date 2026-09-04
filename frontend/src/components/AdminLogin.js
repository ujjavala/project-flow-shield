import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Check, Eye as FiEye, EyeOff as FiEyeOff, Shield as FiShield, Lock as FiLock, Settings as FiSettings, Zap as FiZap } from 'lucide-react';
import FlowShieldLogo from './common/FlowShieldLogo';
import { useAuth } from '../context/AuthContext';
import './AdminLogin.css';

const AdminLogin = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    remember_me: false
  });
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [featuresExpanded, setFeaturesExpanded] = useState(false);
  const navigate = useNavigate();
  const { loginAdmin } = useAuth();

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const data = await loginAdmin(formData.email, formData.password, formData.remember_me);
      toast.success(`Welcome, Admin! (${data.user.role})`);
      navigate('/admin');
    } catch (error) {
      console.error('Admin login error:', error);
      toast.error(
        error.status
          ? error.message || 'Admin login failed'
          : 'Network error. Please check if the backend is running.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="admin-login-container">
      <div className="admin-login-background">
        <div className="admin-pattern"></div>
      </div>

      <div className="admin-login-card">
        <div className="admin-login-header">
          <FlowShieldLogo size={48} />
          <h1>Admin Portal</h1>
          <p>Secure Administrative Access</p>
          <div className="admin-badge">
            <span className="badge-icon"><FiShield /></span>
            <span>Administrative Login</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="admin-login-form">
          <div className="form-group">
            <label htmlFor="email">Admin Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="admin@example.com"
              required
              className="admin-input"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Admin Password</label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? "text" : "password"}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                placeholder="Enter your admin password"
                required
                className="admin-input"
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <FiEyeOff /> : <FiEye />}
              </button>
            </div>
          </div>

          <div className="form-group checkbox-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="remember_me"
                checked={formData.remember_me}
                onChange={handleInputChange}
              />
              <span className="checkbox-custom" aria-hidden="true">
                <Check />
              </span>
              <span className="checkbox-text">Remember this admin session</span>
            </label>
          </div>

          <button
            type="submit"
            className="admin-login-btn"
            disabled={isLoading}
          >
            {isLoading ? (
              <span>Logging you in...</span>
            ) : (
              <>
                <span className="btn-icon"><FiLock /></span>
                <span>Admin Login</span>
              </>
            )}
          </button>

          <div className="admin-login-security">
            <div className="security-notice">
              <span className="security-icon"><FiShield /></span>
              <div className="security-text">
                <strong>Security Notice:</strong>
                <p>This is a restricted admin portal. All access is logged and monitored.</p>
              </div>
            </div>
          </div>

          <div className="admin-login-links">
            <Link to="/login" className="regular-login-link">
              <span className="link-icon"><FiSettings /></span>
              Regular User Login
            </Link>
            <Link to="/admin/forgot-password" className="forgot-password-link">
              <span className="link-icon"><FiSettings /></span>
              Admin Password Reset
            </Link>
          </div>

        </form>
        <div className="admin-login-footer">
          <p>
            <span className="footer-icon"><FiZap /></span>
            Powered by FlowShield Security Platform
          </p>
        </div>
      </div>
    </div>
  );
};

export default AdminLogin;