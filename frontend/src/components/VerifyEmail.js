import React, { useState, useEffect } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [loading, setLoading] = useState(true);
  const [verificationStatus, setVerificationStatus] = useState(null);
  const { verifyEmail } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (token) {
      handleVerification();
    } else {
      setLoading(false);
      setVerificationStatus('no-token');
    }
  }, [token]);

  const handleVerification = async () => {
    setLoading(true);
    try {
      await verifyEmail(token);
      setVerificationStatus('success');
      // Redirect to login after 3 seconds
      setTimeout(() => {
        navigate('/login');
      }, 3000);
    } catch (error) {
      setVerificationStatus('error');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <h2>Verifying Email...</h2>
            <div className="loading-spinner">
              <div className="spinner"></div>
            </div>
            <p>Please wait while we verify your email address.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        {verificationStatus === 'success' && (
          <div className="auth-header">
            <div className="success-icon">✅</div>
            <h2>Email Verified Successfully!</h2>
            <p>Your email address has been verified. You can now sign in to your account.</p>
            <p className="redirect-message">Redirecting to login page in 3 seconds...</p>
          </div>
        )}

        {verificationStatus === 'error' && (
          <div className="auth-header">
            <div className="error-icon">❌</div>
            <h2>Email Verification Failed</h2>
            <p>The verification link is invalid or has expired. Please request a new verification email.</p>
          </div>
        )}

        {verificationStatus === 'no-token' && (
          <div className="auth-header">
            <div className="warning-icon">⚠️</div>
            <h2>Invalid Verification Link</h2>
            <p>The verification link appears to be invalid. Please check your email and try again.</p>
          </div>
        )}

        <div className="auth-footer">
          <p>
            <Link to="/login" className="auth-link">
              Go to Sign In
            </Link>
          </p>
          {(verificationStatus === 'error' || verificationStatus === 'no-token') && (
            <p>
              Need help? <Link to="/register" className="auth-link">Create a new account</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail;