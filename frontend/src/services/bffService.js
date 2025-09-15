/**
 * Backend for Frontend (BFF) Service
 * Token-mediating backend service for enhanced security
 */

const BFF_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

/**
 * Get CSRF token from cookies
 * @returns {string|null} CSRF token
 */
function getCSRFToken() {
  const cookies = document.cookie.split(';');
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'csrf_token') {
      return value;
    }
  }
  return null;
}

/**
 * Make authenticated request through BFF proxy
 * @param {string} path - API path to proxy
 * @param {Object} options - Request options
 * @returns {Promise<Response>} Fetch response
 */
async function bffRequest(path, options = {}) {
  const csrfToken = getCSRFToken();
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };
  
  // Add CSRF token if available
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  
  const response = await fetch(`${BFF_BASE_URL}${path}`, {
    credentials: 'include', // Include HTTP-only cookies
    headers,
    ...options
  });
  
  return response;
}

/**
 * BFF Authentication Service
 * Handles authentication through token-mediating backend
 */
export class BFFAuthService {
  /**
   * Login through BFF with enhanced security
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Promise<Object>} Login response
   */
  async login(email, password) {
    try {
      const response = await bffRequest('/bff/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error_description || 'Login failed');
      }
      
      // BFF returns authorization URL for PKCE flow
      if (data.authorization_url) {
        // Redirect to authorization server
        window.location.href = data.authorization_url;
        return { redirecting: true };
      }
      
      return data;
    } catch (error) {
      console.error('BFF login error:', error);
      throw error;
    }
  }
  
  /**
   * Handle BFF callback after OAuth authorization
   * @param {string} code - Authorization code
   * @param {string} state - State parameter
   * @returns {Promise<Object>} Authentication result
   */
  async handleCallback(code, state) {
    try {
      const response = await bffRequest('/bff/callback', {
        method: 'POST',
        body: JSON.stringify({ code, state })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error_description || 'Authentication failed');
      }
      
      // BFF establishes session and returns user data
      return data;
    } catch (error) {
      console.error('BFF callback error:', error);
      throw error;
    }
  }
  
  /**
   * Get current user through BFF
   * @returns {Promise<Object>} User data
   */
  async getCurrentUser() {
    try {
      const response = await bffRequest('/bff/me');
      
      if (!response.ok) {
        if (response.status === 401) {
          return null; // Not authenticated
        }
        throw new Error('Failed to get user information');
      }
      
      return await response.json();
    } catch (error) {
      console.error('BFF get user error:', error);
      throw error;
    }
  }
  
  /**
   * Logout through BFF
   * @returns {Promise<Object>} Logout response
   */
  async logout() {
    try {
      const response = await bffRequest('/bff/logout', {
        method: 'POST'
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error_description || 'Logout failed');
      }
      
      return data;
    } catch (error) {
      console.error('BFF logout error:', error);
      throw error;
    }
  }
  
  /**
   * Check BFF session status
   * @returns {Promise<Object>} Session status
   */
  async getSessionStatus() {
    try {
      const response = await bffRequest('/bff/session-status');
      
      if (!response.ok) {
        return { authenticated: false };
      }
      
      return await response.json();
    } catch (error) {
      console.error('BFF session status error:', error);
      return { authenticated: false };
    }
  }
  
  /**
   * Make API request through BFF proxy
   * @param {string} path - API path
   * @param {Object} options - Request options
   * @returns {Promise<Object>} API response
   */
  async apiRequest(path, options = {}) {
    try {
      const method = options.method || 'GET';
      
      const response = await bffRequest('/bff/api-proxy', {
        method: 'POST',
        body: JSON.stringify({
          target_path: path,
          method: method
        }),
        ...options
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error_description || `API request failed: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('BFF API request error:', error);
      throw error;
    }
  }
}

/**
 * Secure Fetch with BFF
 * Drop-in replacement for fetch that routes through BFF for security
 */
export class SecureFetch {
  constructor(bffService = new BFFAuthService()) {
    this.bff = bffService;
  }
  
  /**
   * Secure fetch through BFF proxy
   * @param {string} url - Full URL or path
   * @param {Object} options - Fetch options
   * @returns {Promise<Response>} Fetch response
   */
  async fetch(url, options = {}) {
    try {
      // Convert full URLs to paths for BFF proxy
      const path = url.startsWith('http') ? new URL(url).pathname + new URL(url).search : url;
      
      return await this.bff.apiRequest(path, options);
    } catch (error) {
      console.error('Secure fetch error:', error);
      throw error;
    }
  }
  
  /**
   * Secure GET request
   * @param {string} url - URL or path
   * @returns {Promise<Response>} Response
   */
  async get(url) {
    return this.fetch(url, { method: 'GET' });
  }
  
  /**
   * Secure POST request
   * @param {string} url - URL or path
   * @param {Object} data - Request body data
   * @returns {Promise<Response>} Response
   */
  async post(url, data) {
    return this.fetch(url, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  
  /**
   * Secure PUT request
   * @param {string} url - URL or path
   * @param {Object} data - Request body data
   * @returns {Promise<Response>} Response
   */
  async put(url, data) {
    return this.fetch(url, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  
  /**
   * Secure DELETE request
   * @param {string} url - URL or path
   * @returns {Promise<Response>} Response
   */
  async delete(url) {
    return this.fetch(url, { method: 'DELETE' });
  }
}

/**
 * Default BFF service instance
 */
export const bffAuth = new BFFAuthService();

/**
 * Default secure fetch instance
 */
export const secureFetch = new SecureFetch(bffAuth);

/**
 * Security utilities for frontend
 */
export const SecurityUtils = {
  /**
   * Check if current environment supports secure features
   * @returns {boolean} True if secure features are available
   */
  isSecureEnvironment() {
    return window.location.protocol === 'https:' || 
           window.location.hostname === 'localhost';
  },
  
  /**
   * Check if Web Crypto API is available for PKCE
   * @returns {boolean} True if Web Crypto API is available
   */
  isWebCryptoAvailable() {
    return !!(window.crypto && window.crypto.subtle);
  },
  
  /**
   * Validate CSP nonce in current document
   * @returns {string|null} Current CSP nonce or null
   */
  getCurrentCSPNonce() {
    const metaTags = document.getElementsByTagName('meta');
    for (let meta of metaTags) {
      if (meta.name === 'csp-nonce') {
        return meta.content;
      }
    }
    return null;
  },
  
  /**
   * Check if BFF session is active
   * @returns {boolean} True if BFF session cookie exists
   */
  hasBFFSession() {
    return document.cookie.includes('bff_session=');
  },
  
  /**
   * Clear all auth-related storage
   */
  clearAuthStorage() {
    // Clear localStorage
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && (key.startsWith('auth_') || key.startsWith('pkce_') || key.startsWith('token_'))) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
    
    // Clear sessionStorage
    const sessionKeysToRemove = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && (key.startsWith('auth_') || key.startsWith('pkce_') || key.startsWith('token_'))) {
        sessionKeysToRemove.push(key);
      }
    }
    sessionKeysToRemove.forEach(key => sessionStorage.removeItem(key));
  },
  
  /**
   * Report security violation (CSP, etc.)
   * @param {string} violation - Violation type
   * @param {Object} details - Violation details
   */
  reportSecurityViolation(violation, details = {}) {
    console.warn('Security violation detected:', violation, details);
    
    // In production, report to security monitoring service
    if (process.env.NODE_ENV === 'production') {
      fetch('/api/security-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          violation,
          details,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          url: window.location.href
        })
      }).catch(err => console.error('Failed to report security violation:', err));
    }
  }
};

/**
 * Enhanced Security Context Hook Helper
 * Provides security state and utilities for React components
 */
export function createSecurityContext() {
  return {
    bffAuth,
    secureFetch,
    SecurityUtils,
    
    // Security status
    isSecure: SecurityUtils.isSecureEnvironment(),
    hasWebCrypto: SecurityUtils.isWebCryptoAvailable(),
    hasBFFSession: SecurityUtils.hasBFFSession(),
    
    // Security actions
    clearStorage: SecurityUtils.clearAuthStorage,
    reportViolation: SecurityUtils.reportSecurityViolation
  };
}