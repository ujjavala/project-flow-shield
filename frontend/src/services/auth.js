import api from './api';
import Cookies from 'js-cookie';
import jwtDecode from 'jwt-decode';

class AuthService {
  constructor() {
    this.API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
    this.ACCESS_TOKEN_KEY = 'access_token';
    this.REFRESH_TOKEN_KEY = 'refresh_token';
  }

  // Token management
  getAccessToken() {
    return Cookies.get(this.ACCESS_TOKEN_KEY);
  }

  getRefreshToken() {
    return Cookies.get(this.REFRESH_TOKEN_KEY);
  }

  setTokens(accessToken, refreshToken) {
    // Decode access token to get expiry
    const decoded = jwtDecode(accessToken);
    const expiryDate = new Date(decoded.exp * 1000);
    
    Cookies.set(this.ACCESS_TOKEN_KEY, accessToken, { 
      expires: expiryDate,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    if (refreshToken) {
      Cookies.set(this.REFRESH_TOKEN_KEY, refreshToken, { 
        expires: 7, // 7 days
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
    }
  }

  clearTokens() {
    Cookies.remove(this.ACCESS_TOKEN_KEY);
    Cookies.remove(this.REFRESH_TOKEN_KEY);
  }

  isTokenExpired(token) {
    if (!token) return true;
    
    try {
      const decoded = jwtDecode(token);
      return decoded.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }

  // Authentication methods
  async register(userData) {
    const response = await api.post('/user/register', userData);
    return response.data;
  }

  async login(email, password) {
    const response = await api.post('/user/login', { email, password });
    const { access_token, refresh_token } = response.data;
    
    this.setTokens(access_token, refresh_token);
    
    // Get user data
    const user = await this.getCurrentUser();
    
    return { user, tokens: response.data };
  }

  async logout() {
    const refreshToken = this.getRefreshToken();
    
    if (refreshToken) {
      try {
        await api.post('/user/logout', { refresh_token: refreshToken });
      } catch (error) {
        console.error('Logout API call failed:', error);
      }
    }
    
    this.clearTokens();
  }

  async refreshToken() {
    const refreshToken = this.getRefreshToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await api.post('/user/refresh', { 
      refresh_token: refreshToken 
    });
    
    const { access_token, refresh_token: newRefreshToken } = response.data;
    this.setTokens(access_token, newRefreshToken || refreshToken);
    
    return response.data;
  }

  async getCurrentUser() {
    const token = this.getAccessToken();
    
    if (!token || this.isTokenExpired(token)) {
      throw new Error('No valid access token');
    }

    // Decode token to get user info
    const decoded = jwtDecode(token);
    return {
      id: decoded.sub,
      email: decoded.email,
      // Add other fields as needed
    };
  }

  async requestPasswordReset(email) {
    const response = await api.post('/user/password-reset/request', { email });
    return response.data;
  }

  async resetPassword(token, newPassword) {
    const response = await api.post('/user/password-reset/confirm', {
      token,
      new_password: newPassword
    });
    return response.data;
  }

  async verifyEmail(token) {
    const response = await api.post('/user/verify-email', { token });
    return response.data;
  }

  // OAuth2 methods
  getOAuthLoginUrl(clientId, redirectUri, scope = 'read profile email', state) {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope,
      state: state || this.generateState()
    });
    
    return `${this.API_URL}/oauth/authorize?${params.toString()}`;
  }

  async exchangeOAuthCode(code, clientId, clientSecret, redirectUri) {
    const response = await api.post('/oauth/token', {
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri
    });
    
    const { access_token, refresh_token } = response.data;
    this.setTokens(access_token, refresh_token);
    
    return response.data;
  }

  generateState() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  // Check if user is authenticated
  isAuthenticated() {
    const token = this.getAccessToken();
    return token && !this.isTokenExpired(token);
  }
}

export const authService = new AuthService();
export default authService;