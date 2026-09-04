import api from './api';
import { bffAuth } from './bffService';

class AuthService {
  // Authentication methods
  async register(userData) {
    const response = await api.post('/user/register', userData);
    return response.data;
  }

  async login(email, password) {
    return bffAuth.login(email, password);
  }

  async logout() {
    await bffAuth.logout();
  }

  async refreshToken() {
    return bffAuth.refreshToken();
  }

  async getCurrentUser() {
    return bffAuth.getCurrentUser();
  }

  async getSessionStatus() {
    return bffAuth.getSessionStatus();
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

  // Check if user is authenticated
  isAuthenticated() {
    return false;
  }
}

export const authService = new AuthService();
export default authService;