import { vi } from 'vitest';

// Mock implementation of auth service for testing
export const authService = {
  login: vi.fn(),
  register: vi.fn(),
  logout: vi.fn(),
  getCurrentUser: vi.fn(),
  getAccessToken: vi.fn(),
  refreshToken: vi.fn(),
  requestPasswordReset: vi.fn(),
  resetPassword: vi.fn(),
  verifyEmail: vi.fn(),
};