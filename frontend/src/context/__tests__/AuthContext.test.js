import { render, screen, waitFor, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../AuthContext';
import { authService } from '../../services/auth';
import toast from 'react-hot-toast';

// Mock dependencies
jest.mock('../../services/auth');
jest.mock('react-hot-toast');

const mockAuthService = authService;
const mockToast = toast;

// Test component to use the hook
const TestComponent = () => {
  const {
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
    checkAuthStatus,
  } = useAuth();

  return (
    <div>
      <div data-testid="user">{user ? JSON.stringify(user) : 'null'}</div>
      <div data-testid="loading">{loading.toString()}</div>
      <div data-testid="backendOnline">{backendOnline.toString()}</div>
      <button onClick={() => login('test@example.com', 'password')}>
        Login
      </button>
      <button onClick={() => register({ email: 'test@example.com' })}>
        Register
      </button>
      <button onClick={logout}>Logout</button>
      <button onClick={() => requestPasswordReset('test@example.com')}>
        Reset Password
      </button>
      <button onClick={() => resetPassword('token', 'newPassword')}>
        Reset Password Confirm
      </button>
      <button onClick={() => verifyEmail('token')}>Verify Email</button>
      <button onClick={refreshToken}>Refresh Token</button>
      <button onClick={checkAuthStatus}>Check Auth</button>
    </div>
  );
};

const renderWithProvider = () => {
  return render(
    <AuthProvider>
      <TestComponent />
    </AuthProvider>
  );
};

describe('AuthContext', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAuthService.getAccessToken = jest.fn();
    mockAuthService.getCurrentUser = jest.fn();
    mockAuthService.login = jest.fn();
    mockAuthService.register = jest.fn();
    mockAuthService.logout = jest.fn();
    mockAuthService.requestPasswordReset = jest.fn();
    mockAuthService.resetPassword = jest.fn();
    mockAuthService.verifyEmail = jest.fn();
    mockAuthService.refreshToken = jest.fn();
    mockToast.success = jest.fn();
    mockToast.error = jest.fn();
  });

  test('throws error when useAuth is used outside AuthProvider', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    
    expect(() => {
      render(<TestComponent />);
    }).toThrow('useAuth must be used within an AuthProvider');
    
    consoleSpy.mockRestore();
  });

  test('initializes with loading state and checks auth status', async () => {
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    expect(screen.getByTestId('loading')).toHaveTextContent('true');
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    expect(mockAuthService.getAccessToken).toHaveBeenCalled();
  });

  test('restores user from valid token on initialization', async () => {
    const mockUser = { id: 1, email: 'test@example.com' };
    mockAuthService.getAccessToken.mockReturnValue('valid-token');
    mockAuthService.getCurrentUser.mockResolvedValue(mockUser);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent(JSON.stringify(mockUser));
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
  });

  test('handles network error during auth check gracefully', async () => {
    mockAuthService.getAccessToken.mockReturnValue('valid-token');
    mockAuthService.getCurrentUser.mockRejectedValue(new Error('Network Error'));
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('backendOnline')).toHaveTextContent('false');
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
  });

  test('logs out user for invalid token', async () => {
    mockAuthService.getAccessToken.mockReturnValue('invalid-token');
    mockAuthService.getCurrentUser.mockRejectedValue(new Error('No valid access token'));
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(mockAuthService.logout).toHaveBeenCalled();
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
  });

  test('login function works correctly', async () => {
    const mockUser = { id: 1, email: 'test@example.com' };
    mockAuthService.login.mockResolvedValue({ user: mockUser });
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Login').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.login).toHaveBeenCalledWith('test@example.com', 'password');
      expect(mockToast.success).toHaveBeenCalledWith('Login successful!');
      expect(screen.getByTestId('user')).toHaveTextContent(JSON.stringify(mockUser));
    });
  });

  test('login handles errors correctly', async () => {
    const error = { response: { data: { detail: 'Invalid credentials' } } };
    mockAuthService.login.mockRejectedValue(error);
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Login').click();
    });
    
    await waitFor(() => {
      expect(mockToast.error).toHaveBeenCalledWith('Invalid credentials');
    });
  });

  test('register function works correctly', async () => {
    const mockResponse = { user: { id: 1, email: 'test@example.com' } };
    mockAuthService.register.mockResolvedValue(mockResponse);
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Register').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.register).toHaveBeenCalledWith({ email: 'test@example.com' });
      expect(mockToast.success).toHaveBeenCalledWith('Registration successful! Please check your email to verify your account.');
    });
  });

  test('logout function works correctly', async () => {
    const mockUser = { id: 1, email: 'test@example.com' };
    mockAuthService.getAccessToken.mockReturnValue('valid-token');
    mockAuthService.getCurrentUser.mockResolvedValue(mockUser);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent(JSON.stringify(mockUser));
    });
    
    act(() => {
      screen.getByText('Logout').click();
    });
    
    expect(mockAuthService.logout).toHaveBeenCalled();
    expect(screen.getByTestId('user')).toHaveTextContent('null');
    expect(mockToast.success).toHaveBeenCalledWith('Logged out successfully');
  });

  test('requestPasswordReset function works correctly', async () => {
    mockAuthService.requestPasswordReset.mockResolvedValue();
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Reset Password').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.requestPasswordReset).toHaveBeenCalledWith('test@example.com');
      expect(mockToast.success).toHaveBeenCalledWith('Password reset email sent! Please check your inbox.');
    });
  });

  test('resetPassword function works correctly', async () => {
    mockAuthService.resetPassword.mockResolvedValue();
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Reset Password Confirm').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.resetPassword).toHaveBeenCalledWith('token', 'newPassword');
      expect(mockToast.success).toHaveBeenCalledWith('Password reset successful! You can now login with your new password.');
    });
  });

  test('verifyEmail function works correctly', async () => {
    mockAuthService.verifyEmail.mockResolvedValue();
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Verify Email').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.verifyEmail).toHaveBeenCalledWith('token');
      expect(mockToast.success).toHaveBeenCalledWith('Email verified successfully!');
    });
  });

  test('refreshToken function works correctly', async () => {
    const mockResponse = { token: 'new-token' };
    mockAuthService.refreshToken.mockResolvedValue(mockResponse);
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Refresh Token').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.refreshToken).toHaveBeenCalled();
    });
  });

  test('refreshToken handles errors by logging out', async () => {
    mockAuthService.refreshToken.mockRejectedValue(new Error('Token refresh failed'));
    mockAuthService.getAccessToken.mockReturnValue(null);
    
    renderWithProvider();
    
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false');
    });
    
    await act(async () => {
      screen.getByText('Refresh Token').click();
    });
    
    await waitFor(() => {
      expect(mockAuthService.logout).toHaveBeenCalled();
      expect(screen.getByTestId('user')).toHaveTextContent('null');
    });
  });
});