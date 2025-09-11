import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { AuthContext } from '../../../context/AuthContext';
import Login from '../../Login';
import { authService } from '../../../services/auth';
import toast from 'react-hot-toast';

// Mock dependencies
jest.mock('../../../services/auth');
jest.mock('react-hot-toast');
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => jest.fn(),
}));

const mockAuthService = authService;
const mockToast = toast;

describe('Login Flow Integration Tests', () => {
  const mockAuthContextValue = {
    user: null,
    loading: false,
    backendOnline: true,
    login: jest.fn(),
    register: jest.fn(),
    logout: jest.fn(),
    requestPasswordReset: jest.fn(),
    resetPassword: jest.fn(),
    verifyEmail: jest.fn(),
    refreshToken: jest.fn(),
    checkAuthStatus: jest.fn(),
  };

  const renderLoginWithContext = (contextValue = mockAuthContextValue) => {
    return render(
      <BrowserRouter>
        <AuthContext.Provider value={contextValue}>
          <Login />
        </AuthContext.Provider>
      </BrowserRouter>
    );
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockToast.success = jest.fn();
    mockToast.error = jest.fn();
  });

  test('complete successful login flow', async () => {
    const user = userEvent.setup();
    const mockUser = { id: 1, email: 'test@example.com', name: 'Test User' };
    
    // Mock successful login response
    const mockLoginResponse = {
      user: mockUser,
      access_token: 'access-token',
      refresh_token: 'refresh-token',
    };
    
    mockAuthContextValue.login.mockResolvedValue(mockLoginResponse);
    
    renderLoginWithContext();

    // Verify initial render
    expect(screen.getByText('Sign In')).toBeInTheDocument();
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();

    // Fill in login form
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'password123');

    // Submit form
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    // Verify loading state
    expect(screen.getByText('Signing In...')).toBeInTheDocument();

    // Wait for login completion
    await waitFor(() => {
      expect(mockAuthContextValue.login).toHaveBeenCalledWith('test@example.com', 'password123');
    });
  });

  test('login flow with validation errors', async () => {
    const user = userEvent.setup();
    
    renderLoginWithContext();

    // Try to submit without filling fields
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    // Verify validation errors
    await waitFor(() => {
      expect(screen.getByText('Email is required')).toBeInTheDocument();
      expect(screen.getByText('Password is required')).toBeInTheDocument();
    });

    // Fill in invalid email
    await user.type(screen.getByLabelText('Email Address'), 'invalid-email');
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    await waitFor(() => {
      expect(screen.getByText('Invalid email address')).toBeInTheDocument();
    });

    // Fill in short password
    await user.clear(screen.getByLabelText('Email Address'));
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), '123');
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    await waitFor(() => {
      expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument();
    });
  });

  test('login flow with network error', async () => {
    const user = userEvent.setup();
    
    // Mock network error
    const networkError = new Error('Network Error');
    mockAuthContextValue.login.mockRejectedValue(networkError);
    
    renderLoginWithContext();

    // Fill in valid credentials
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'password123');
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    // Wait for error handling
    await waitFor(() => {
      expect(mockAuthContextValue.login).toHaveBeenCalled();
    });

    // Verify error is handled gracefully and form is reset
    await waitFor(() => {
      expect(screen.getByText('Sign In', { selector: 'button' })).not.toBeDisabled();
    });
  });

  test('login flow with backend offline', async () => {
    const user = userEvent.setup();
    
    const offlineContextValue = {
      ...mockAuthContextValue,
      backendOnline: false,
    };
    
    renderLoginWithContext(offlineContextValue);

    // Should still render login form even when backend is offline
    expect(screen.getByText('Sign In')).toBeInTheDocument();
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();

    // User can still attempt login (fallback mechanisms should handle)
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'password123');
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    await waitFor(() => {
      expect(mockAuthContextValue.login).toHaveBeenCalled();
    });
  });

  test('login form accessibility and keyboard navigation', async () => {
    const user = userEvent.setup();
    
    renderLoginWithContext();

    // Test tab navigation
    await user.tab();
    expect(screen.getByLabelText('Email Address')).toHaveFocus();

    await user.tab();
    expect(screen.getByLabelText('Password')).toHaveFocus();

    await user.tab();
    expect(screen.getByText('Forgot your password?')).toHaveFocus();

    await user.tab();
    expect(screen.getByText('Sign In', { selector: 'button' })).toHaveFocus();

    // Test form submission with Enter key
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'password123');
    
    // Focus on email field and press Enter
    screen.getByLabelText('Email Address').focus();
    await user.keyboard('{Enter}');

    await waitFor(() => {
      expect(mockAuthContextValue.login).toHaveBeenCalled();
    });
  });

  test('login form with different screen sizes', async () => {
    // Test responsive behavior by checking if elements are properly rendered
    renderLoginWithContext();

    // Verify all responsive elements are present
    expect(screen.getByText('Sign In')).toBeInTheDocument();
    expect(screen.getByText('Welcome back! Please sign in to your account.')).toBeInTheDocument();
    expect(screen.getByText('Don\'t have an account?')).toBeInTheDocument();
    expect(screen.getByText('Sign up here')).toBeInTheDocument();

    // Verify OAuth section is present
    expect(screen.getByText('or')).toBeInTheDocument();
    expect(screen.getByText(/This is a demo OAuth2 server/)).toBeInTheDocument();
  });

  test('login form interaction with external links', async () => {
    const user = userEvent.setup();
    
    renderLoginWithContext();

    // Test forgot password link
    const forgotPasswordLink = screen.getByText('Forgot your password?');
    expect(forgotPasswordLink).toHaveAttribute('href', '/reset-password');

    // Test sign up link
    const signUpLink = screen.getByText('Sign up here');
    expect(signUpLink).toHaveAttribute('href', '/register');

    // Links should be clickable
    await user.click(forgotPasswordLink);
    await user.click(signUpLink);
  });

  test('login form state persistence during navigation', async () => {
    const user = userEvent.setup();
    
    renderLoginWithContext();

    // Fill in some data
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'partial');

    // Verify data is present
    expect(screen.getByLabelText('Email Address')).toHaveValue('test@example.com');
    expect(screen.getByLabelText('Password')).toHaveValue('partial');

    // Test that validation still works with partial data
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    await waitFor(() => {
      expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument();
    });
  });

  test('complete login flow with mocked API responses', async () => {
    const user = userEvent.setup();
    
    // Mock the complete flow
    const mockLoginResponse = {
      user: { id: 1, email: 'test@example.com' },
      access_token: 'mock-access-token',
      refresh_token: 'mock-refresh-token',
    };

    mockAuthContextValue.login.mockImplementation(async (email, password) => {
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 100));
      
      if (email === 'test@example.com' && password === 'password123') {
        return mockLoginResponse;
      } else {
        throw new Error('Invalid credentials');
      }
    });

    renderLoginWithContext();

    // Complete the login flow
    await user.type(screen.getByLabelText('Email Address'), 'test@example.com');
    await user.type(screen.getByLabelText('Password'), 'password123');
    await user.click(screen.getByText('Sign In', { selector: 'button' }));

    // Verify loading state
    expect(screen.getByText('Signing In...')).toBeInTheDocument();

    // Wait for completion
    await waitFor(() => {
      expect(mockAuthContextValue.login).toHaveBeenCalledWith('test@example.com', 'password123');
    });
  });
});