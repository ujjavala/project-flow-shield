import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import Login from '../Login';
import { vi } from 'vitest';

// Mock the auth context hook
const { mockLogin, mockNavigate } = vi.hoisted(() => ({
  mockLogin: vi.fn(),
  mockNavigate: vi.fn(),
}));
const mockUseAuth = {
  login: mockLogin,
  user: null,
  loading: false,
  backendOnline: true,
};

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => mockUseAuth,
}));

// Mock navigate
vi.mock('react-router-dom', async () => ({
  ...(await vi.importActual('react-router-dom')),
  useNavigate: () => mockNavigate,
}));

const renderLogin = () => {
  return render(
    <BrowserRouter>
      <Login />
    </BrowserRouter>
  );
};

describe('Login Component - Simple Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('renders login page structure', () => {
    renderLogin();
    
    // Check for main elements without conflicting text
    expect(screen.getByRole('heading', { name: 'Sign In' })).toBeInTheDocument();
    expect(screen.getByText('Welcome back! Please sign in to your account.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();
  });

  test('renders form inputs', () => {
    renderLogin();
    
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });

  test('renders navigation links', () => {
    renderLogin();
    
    expect(screen.getByText('Forgot your password?')).toBeInTheDocument();
    expect(screen.getByText('Sign up here')).toBeInTheDocument();
  });

  test('renders OAuth section', () => {
    renderLogin();
    
    expect(screen.getByText('or')).toBeInTheDocument();
    expect(screen.getByText(/This is a demo OAuth2 server/)).toBeInTheDocument();
  });

  test('form inputs accept user input', async () => {
    renderLogin();
    
    const emailInput = screen.getByLabelText('Email Address');
    const passwordInput = screen.getByLabelText('Password');
    
    await userEvent.type(emailInput, 'test@example.com');
    await userEvent.type(passwordInput, 'password123');
    
    expect(emailInput).toHaveValue('test@example.com');
    expect(passwordInput).toHaveValue('password123');
  });

  test('button is clickable', async () => {
    renderLogin();
    
    const submitButton = screen.getByRole('button', { name: 'Sign In' });
    await userEvent.click(submitButton);
    
    // Button should be clickable (no errors thrown)
    expect(submitButton).toBeInTheDocument();
  });

  test('external links have correct hrefs', () => {
    renderLogin();
    
    const forgotPasswordLink = screen.getByText('Forgot your password?');
    const signUpLink = screen.getByText('Sign up here');
    
    expect(forgotPasswordLink).toHaveAttribute('href', '/reset-password');
    expect(signUpLink).toHaveAttribute('href', '/register');
  });
});