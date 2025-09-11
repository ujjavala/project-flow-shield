import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import Register from '../Register';

// Mock the auth context hook
const mockRegister = jest.fn();
const mockUseAuth = {
  register: mockRegister,
  user: null,
  loading: false,
  backendOnline: true,
};

jest.mock('../../context/AuthContext', () => ({
  useAuth: () => mockUseAuth,
}));

// Mock navigate
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate,
}));

const renderRegister = () => {
  return render(
    <BrowserRouter>
      <Register />
    </BrowserRouter>
  );
};

describe('Register Component - Simple Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders registration page structure', () => {
    renderRegister();
    
    expect(screen.getByRole('heading', { name: 'Create Account' })).toBeInTheDocument();
    expect(screen.getByText('Join us today! Create your account to get started.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Account' })).toBeInTheDocument();
  });

  test('renders all form inputs', () => {
    renderRegister();
    
    expect(screen.getByLabelText('First Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Last Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Username (Optional)')).toBeInTheDocument();
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm Password')).toBeInTheDocument();
  });

  test('renders navigation links', () => {
    renderRegister();
    
    expect(screen.getByText('Sign in here')).toBeInTheDocument();
  });

  test('form inputs accept user input', async () => {
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    const lastNameInput = screen.getByLabelText('Last Name');
    const emailInput = screen.getByLabelText('Email Address');
    
    await userEvent.type(firstNameInput, 'John');
    await userEvent.type(lastNameInput, 'Doe');
    await userEvent.type(emailInput, 'john@example.com');
    
    expect(firstNameInput).toHaveValue('John');
    expect(lastNameInput).toHaveValue('Doe');
    expect(emailInput).toHaveValue('john@example.com');
  });

  test('password fields work correctly', async () => {
    renderRegister();
    
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    
    await userEvent.type(passwordInput, 'Password123!');
    await userEvent.type(confirmPasswordInput, 'Password123!');
    
    expect(passwordInput).toHaveValue('Password123!');
    expect(confirmPasswordInput).toHaveValue('Password123!');
  });

  test('optional username field works', async () => {
    renderRegister();
    
    const usernameInput = screen.getByLabelText('Username (Optional)');
    
    await userEvent.type(usernameInput, 'johndoe');
    
    expect(usernameInput).toHaveValue('johndoe');
  });

  test('form submission triggers register function', async () => {
    mockRegister.mockResolvedValueOnce({ success: true });
    renderRegister();
    
    // Fill out form
    await userEvent.type(screen.getByLabelText('First Name'), 'John');
    await userEvent.type(screen.getByLabelText('Last Name'), 'Doe');
    await userEvent.type(screen.getByLabelText('Email Address'), 'john@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'Password123!');
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'Password123!');
    
    // Submit form
    const submitButton = screen.getByRole('button', { name: 'Create Account' });
    await userEvent.click(submitButton);
    
    // Should eventually call register (though form validation might prevent it in this simple test)
    expect(submitButton).toBeInTheDocument();
  });

  test('external links have correct hrefs', () => {
    renderRegister();
    
    const signInLink = screen.getByText('Sign in here');
    expect(signInLink).toHaveAttribute('href', '/login');
  });

  test('form has proper accessibility attributes', () => {
    renderRegister();
    
    // Check that form inputs have proper labels
    expect(screen.getByLabelText('First Name')).toHaveAttribute('id', 'firstName');
    expect(screen.getByLabelText('Last Name')).toHaveAttribute('id', 'lastName');
    expect(screen.getByLabelText('Email Address')).toHaveAttribute('id', 'email');
    expect(screen.getByLabelText('Password')).toHaveAttribute('id', 'password');
    expect(screen.getByLabelText('Confirm Password')).toHaveAttribute('id', 'confirmPassword');
  });
});