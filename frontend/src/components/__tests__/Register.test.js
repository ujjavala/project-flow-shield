import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { AuthContext } from '../../context/AuthContext';
import Register from '../Register';

const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate,
}));

const mockRegister = jest.fn();
const mockAuthContextValue = {
  register: mockRegister,
  user: null,
  loading: false,
  backendOnline: true,
};

const renderRegister = (contextValue = mockAuthContextValue) => {
  return render(
    <BrowserRouter>
      <AuthContext.Provider value={contextValue}>
        <Register />
      </AuthContext.Provider>
    </BrowserRouter>
  );
};

describe('Register Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders registration form elements', () => {
    renderRegister();
    
    expect(screen.getByText('Create Account')).toBeInTheDocument();
    expect(screen.getByText('Join us today! Create your account to get started.')).toBeInTheDocument();
    expect(screen.getByLabelText('First Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Last Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Username (Optional)')).toBeInTheDocument();
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm Password')).toBeInTheDocument();
    expect(screen.getByText('Create Account', { selector: 'button' })).toBeInTheDocument();
    expect(screen.getByText('Sign in here')).toBeInTheDocument();
  });

  test('shows validation errors for empty required fields', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('First name is required')).toBeInTheDocument();
      expect(screen.getByText('Last name is required')).toBeInTheDocument();
      expect(screen.getByText('Email is required')).toBeInTheDocument();
      expect(screen.getByText('Password is required')).toBeInTheDocument();
      expect(screen.getByText('Please confirm your password')).toBeInTheDocument();
    });
  });

  test('shows validation error for short first name', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    await user.type(firstNameInput, 'A');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('First name must be at least 2 characters')).toBeInTheDocument();
    });
  });

  test('shows validation error for short last name', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const lastNameInput = screen.getByLabelText('Last Name');
    await user.type(lastNameInput, 'B');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Last name must be at least 2 characters')).toBeInTheDocument();
    });
  });

  test('shows validation error for invalid username', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const usernameInput = screen.getByLabelText('Username (Optional)');
    await user.type(usernameInput, 'ab');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Username must be at least 3 characters')).toBeInTheDocument();
    });
  });

  test('shows validation error for username with special characters', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const usernameInput = screen.getByLabelText('Username (Optional)');
    await user.type(usernameInput, 'user@name');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Username can only contain letters, numbers, and underscores')).toBeInTheDocument();
    });
  });

  test('shows validation error for invalid email format', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const emailInput = screen.getByLabelText('Email Address');
    await user.type(emailInput, 'invalid-email');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Invalid email address')).toBeInTheDocument();
    });
  });

  test('shows validation error for weak password', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const passwordInput = screen.getByLabelText('Password');
    await user.type(passwordInput, 'weak');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument();
    });
  });

  test('shows validation error for password without special characters', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const passwordInput = screen.getByLabelText('Password');
    await user.type(passwordInput, 'Password123');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/Password must contain at least one uppercase letter/)).toBeInTheDocument();
    });
  });

  test('shows validation error for mismatched passwords', async () => {
    const user = userEvent.setup();
    renderRegister();
    
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    
    await user.type(passwordInput, 'Password123!');
    await user.type(confirmPasswordInput, 'DifferentPassword123!');
    
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Passwords do not match')).toBeInTheDocument();
    });
  });

  test('submits form with valid data and navigates on success', async () => {
    const user = userEvent.setup();
    mockRegister.mockResolvedValueOnce({ user: { id: 1, email: 'test@example.com' } });
    
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    const lastNameInput = screen.getByLabelText('Last Name');
    const usernameInput = screen.getByLabelText('Username (Optional)');
    const emailInput = screen.getByLabelText('Email Address');
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    
    await user.type(firstNameInput, 'John');
    await user.type(lastNameInput, 'Doe');
    await user.type(usernameInput, 'johndoe');
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'Password123!');
    await user.type(confirmPasswordInput, 'Password123!');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'Password123!',
        first_name: 'John',
        last_name: 'Doe',
        username: 'johndoe',
      });
      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });

  test('submits form without optional username', async () => {
    const user = userEvent.setup();
    mockRegister.mockResolvedValueOnce({ user: { id: 1, email: 'test@example.com' } });
    
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    const lastNameInput = screen.getByLabelText('Last Name');
    const emailInput = screen.getByLabelText('Email Address');
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    
    await user.type(firstNameInput, 'John');
    await user.type(lastNameInput, 'Doe');
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'Password123!');
    await user.type(confirmPasswordInput, 'Password123!');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'Password123!',
        first_name: 'John',
        last_name: 'Doe',
        username: '',
      });
    });
  });

  test('shows loading state during registration', async () => {
    const user = userEvent.setup();
    mockRegister.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));
    
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    const lastNameInput = screen.getByLabelText('Last Name');
    const emailInput = screen.getByLabelText('Email Address');
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    
    await user.type(firstNameInput, 'John');
    await user.type(lastNameInput, 'Doe');
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'Password123!');
    await user.type(confirmPasswordInput, 'Password123!');
    await user.click(submitButton);
    
    expect(screen.getByText('Creating Account...')).toBeInTheDocument();
    expect(submitButton).toBeDisabled();
  });

  test('handles registration error gracefully', async () => {
    const user = userEvent.setup();
    mockRegister.mockRejectedValueOnce(new Error('Registration failed'));
    
    renderRegister();
    
    const firstNameInput = screen.getByLabelText('First Name');
    const lastNameInput = screen.getByLabelText('Last Name');
    const emailInput = screen.getByLabelText('Email Address');
    const passwordInput = screen.getByLabelText('Password');
    const confirmPasswordInput = screen.getByLabelText('Confirm Password');
    const submitButton = screen.getByText('Create Account', { selector: 'button' });
    
    await user.type(firstNameInput, 'John');
    await user.type(lastNameInput, 'Doe');
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'Password123!');
    await user.type(confirmPasswordInput, 'Password123!');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalled();
      expect(mockNavigate).not.toHaveBeenCalled();
    });
  });

  test('sign in link points to correct route', () => {
    renderRegister();
    
    const signInLink = screen.getByText('Sign in here');
    expect(signInLink).toHaveAttribute('href', '/login');
  });
});