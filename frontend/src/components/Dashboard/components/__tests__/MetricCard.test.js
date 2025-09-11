import { render, screen } from '@testing-library/react';
import MetricCard from '../MetricCard';

describe('MetricCard Component', () => {
  const defaultProps = {
    icon: '📊',
    title: 'Total Users',
    value: '1,234',
    change: { text: '+12%', type: 'positive' },
  };

  test('renders metric card with basic props', () => {
    render(<MetricCard {...defaultProps} />);
    
    expect(screen.getByText('📊')).toBeInTheDocument();
    expect(screen.getByText('Total Users')).toBeInTheDocument();
    expect(screen.getByText('1,234')).toBeInTheDocument();
    expect(screen.getByText('+12%')).toBeInTheDocument();
  });

  test('applies positive change styling', () => {
    render(<MetricCard {...defaultProps} />);
    
    const changeElement = screen.getByText('+12%');
    expect(changeElement).toHaveClass('metric-change', 'positive');
  });

  test('applies negative change styling', () => {
    const props = {
      ...defaultProps,
      change: { text: '-5%', type: 'negative' },
    };
    
    render(<MetricCard {...props} />);
    
    const changeElement = screen.getByText('-5%');
    expect(changeElement).toHaveClass('metric-change', 'negative');
  });

  test('applies neutral change styling when no type provided', () => {
    const props = {
      ...defaultProps,
      change: { text: '0%' },
    };
    
    render(<MetricCard {...props} />);
    
    const changeElement = screen.getByText('0%');
    expect(changeElement).toHaveClass('metric-change', 'neutral');
  });

  test('applies highlight class when highlight prop is true', () => {
    render(<MetricCard {...defaultProps} highlight={true} />);
    
    const cardElement = screen.getByText('Total Users').closest('.metric-card');
    expect(cardElement).toHaveClass('highlight');
  });

  test('does not apply highlight class when highlight prop is false', () => {
    render(<MetricCard {...defaultProps} highlight={false} />);
    
    const cardElement = screen.getByText('Total Users').closest('.metric-card');
    expect(cardElement).not.toHaveClass('highlight');
  });

  test('does not apply highlight class when highlight prop is not provided', () => {
    render(<MetricCard {...defaultProps} />);
    
    const cardElement = screen.getByText('Total Users').closest('.metric-card');
    expect(cardElement).not.toHaveClass('highlight');
  });

  test('renders with different icon types', () => {
    const props = {
      ...defaultProps,
      icon: '🔒',
      title: 'Security Events',
    };
    
    render(<MetricCard {...props} />);
    
    expect(screen.getByText('🔒')).toBeInTheDocument();
    expect(screen.getByText('Security Events')).toBeInTheDocument();
  });

  test('renders with long values', () => {
    const props = {
      ...defaultProps,
      value: '1,234,567,890',
    };
    
    render(<MetricCard {...props} />);
    
    expect(screen.getByText('1,234,567,890')).toBeInTheDocument();
  });

  test('renders with complex change text', () => {
    const props = {
      ...defaultProps,
      change: { text: '+15% from last month', type: 'positive' },
    };
    
    render(<MetricCard {...props} />);
    
    expect(screen.getByText('+15% from last month')).toBeInTheDocument();
  });
});