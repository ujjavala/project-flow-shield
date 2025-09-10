import React from 'react';

const LineChart = ({ data, color, label }) => {
  const maxValue = Math.max(...data.map(d => d.cpu || d.memory || d.network || 100));
  const minValue = Math.min(...data.map(d => d.cpu || d.memory || d.network || 0));
  const range = maxValue - minValue || 1;

  return (
    <div className="interactive-chart">
      <div className="chart-header">
        <span className="chart-label">{label}</span>
        <span className="chart-value">{data[data.length - 1]?.cpu?.toFixed(1) || '0'}%</span>
      </div>
      <svg width="100%" height="60" className="chart-svg">
        <defs>
          <linearGradient id={`gradient-${label}`} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={color} stopOpacity="0.6"/>
            <stop offset="100%" stopColor={color} stopOpacity="0.1"/>
          </linearGradient>
        </defs>
        <polyline
          fill="none"
          stroke={color}
          strokeWidth="2"
          points={data.map((d, i) => 
            `${(i / (data.length - 1)) * 100},${60 - ((d.cpu - minValue) / range) * 50}`
          ).join(' ')}
        />
        <polygon
          fill={`url(#gradient-${label})`}
          points={`0,60 ${data.map((d, i) => 
            `${(i / (data.length - 1)) * 100},${60 - ((d.cpu - minValue) / range) * 50}`
          ).join(' ')} 100,60`}
        />
      </svg>
    </div>
  );
};

export default LineChart;