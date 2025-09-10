import React from 'react';
import LineChart from './LineChart';

const HealthCard = ({ 
  icon, 
  title, 
  value, 
  status, 
  chartData, 
  chartColor, 
  chartLabel, 
  getHealthStatus 
}) => (
  <div className="health-card interactive-card">
    <div className="health-header">
      <span className="health-icon">{icon}</span>
      <h4>{title}</h4>
      <span className={`health-status ${status}`}>
        {status}
      </span>
    </div>
    <div className="progress-container">
      <div className="progress-bar">
        <div 
          className={`progress-fill ${status}`}
          style={{ width: `${value}%` }}
        ></div>
      </div>
      <span className="progress-value">{Math.round(value)}%</span>
    </div>
    {chartData.length > 0 && (
      <LineChart 
        data={chartData} 
        color={chartColor} 
        label={chartLabel} 
      />
    )}
  </div>
);

export default HealthCard;