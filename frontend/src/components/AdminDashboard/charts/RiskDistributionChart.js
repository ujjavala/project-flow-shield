import React from 'react';

const RiskDistributionChart = ({ data }) => {
  if (!data) return <div className="no-data">No data available</div>;
  
  const total = Object.values(data).reduce((sum, val) => sum + val, 0);
  
  return (
    <div className="risk-chart">
      {Object.entries(data).map(([key, value]) => (
        <div key={key} className="risk-bar">
          <span className="risk-label">{key}</span>
          <div className="risk-bar-container">
            <div 
              className={`risk-bar-fill ${key}`}
              style={{ width: `${(value / total) * 100}%` }}
            ></div>
          </div>
          <span className="risk-value">{value}</span>
        </div>
      ))}
    </div>
  );
};

export default RiskDistributionChart;