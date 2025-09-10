import React from 'react';

const RiskFactorsChart = ({ data }) => {
  if (!data) return <div className="no-data">No data available</div>;
  
  return (
    <div className="risk-factors-chart">
      {data.slice(0, 5).map((factor, i) => (
        <div key={i} className="factor-item">
          <span className="factor-name">{factor.factor.replace(/_/g, ' ')}</span>
          <div className="factor-bar">
            <div 
              className="factor-fill"
              style={{ width: `${factor.percentage}%` }}
            ></div>
          </div>
          <span className="factor-percentage">{factor.percentage}%</span>
        </div>
      ))}
    </div>
  );
};

export default RiskFactorsChart;