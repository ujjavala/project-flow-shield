import React from 'react';

const MetricCard = ({ icon, title, value, change, highlight = false }) => (
  <div className={`metric-card ${highlight ? 'highlight' : ''}`}>
    <div className="metric-header">
      <span className="metric-icon">{icon}</span>
      <h3>{title}</h3>
    </div>
    <div className="metric-value">{value}</div>
    <div className={`metric-change ${change.type || 'neutral'}`}>{change.text}</div>
  </div>
);

export default MetricCard;