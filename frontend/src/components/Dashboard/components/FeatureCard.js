import React from 'react';

const FeatureCard = ({ icon, title, description, status, animationClass }) => (
  <div className="feature-card">
    <div className="feature-visual">
      <div className="feature-icon-large">{icon}</div>
      <div className={`feature-animation ${animationClass}`}></div>
    </div>
    <h3>{title}</h3>
    <p>{description}</p>
    <div className="feature-status online">{status}</div>
  </div>
);

export default FeatureCard;