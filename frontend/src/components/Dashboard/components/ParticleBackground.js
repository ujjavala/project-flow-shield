import React from 'react';

const ParticleBackground = ({ particleData }) => (
  <div className="particle-background">
    {particleData.map(particle => (
      <div
        key={particle.id}
        className="particle"
        style={{
          left: `${particle.x}px`,
          top: `${particle.y}px`,
          width: `${particle.size}px`,
          height: `${particle.size}px`,
          backgroundColor: particle.color,
          opacity: particle.opacity
        }}
      />
    ))}
  </div>
);

export default ParticleBackground;