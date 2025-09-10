import React from 'react';

const NetworkVisualization = ({ activeConnections }) => (
  <div className="network-viz">
    <svg width="100%" height="200" className="network-svg">
      {activeConnections.map(conn => (
        <g key={conn.id}>
          <line
            x1={conn.from.x}
            y1={conn.from.y}
            x2={conn.to.x}
            y2={conn.to.y}
            stroke={conn.active ? '#4facfe' : 'rgba(255,255,255,0.2)'}
            strokeWidth={conn.strength * 3 + 1}
            opacity={conn.active ? 0.8 : 0.3}
          />
          <circle
            cx={conn.from.x}
            cy={conn.from.y}
            r={conn.active ? 6 : 3}
            fill={conn.active ? '#00f2fe' : 'rgba(255,255,255,0.5)'}
            opacity={conn.active ? 1 : 0.6}
          />
          <circle
            cx={conn.to.x}
            cy={conn.to.y}
            r={conn.active ? 6 : 3}
            fill={conn.active ? '#4facfe' : 'rgba(255,255,255,0.5)'}
            opacity={conn.active ? 1 : 0.6}
          />
        </g>
      ))}
    </svg>
  </div>
);

export default NetworkVisualization;