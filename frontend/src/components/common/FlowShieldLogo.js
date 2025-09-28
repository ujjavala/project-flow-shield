import React from 'react';

const FlowShieldLogo = ({ size = 32, className = "" }) => (
  <div className={`flowshield-logo ${className}`} style={{ width: size, height: size }}>
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#4facfe" />
          <stop offset="50%" stopColor="#00f2fe" />
          <stop offset="100%" stopColor="#4facfe" />
        </linearGradient>
        <linearGradient id="flowGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00ff88" />
          <stop offset="50%" stopColor="#4facfe" />
          <stop offset="100%" stopColor="#00f2fe" />
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>

      {/* Shield Base */}
      <path
        d="M50 10 L20 25 L20 55 Q20 75 50 90 Q80 75 80 55 L80 25 Z"
        fill="url(#shieldGradient)"
        stroke="rgba(255,255,255,0.2)"
        strokeWidth="1"
        filter="url(#glow)"
      />

      {/* Flow Lines */}
      <g stroke="url(#flowGradient)" strokeWidth="2" fill="none" opacity="0.8">
        <path d="M35 35 Q50 30 65 35" strokeLinecap="round" />
        <path d="M30 45 Q50 40 70 45" strokeLinecap="round" />
        <path d="M35 55 Q50 50 65 55" strokeLinecap="round" />
      </g>

      {/* Center Dot */}
      <circle
        cx="50"
        cy="45"
        r="4"
        fill="#ffffff"
        filter="url(#glow)"
      />

      {/* Security Lock Symbol */}
      <g fill="rgba(255,255,255,0.9)">
        <rect x="46" y="60" width="8" height="6" rx="1" />
        <path d="M47 60 L47 57 Q47 55 50 55 Q53 55 53 57 L53 60" stroke="rgba(255,255,255,0.9)" strokeWidth="1.5" fill="none" />
      </g>
    </svg>
  </div>
);

export default FlowShieldLogo;