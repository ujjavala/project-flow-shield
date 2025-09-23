import React from 'react';

const AITab = ({ aiStatus, fraudAnalytics, onRefresh }) => (
  <div className="ai-tab">
    <div className="ai-tab-header">
      <h2>AI System Status</h2>
    </div>
    <div className="ai-metrics-grid">
      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">🤖</span>
          <h3>Ollama Status</h3>
          <span className={`status-badge ${aiStatus?.ollama_available ? 'healthy' : 'critical'}`}>
            {aiStatus?.ollama_available ? 'Online' : 'Offline'}
          </span>
        </div>
        <div className="ai-details">
          <p>Model: {aiStatus?.model_name || 'llama3'}</p>
          <p>Endpoint: {aiStatus?.endpoint || 'localhost:11434'}</p>
        </div>
      </div>

      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">⚡</span>
          <h3>Performance</h3>
          <span className="status-badge healthy">Active</span>
        </div>
        <div className="ai-details">
          <p>Response Time: {fraudAnalytics?.ai_model_stats?.avg_response_time_ms || 0}ms</p>
          <p>Accuracy: {fraudAnalytics?.ai_model_stats?.model_accuracy || 0}%</p>
        </div>
      </div>

      <div className="ai-card">
        <div className="ai-header">
          <span className="ai-icon">📊</span>
          <h3>Usage Stats</h3>
          <span className="status-badge healthy">Monitoring</span>
        </div>
        <div className="ai-details">
          <p>Total Requests: {fraudAnalytics?.ai_model_stats?.total_ai_requests || 0}</p>
          <p>Availability: {fraudAnalytics?.ai_model_stats?.ai_availability || 0}%</p>
        </div>
      </div>
    </div>
  </div>
);

export default AITab;