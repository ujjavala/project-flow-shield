import React from 'react';
import { FiMonitor, FiTool, FiActivity } from 'react-icons/fi';

const ServicesTab = ({ serviceStatus, temporalStatus }) => (
  <div className="services-tab">
    <div className="services-grid">
      <div className="service-card">
        <div className="service-header">
          <span className="service-icon"><FiMonitor /></span>
          <h3>Simple Server</h3>
          <span className={`status-badge ${serviceStatus?.simple_server?.status || 'unknown'}`}>
            {serviceStatus?.simple_server?.status || 'Unknown'}
          </span>
        </div>
        <div className="service-details">
          <p>Port: {serviceStatus?.simple_server?.port || 'N/A'}</p>
          <p>Features: {serviceStatus?.simple_server?.features?.join(', ') || 'None'}</p>
        </div>
      </div>

      <div className="service-card">
        <div className="service-header">
          <span className="service-icon"><FiTool /></span>
          <h3>Main Backend</h3>
          <span className={`status-badge ${serviceStatus?.main_backend?.status || 'unknown'}`}>
            {serviceStatus?.main_backend?.status || 'Unknown'}
          </span>
        </div>
        <div className="service-details">
          <p>Port: {serviceStatus?.main_backend?.port || 'N/A'}</p>
          <p>Features: {serviceStatus?.main_backend?.features?.join(', ') || 'None'}</p>
        </div>
      </div>

      <div className="service-card">
        <div className="service-header">
          <span className="service-icon"><FiActivity /></span>
          <h3>Temporal</h3>
          <span className={`status-badge ${temporalStatus?.temporal_connected ? 'healthy' : 'critical'}`}>
            {temporalStatus?.temporal_connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <div className="service-details">
          <p>Server: {temporalStatus?.temporal_server || 'N/A'}</p>
          <p>Namespace: {temporalStatus?.namespace || 'default'}</p>
          <p>Task Queue: {temporalStatus?.task_queue || 'N/A'}</p>
        </div>
      </div>
    </div>
  </div>
);

export default ServicesTab;