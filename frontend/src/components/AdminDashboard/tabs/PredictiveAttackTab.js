import React, { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { FiZap, FiShield, FiTarget, FiAlertTriangle, FiBarChart2, FiTrendingUp, FiSearch, FiRotateCcw, FiPlay, FiActivity } from 'react-icons/fi';
import './PredictiveAttackTab.css';

const PredictiveAttackTab = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [simulations, setSimulations] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [activeSimulations, setActiveSimulations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showSimulationModal, setShowSimulationModal] = useState(false);
  const [selectedSimulation, setSelectedSimulation] = useState(null);
  const [simulationForm, setSimulationForm] = useState({
    target_system: '',
    simulation_type: 'standard',
    severity_threshold: 0.7,
    max_simulations: 10,
    safety_mode: true,
    auto_remediation: false
  });
  const [continuousMonitoring, setContinuousMonitoring] = useState(null);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const token = localStorage.getItem('admin_token');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Load all data in parallel
      const [dashboardRes, simulationsRes, predictionsRes] = await Promise.all([
        fetch('/api/predictive-attack/dashboard', { headers }),
        fetch('/api/predictive-attack/simulations?limit=20', { headers }),
        fetch('/api/predictive-attack/predictions?limit=15', { headers })
      ]);

      if (dashboardRes.ok) {
        const dashboardData = await dashboardRes.json();
        setDashboardData(dashboardData);
      }

      if (simulationsRes.ok) {
        const simulationsData = await simulationsRes.json();
        setSimulations(simulationsData);
        setActiveSimulations(simulationsData.filter(s => s.status === 'running' || s.status === 'pending'));
      }

      if (predictionsRes.ok) {
        const predictionsData = await predictionsRes.json();
        setPredictions(predictionsData);
      }

      setLoading(false);
    } catch (error) {
      console.error('Error loading predictive attack data:', error);
      toast.error('Failed to load predictive attack data');
      setLoading(false);
    }
  };

  const startSimulation = async () => {
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch('/api/predictive-attack/simulate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(simulationForm)
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`Attack simulation started: ${result.simulation_id}`);
        setShowSimulationModal(false);
        loadDashboardData(); // Refresh data
      } else {
        const error = await response.json();
        toast.error(`Failed to start simulation: ${error.detail}`);
      }
    } catch (error) {
      console.error('Error starting simulation:', error);
      toast.error('Failed to start attack simulation');
    }
  };

  const toggleContinuousMonitoring = async (system) => {
    try {
      const token = localStorage.getItem('admin_token');

      if (continuousMonitoring && continuousMonitoring.target_system === system) {
        // Stop monitoring
        const response = await fetch(`/api/predictive-attack/continuous-monitoring/${continuousMonitoring.monitoring_id}/stop`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });

        if (response.ok) {
          setContinuousMonitoring(null);
          toast.success('Continuous monitoring stopped');
        }
      } else {
        // Start monitoring
        const response = await fetch('/api/predictive-attack/continuous-monitoring/start', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            target_system: system,
            monitoring_duration_hours: 24
          })
        });

        if (response.ok) {
          const result = await response.json();
          setContinuousMonitoring(result);
          toast.success('Continuous monitoring started');
        }
      }
    } catch (error) {
      console.error('Error toggling continuous monitoring:', error);
      toast.error('Failed to toggle continuous monitoring');
    }
  };

  const viewSimulationDetails = async (simulationId) => {
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch(`/api/predictive-attack/simulation/${simulationId}/status`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const details = await response.json();
        setSelectedSimulation(details);
      }
    } catch (error) {
      console.error('Error fetching simulation details:', error);
      toast.error('Failed to load simulation details');
    }
  };

  const getRiskLevelColor = (level) => {
    const colors = {
      'low': '#10b981',
      'medium': '#f59e0b',
      'high': '#f97316',
      'critical': '#dc2626'
    };
    return colors[level] || '#6b7280';
  };

  const getSimulationStatusColor = (status) => {
    const colors = {
      'running': '#3b82f6',
      'completed': '#10b981',
      'failed': '#dc2626',
      'pending': '#f59e0b'
    };
    return colors[status] || '#6b7280';
  };

  if (loading) {
    return (
      <div className="predictive-attack-tab">
        <div className="loading-container">
          <p>Loading Predictive Attack Intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="predictive-attack-tab">
      <div className="tab-header">
        <h2><FiActivity /> Predictive Attack Simulation</h2>
        <div className="header-actions">
          <button
            className="start-simulation-btn"
            onClick={() => setShowSimulationModal(true)}
          >
            <span className="icon"><FiZap /></span>
            Start Attack Simulation
          </button>
        </div>
      </div>

      {/* Security Overview Dashboard */}
      {dashboardData && (
        <div className="security-overview-cards">
          <div className="overview-card">
            <div className="card-icon"><FiShield /></div>
            <div className="card-content">
              <div className="card-value">{dashboardData.overview.systems_monitored}</div>
              <div className="card-label">Systems Monitored</div>
            </div>
          </div>
          <div className="overview-card">
            <div className="card-icon"><FiTarget /></div>
            <div className="card-content">
              <div className="card-value">{dashboardData.overview.total_simulations}</div>
              <div className="card-label">Attack Simulations</div>
            </div>
          </div>
          <div className="overview-card">
            <div className="card-icon"><FiAlertTriangle /></div>
            <div className="card-content">
              <div className="card-value">{dashboardData.high_risk_predictions.length}</div>
              <div className="card-label">High-Risk Predictions</div>
            </div>
          </div>
          <div className="overview-card">
            <div className="card-icon"><FiBarChart2 /></div>
            <div className="card-content">
              <div className="card-value">{dashboardData.security_metrics.security_posture_score.toFixed(1)}</div>
              <div className="card-label">Security Score</div>
            </div>
          </div>
        </div>
      )}

      {/* Active Simulations Alert */}
      {activeSimulations.length > 0 && (
        <div className="active-simulations-alert">
          <div className="alert-content">
            <span className="alert-icon"><FiRotateCcw /></span>
            <span className="alert-text">
              {activeSimulations.length} attack simulation{activeSimulations.length > 1 ? 's' : ''} currently running
            </span>
          </div>
        </div>
      )}

      <div className="content-grid">
        {/* High-Risk Predictions Panel */}
        <div className="panel high-risk-predictions">
          <h3><FiTarget /> High-Risk Attack Predictions</h3>
          <div className="predictions-list">
            {predictions.slice(0, 8).map((prediction) => (
              <div key={prediction.id} className="prediction-item">
                <div className="prediction-header">
                  <span className="attack-type">{prediction.attack_type.replace('_', ' ').toUpperCase()}</span>
                  <span className="likelihood-badge" style={{backgroundColor: getRiskLevelColor(prediction.likelihood > 0.8 ? 'critical' : prediction.likelihood > 0.6 ? 'high' : 'medium')}}>
                    {(prediction.likelihood * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="prediction-details">
                  <div className="target">Target: {prediction.target_component}</div>
                  <div className="confidence">Confidence: {(prediction.confidence * 100).toFixed(0)}%</div>
                  <div className="reasoning">{prediction.reasoning}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Simulations */}
        <div className="panel recent-simulations">
          <h3><FiZap /> Recent Attack Simulations</h3>
          <div className="simulations-list">
            {simulations.slice(0, 10).map((simulation) => (
              <div
                key={simulation.id}
                className="simulation-item"
                onClick={() => viewSimulationDetails(simulation.id)}
              >
                <div className="simulation-header">
                  <span className="simulation-name">{simulation.simulation_name}</span>
                  <span
                    className="status-badge"
                    style={{backgroundColor: getSimulationStatusColor(simulation.status)}}
                  >
                    {simulation.status.toUpperCase()}
                  </span>
                </div>
                <div className="simulation-details">
                  <div className="target-system">System: {simulation.target_system}</div>
                  <div className="vulnerabilities">
                    Vulnerabilities Found: {simulation.vulnerabilities_found}
                  </div>
                  <div className="impact-score">
                    Impact Score: {simulation.security_impact_score.toFixed(2)}
                  </div>
                  <div className="duration">
                    Duration: {Math.floor(simulation.duration_seconds / 60)}m {simulation.duration_seconds % 60}s
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Metrics */}
        <div className="panel security-metrics">
          <h3><FiTrendingUp /> Security Intelligence Metrics</h3>
          {dashboardData && (
            <div className="metrics-grid">
              <div className="metric-item">
                <div className="metric-label">Prediction Accuracy</div>
                <div className="metric-value">
                  {(dashboardData.security_metrics.prediction_accuracy * 100).toFixed(1)}%
                </div>
                <div className="metric-bar">
                  <div
                    className="metric-fill"
                    style={{width: `${dashboardData.security_metrics.prediction_accuracy * 100}%`}}
                  ></div>
                </div>
              </div>
              <div className="metric-item">
                <div className="metric-label">False Positive Rate</div>
                <div className="metric-value">
                  {(dashboardData.security_metrics.false_positive_rate * 100).toFixed(1)}%
                </div>
                <div className="metric-bar">
                  <div
                    className="metric-fill error"
                    style={{width: `${dashboardData.security_metrics.false_positive_rate * 100}%`}}
                  ></div>
                </div>
              </div>
              <div className="metric-item">
                <div className="metric-label">Systems Scanned (24h)</div>
                <div className="metric-value">
                  {dashboardData.overview.simulations_24h}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Top Vulnerabilities */}
        <div className="panel top-vulnerabilities">
          <h3><FiSearch /> Top Vulnerability Types</h3>
          <div className="vulnerabilities-list">
            {dashboardData?.top_vulnerabilities.map((vuln, index) => (
              <div key={index} className="vulnerability-item">
                <div className="vuln-rank">{index + 1}</div>
                <div className="vuln-details">
                  <div className="vuln-type">{vuln.vulnerability_type.replace('_', ' ').toUpperCase()}</div>
                  <div className="vuln-stats">
                    Found {vuln.occurrence_count} times • Avg Severity: {vuln.average_severity.toFixed(1)}
                  </div>
                </div>
                <div className="vuln-severity-bar">
                  <div
                    className="severity-fill"
                    style={{
                      width: `${(vuln.average_severity / 10) * 100}%`,
                      backgroundColor: getRiskLevelColor(vuln.average_severity > 7 ? 'critical' : vuln.average_severity > 5 ? 'high' : 'medium')
                    }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Continuous Monitoring Control */}
        <div className="panel continuous-monitoring">
          <h3><FiRotateCcw /> Continuous Attack Monitoring</h3>
          <div className="monitoring-controls">
            {continuousMonitoring ? (
              <div className="monitoring-active">
                <div className="monitoring-status">
                  <span className="status-indicator active"></span>
                  <span>Monitoring: {continuousMonitoring.target_system}</span>
                </div>
                <div className="monitoring-details">
                  Started: {new Date(continuousMonitoring.started_at).toLocaleString()}
                </div>
                <button
                  className="stop-monitoring-btn"
                  onClick={() => toggleContinuousMonitoring(continuousMonitoring.target_system)}
                >
                  Stop Monitoring
                </button>
              </div>
            ) : (
              <div className="monitoring-inactive">
                <p>Start continuous attack monitoring for real-time threat detection</p>
                <input
                  type="text"
                  placeholder="Target system (e.g., production_api)"
                  className="system-input"
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      toggleContinuousMonitoring(e.target.value);
                    }
                  }}
                />
                <button
                  className="start-monitoring-btn"
                  onClick={() => {
                    const input = document.querySelector('.system-input');
                    if (input.value.trim()) {
                      toggleContinuousMonitoring(input.value.trim());
                    }
                  }}
                >
                  Start 24h Monitoring
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* New Simulation Modal */}
      {showSimulationModal && (
        <div className="modal-overlay" onClick={() => setShowSimulationModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3><FiPlay /> Start Attack Simulation</h3>
              <button
                className="close-btn"
                onClick={() => setShowSimulationModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Target System</label>
                <input
                  type="text"
                  value={simulationForm.target_system}
                  onChange={(e) => setSimulationForm({...simulationForm, target_system: e.target.value})}
                  placeholder="e.g., web_application, api_service"
                />
              </div>
              <div className="form-group">
                <label>Simulation Type</label>
                <select
                  value={simulationForm.simulation_type}
                  onChange={(e) => setSimulationForm({...simulationForm, simulation_type: e.target.value})}
                >
                  <option value="standard">Standard Scan</option>
                  <option value="deep">Deep Analysis</option>
                  <option value="targeted">Targeted Attack</option>
                </select>
              </div>
              <div className="form-group">
                <label>Severity Threshold: {simulationForm.severity_threshold}</label>
                <input
                  type="range"
                  min="0.1"
                  max="1.0"
                  step="0.1"
                  value={simulationForm.severity_threshold}
                  onChange={(e) => setSimulationForm({...simulationForm, severity_threshold: parseFloat(e.target.value)})}
                />
                <div className="range-labels">
                  <span>Low (0.1)</span>
                  <span>Critical (1.0)</span>
                </div>
              </div>
              <div className="form-group">
                <label>Max Simulations</label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  value={simulationForm.max_simulations}
                  onChange={(e) => setSimulationForm({...simulationForm, max_simulations: parseInt(e.target.value)})}
                />
              </div>
              <div className="form-group checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    checked={simulationForm.safety_mode}
                    onChange={(e) => setSimulationForm({...simulationForm, safety_mode: e.target.checked})}
                  />
                  Safety Mode (Recommended)
                </label>
              </div>
              <div className="form-group checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    checked={simulationForm.auto_remediation}
                    onChange={(e) => setSimulationForm({...simulationForm, auto_remediation: e.target.checked})}
                  />
                  Enable Auto-Remediation
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="cancel-btn"
                onClick={() => setShowSimulationModal(false)}
              >
                Cancel
              </button>
              <button
                className="start-btn"
                onClick={startSimulation}
                disabled={!simulationForm.target_system}
              >
                <FiPlay /> Start Simulation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Simulation Details Modal */}
      {selectedSimulation && (
        <div className="modal-overlay" onClick={() => setSelectedSimulation(null)}>
          <div className="modal-content large" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3><FiBarChart2 /> Simulation Details</h3>
              <button
                className="close-btn"
                onClick={() => setSelectedSimulation(null)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="simulation-details-content">
                <div className="detail-section">
                  <h4>Simulation Status</h4>
                  <p>Status: <span className="status">{selectedSimulation.status}</span></p>
                  <p>Simulation ID: {selectedSimulation.simulation_id}</p>
                </div>
                {selectedSimulation.result && (
                  <div className="detail-section">
                    <h4>Results Summary</h4>
                    <p>Predictions Analyzed: {selectedSimulation.result.predictions_analyzed}</p>
                    <p>Simulations Executed: {selectedSimulation.result.simulations_executed}</p>
                    <p>Vulnerabilities Found: {selectedSimulation.result.vulnerabilities_discovered}</p>
                    <p>Security Score: {selectedSimulation.result.overall_security_score}/10</p>

                    {selectedSimulation.result.recommendations && (
                      <div className="recommendations">
                        <h5>AI Recommendations:</h5>
                        <ul>
                          {selectedSimulation.result.recommendations.map((rec, idx) => (
                            <li key={idx}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PredictiveAttackTab;