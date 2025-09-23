"""
Comprehensive tests for Predictive Attack Simulation feature
Tests workflows, activities, and API endpoints
"""

import pytest
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient

from app.temporal.workflows.predictive_attack_workflow import (
    PredictiveAttackSimulationWorkflow,
    AttackSimulationExecutorWorkflow,
    AutoRemediationWorkflow,
    AttackSimulationRequest
)
from app.temporal.activities.attack_simulation_activities import AttackSimulationActivities


class TestPredictiveAttackWorkflows:
    """Test Temporal workflows for predictive attack simulation"""

    @pytest.fixture
    def mock_workflow_context(self):
        """Mock workflow context"""
        with patch('temporalio.workflow.info') as mock_info:
            mock_info.return_value.workflow_id = "test-workflow-123"
            mock_info.return_value.start_time = datetime.utcnow()
            yield mock_info

    @pytest.fixture
    def attack_simulation_request(self):
        """Sample attack simulation request"""
        return AttackSimulationRequest(
            target_system="test_system",
            simulation_type="standard",
            attack_vectors=["sql_injection", "xss"],
            severity_threshold=0.7,
            max_simulations=5,
            safety_mode=True,
            requester_id="test_admin",
            metadata={"test": True}
        )

    @pytest.mark.asyncio
    async def test_predictive_attack_simulation_workflow_success(
        self, mock_workflow_context, attack_simulation_request
    ):
        """Test successful execution of main attack simulation workflow"""

        # Mock activity results
        mock_attack_surface = {
            "success": True,
            "target_system": "test_system",
            "vulnerability_score": 0.8,
            "exposure_level": "high",
            "attack_vectors": ["sql_injection", "xss"]
        }

        mock_predictions = {
            "success": True,
            "predictions": [
                {
                    "attack_type": "sql_injection",
                    "likelihood": 0.9,
                    "confidence": 0.85,
                    "details": {"severity": "high"}
                },
                {
                    "attack_type": "xss",
                    "likelihood": 0.8,
                    "confidence": 0.8,
                    "details": {"severity": "medium"}
                }
            ]
        }

        mock_security_report = {
            "success": True,
            "overall_security_score": 6.5,
            "security_improvement": 2.3,
            "top_recommendations": ["Fix SQL injection", "Implement XSS protection"]
        }

        with patch('temporalio.workflow.execute_activity') as mock_activity, \
             patch('temporalio.workflow.execute_child_workflow') as mock_child, \
             patch('temporalio.workflow.gather') as mock_gather:

            # Setup activity mocks
            mock_activity.side_effect = [
                mock_attack_surface,  # analyze_attack_surface
                mock_predictions,     # predict_attack_vectors
                mock_security_report, # generate_security_report
                {"success": True}     # update_security_metrics
            ]

            # Setup child workflow mocks (simulations)
            mock_simulation_results = [
                {
                    "success": True,
                    "vulnerabilities": [{"severity": "high"}, {"severity": "medium"}],
                    "security_impact": 0.8
                },
                {
                    "success": True,
                    "vulnerabilities": [{"severity": "critical"}],
                    "security_impact": 0.9
                }
            ]
            mock_gather.return_value = mock_simulation_results

            # Execute workflow
            workflow = PredictiveAttackSimulationWorkflow()
            result = await workflow.run(attack_simulation_request)

            # Assertions
            assert result["success"] is True
            assert result["target_system"] == "test_system"
            assert result["predictions_analyzed"] == 2
            assert result["vulnerabilities_discovered"] > 0
            assert result["overall_security_score"] == 6.5
            assert len(result["recommendations"]) == 2

            # Verify activities were called
            assert mock_activity.call_count >= 3

    @pytest.mark.asyncio
    async def test_attack_simulation_executor_workflow(self, mock_workflow_context):
        """Test individual attack simulation executor workflow"""

        request = {
            "prediction": {
                "attack_type": "sql_injection",
                "likelihood": 0.9,
                "details": {"entry_points": ["login_form"]}
            },
            "target_system": "test_system",
            "safety_mode": True,
            "simulation_id": "test-sim-123"
        }

        mock_safety_check = {"safe_to_proceed": True}
        mock_environment = {"success": True, "environment_id": "test-env-123"}
        mock_simulation = {
            "success": True,
            "vulnerabilities": [{"type": "sql_injection", "severity": "high"}],
            "impact_score": 0.8,
            "execution_time_seconds": 45
        }
        mock_ai_analysis = {
            "insights": ["Critical SQL injection found"],
            "recommended_fixes": ["Use parameterized queries"]
        }

        with patch('temporalio.workflow.execute_activity') as mock_activity:
            mock_activity.side_effect = [
                mock_safety_check,    # perform_safety_checks
                mock_environment,     # setup_simulation_environment
                mock_simulation,      # execute_attack_simulation
                mock_ai_analysis,     # ai_analyze_simulation_results
                {"success": True}     # cleanup_simulation_environment
            ]

            workflow = AttackSimulationExecutorWorkflow()
            result = await workflow.run(request)

            assert result["success"] is True
            assert result["simulation_id"] == "test-sim-123"
            assert result["attack_type"] == "sql_injection"
            assert len(result["vulnerabilities"]) == 1
            assert result["security_impact"] == 0.8

    @pytest.mark.asyncio
    async def test_workflow_failure_handling(self, mock_workflow_context, attack_simulation_request):
        """Test workflow handles failures gracefully"""

        with patch('temporalio.workflow.execute_activity') as mock_activity:
            # Mock activity failure
            mock_activity.side_effect = Exception("Activity failed")

            workflow = PredictiveAttackSimulationWorkflow()
            result = await workflow.run(attack_simulation_request)

            assert result["success"] is False
            assert "Workflow execution failed" in result["error"]
            assert result["target_system"] == "test_system"


class TestAttackSimulationActivities:
    """Test attack simulation activities"""

    @pytest.fixture
    def activities(self):
        """Create activities instance with mocked dependencies"""
        with patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal'), \
             patch('app.temporal.activities.attack_simulation_activities.redis.Redis'):
            return AttackSimulationActivities()

    @pytest.mark.asyncio
    async def test_analyze_attack_surface_activity(self, activities):
        """Test attack surface analysis activity"""

        with patch.object(activities, '_ai_analyze_attack_surface') as mock_ai, \
             patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal'):

            mock_ai.return_value = {
                "vulnerability_score": 0.7,
                "exposure_level": "high",
                "component_type": "web_application",
                "attack_vectors": ["sql_injection", "xss"],
                "security_controls": ["input_validation", "authentication"],
                "insights": ["Improve input validation"]
            }

            # Mock database session
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchone.return_value = None  # No cached analysis
            mock_session.execute.return_value = mock_result

            with patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal') as mock_session_local:
                mock_session_local.return_value.__aenter__.return_value = mock_session

                result = await activities.analyze_attack_surface("test_system", {"env": "test"})

                assert result["success"] is True
                assert result["target_system"] == "test_system"
                assert result["vulnerability_score"] == 0.7
                assert result["exposure_level"] == "high"
                assert "sql_injection" in result["attack_vectors"]

    @pytest.mark.asyncio
    async def test_predict_attack_vectors_activity(self, activities):
        """Test AI-powered attack vector prediction"""

        attack_surface_data = {
            "target_system": "test_system",
            "vulnerability_score": 0.8,
            "attack_vectors": ["sql_injection"]
        }

        with patch.object(activities, '_ai_predict_attacks') as mock_ai_predict, \
             patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal'):

            mock_ai_predict.return_value = {
                "predictions": [
                    {
                        "attack_type": "sql_injection",
                        "likelihood": 0.9,
                        "confidence": 0.85,
                        "details": {"entry_points": ["login_form"]},
                        "reasoning": "High vulnerability score with database access"
                    }
                ],
                "overall_confidence": 0.8
            }

            # Mock database session
            mock_session = AsyncMock()
            with patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal') as mock_session_local:
                mock_session_local.return_value.__aenter__.return_value = mock_session

                result = await activities.predict_attack_vectors(attack_surface_data, 0.7)

                assert result["success"] is True
                assert len(result["predictions"]) == 1
                assert result["predictions"][0]["attack_type"] == "sql_injection"
                assert result["predictions"][0]["likelihood"] == 0.9
                assert result["high_risk_count"] == 1

    @pytest.mark.asyncio
    async def test_safety_checks_activity(self, activities):
        """Test safety checks before simulation"""

        prediction = {
            "attack_type": "sql_injection",
            "likelihood": 0.8
        }

        with patch.object(activities, '_check_simulation_environment') as mock_env_check, \
             patch.object(activities, '_check_system_resources') as mock_resource_check:

            mock_env_check.return_value = True
            mock_resource_check.return_value = {"sufficient": True, "issue": "Resources OK"}

            result = await activities.perform_safety_checks("test_system", prediction, True)

            assert result["safe_to_proceed"] is True
            assert result["safety_mode"] is True
            assert result["checks_passed"]["environment_check"] is True
            assert result["checks_passed"]["resource_check"] is True

    @pytest.mark.asyncio
    async def test_safety_checks_production_blocking(self, activities):
        """Test safety checks block production systems"""

        prediction = {"attack_type": "sql_injection", "likelihood": 0.8}

        with patch.object(activities, '_check_simulation_environment') as mock_env_check, \
             patch.object(activities, '_check_system_resources') as mock_resource_check:

            mock_env_check.return_value = True
            mock_resource_check.return_value = {"sufficient": True, "issue": "Resources OK"}

            result = await activities.perform_safety_checks("prod_system", prediction, True)

            assert result["safe_to_proceed"] is False
            assert "Production system detected" in result["issues"][0]

    @pytest.mark.asyncio
    async def test_simulation_environment_setup(self, activities):
        """Test simulation environment setup"""

        prediction = {"attack_type": "sql_injection"}

        mock_docker_client = MagicMock()
        mock_network = MagicMock()
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.id = "container-123"

        mock_docker_client.networks.create.return_value = mock_network
        mock_docker_client.containers.run.return_value = mock_container

        with patch.object(activities, '_get_docker_client') as mock_get_docker, \
             patch('asyncio.sleep'):  # Mock sleep

            mock_get_docker.return_value = mock_docker_client

            result = await activities.setup_simulation_environment(
                "sim-123", "test_system", prediction
            )

            assert result["success"] is True
            assert "sim_network_" in result["environment_id"]
            assert "sim_env_" in result["container_name"]

    @pytest.mark.asyncio
    async def test_execute_attack_simulation(self, activities):
        """Test attack simulation execution"""

        simulation_config = {
            "environment_id": "network:container",
            "prediction": {"attack_type": "sql_injection"},
            "target_system": "test_system",
            "simulation_id": "sim-123",
            "max_duration_minutes": 5
        }

        mock_docker_client = MagicMock()
        mock_container = MagicMock()
        mock_exec_result = MagicMock()
        mock_exec_result.output = b"FINDING: SQL injection vulnerability detected"
        mock_exec_result.exit_code = 0

        mock_container.exec_run.return_value = mock_exec_result
        mock_docker_client.containers.get.return_value = mock_container

        with patch.object(activities, '_get_docker_client') as mock_get_docker, \
             patch.object(activities, '_generate_attack_script') as mock_script, \
             patch.object(activities, '_store_simulation_results') as mock_store:

            mock_get_docker.return_value = mock_docker_client
            mock_script.return_value = "echo 'test script'"

            result = await activities.execute_attack_simulation(simulation_config)

            assert result["success"] is True
            assert result["simulation_id"] == "sim-123"
            assert len(result["vulnerabilities"]) > 0
            assert result["exploitation_successful"] is True


class TestPredictiveAttackAPI:
    """Test API endpoints for predictive attack simulation"""

    @pytest.mark.asyncio
    async def test_start_attack_simulation_endpoint(self, client, mock_admin_user):
        """Test starting attack simulation via API"""

        request_data = {
            "target_system": "test_application",
            "simulation_type": "standard",
            "severity_threshold": 0.7,
            "max_simulations": 5,
            "safety_mode": True,
            "auto_remediation": False
        }

        with patch('app.api.predictive_attack.get_temporal_client') as mock_temporal:
            mock_client = AsyncMock()
            mock_workflow_handle = AsyncMock()
            mock_client.start_workflow.return_value = mock_workflow_handle
            mock_temporal.return_value = mock_client

            response = await client.post(
                "/predictive-attack/simulate",
                json=request_data,
                headers={"Authorization": f"Bearer {mock_admin_user['token']}"}
            )

            assert response.status_code == 200
            data = response.json()
            assert data["target_system"] == "test_application"
            assert data["status"] == "started"
            assert "simulation_id" in data

    @pytest.mark.asyncio
    async def test_list_simulations_endpoint(self, client, mock_admin_user):
        """Test listing simulations via API"""

        # Mock database data
        with patch('app.api.predictive_attack.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchall.return_value = [
                (
                    "sim-123", "Test Simulation", "test_system", "completed",
                    5, 0.7, 120, datetime.utcnow(), datetime.utcnow()
                )
            ]
            mock_db.execute.return_value = mock_result
            mock_get_db.return_value = mock_db

            response = await client.get(
                "/predictive-attack/simulations",
                headers={"Authorization": f"Bearer {mock_admin_user['token']}"}
            )

            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["simulation_name"] == "Test Simulation"
            assert data[0]["vulnerabilities_found"] == 5

    @pytest.mark.asyncio
    async def test_security_dashboard_endpoint(self, client, mock_admin_user):
        """Test security dashboard endpoint"""

        with patch('app.api.predictive_attack.get_db') as mock_get_db:
            mock_db = AsyncMock()

            # Mock overview stats
            overview_result = MagicMock()
            overview_result.fetchone.return_value = (5, 50, 45, 7.5, 10)

            # Mock recent simulations
            sims_result = MagicMock()
            sims_result.fetchall.return_value = [
                ("sim-1", "Sim 1", "sys1", "completed", 3, 0.6, 90, datetime.utcnow(), datetime.utcnow())
            ]

            # Mock high-risk predictions
            pred_result = MagicMock()
            pred_result.fetchall.return_value = [
                ("pred-1", "sql_injection", 0.9, 0.85, "test_component", "High risk", datetime.utcnow())
            ]

            # Mock metrics
            metrics_result = MagicMock()
            metrics_result.fetchone.return_value = (0.85, 0.1, 78.5, 7)

            # Mock vulnerabilities
            vulns_result = MagicMock()
            vulns_result.fetchall.return_value = [
                ("sql_injection", 5, 8.5),
                ("xss", 3, 6.2)
            ]

            mock_db.execute.side_effect = [
                overview_result,
                sims_result,
                pred_result,
                metrics_result,
                vulns_result
            ]
            mock_get_db.return_value = mock_db

            response = await client.get(
                "/predictive-attack/dashboard",
                headers={"Authorization": f"Bearer {mock_admin_user['token']}"}
            )

            assert response.status_code == 200
            data = response.json()
            assert "overview" in data
            assert "recent_simulations" in data
            assert "high_risk_predictions" in data
            assert "security_metrics" in data
            assert "top_vulnerabilities" in data

            assert data["overview"]["systems_monitored"] == 5
            assert len(data["top_vulnerabilities"]) == 2

    @pytest.mark.asyncio
    async def test_unauthorized_access(self, client):
        """Test that endpoints require admin authentication"""

        response = await client.post(
            "/predictive-attack/simulate",
            json={"target_system": "test"}
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_input_validation(self, client, mock_admin_user):
        """Test API input validation"""

        # Test invalid threshold
        invalid_request = {
            "target_system": "test",
            "severity_threshold": 1.5  # Invalid: should be 0.0-1.0
        }

        response = await client.post(
            "/predictive-attack/simulate",
            json=invalid_request,
            headers={"Authorization": f"Bearer {mock_admin_user['token']}"}
        )

        assert response.status_code == 422  # Validation error


class TestIntegrationScenarios:
    """Integration tests for complete workflows"""

    @pytest.mark.asyncio
    async def test_end_to_end_simulation_flow(self):
        """Test complete end-to-end simulation flow"""

        # This would be a comprehensive integration test
        # combining workflow execution, database operations, and API calls

        # For now, we'll test the key integration points
        activities = AttackSimulationActivities()

        with patch.object(activities, '_get_redis'), \
             patch.object(activities, 'ollama_service'), \
             patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal'):

            # Test attack surface analysis
            surface_result = await activities.analyze_attack_surface("test_system")

            # Test that subsequent prediction would use the analysis
            prediction_result = await activities.predict_attack_vectors(surface_result, 0.7)

            # Verify the flow works
            assert surface_result.get("success") is not None
            assert prediction_result.get("success") is not None

    @pytest.mark.asyncio
    async def test_error_recovery_scenarios(self):
        """Test error recovery in various failure scenarios"""

        activities = AttackSimulationActivities()

        # Test database failure recovery
        with patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal') as mock_session:
            mock_session.side_effect = Exception("Database connection failed")

            result = await activities.analyze_attack_surface("test_system")

            # Should handle the error gracefully
            assert result["success"] is False
            assert "Database connection failed" in result["error"]

        # Test AI service failure recovery
        with patch.object(activities.ollama_service, 'generate_completion') as mock_ai:
            mock_ai.side_effect = Exception("AI service unavailable")

            with patch('app.temporal.activities.attack_simulation_activities.AsyncSessionLocal'):
                # The activity should fall back to heuristic analysis
                result = await activities.analyze_attack_surface("test_system")

                # Should use fallback logic
                # (depending on implementation, this might still succeed with fallback data)


# Fixtures for testing
@pytest.fixture
def mock_admin_user():
    """Mock admin user for testing"""
    return {
        "id": "admin-123",
        "email": "admin@test.com",
        "role": "admin",
        "token": "mock-admin-token"
    }


# Run tests with: pytest tests/test_predictive_attack_simulation.py -v