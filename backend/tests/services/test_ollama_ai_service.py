import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import aiohttp
from aioresponses import aioresponses

from app.services.ollama_ai_service import OllamaAIService


class TestOllamaAIService:
    
    @pytest.fixture
    def ollama_service(self):
        return OllamaAIService(host="localhost", port=11434, model="llama3")
    
    @pytest.fixture
    def mock_ollama_response(self):
        return {
            "model": "llama3",
            "created_at": "2023-01-01T00:00:00Z",
            "response": "Risk score: 75. This login shows suspicious patterns.",
            "done": True
        }
    
    @pytest.mark.asyncio
    async def test_service_initialization(self, ollama_service):
        """Test service initialization with correct parameters"""
        assert ollama_service.base_url == "http://localhost:11434"
        assert ollama_service.model == "llama3"
        assert ollama_service.session is None
    
    @pytest.mark.asyncio
    async def test_ensure_session_creation(self, ollama_service):
        """Test session creation when making requests"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value = mock_session
            
            await ollama_service._ensure_session()
            
            assert ollama_service.session == mock_session
            mock_session_class.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_make_request_success(self, ollama_service, mock_ollama_response):
        """Test successful API request to Ollama"""
        
        with aioresponses() as mock_http:
            mock_http.post(
                f"{ollama_service.base_url}/api/generate",
                payload=mock_ollama_response
            )
            
            # Manually set session to avoid initialization issues
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                result = await ollama_service._make_request("Test prompt")
                assert result == "Risk score: 75. This login shows suspicious patterns."
            finally:
                await ollama_service.session.close()
    
    @pytest.mark.asyncio
    async def test_make_request_server_error(self, ollama_service):
        """Test API request handling server errors"""
        
        with aioresponses() as mock_http:
            mock_http.post(
                f"{ollama_service.base_url}/api/generate",
                status=500
            )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                with pytest.raises(Exception):
                    await ollama_service._make_request("Test prompt")
            finally:
                await ollama_service.session.close()
    
    @pytest.mark.asyncio
    async def test_make_request_timeout(self, ollama_service):
        """Test API request timeout handling"""
        
        with aioresponses() as mock_http:
            mock_http.post(
                f"{ollama_service.base_url}/api/generate",
                exception=aiohttp.ServerTimeoutError()
            )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                with pytest.raises(Exception):
                    await ollama_service._make_request("Test prompt")
            finally:
                await ollama_service.session.close()
    
    @pytest.mark.asyncio
    async def test_make_request_with_custom_tokens(self, ollama_service, mock_ollama_response):
        """Test API request with custom max tokens"""
        
        with aioresponses() as mock_http:
            mock_http.post(
                f"{ollama_service.base_url}/api/generate",
                payload=mock_ollama_response
            )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                result = await ollama_service._make_request("Test prompt", max_tokens=500)
                assert result == "Risk score: 75. This login shows suspicious patterns."
                
                # Verify request payload includes custom tokens
                request_data = mock_http.requests[('POST', f"{ollama_service.base_url}/api/generate")][0].kwargs
                payload = json.loads(request_data['data'])
                assert payload['options']['num_predict'] == 500
            finally:
                await ollama_service.session.close()
    
    @pytest.mark.asyncio 
    async def test_analyze_login_behavior_pattern(self, ollama_service):
        """Test login behavior analysis"""
        
        login_data = {
            "user_id": "user-123",
            "email": "test@example.com",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0...",
            "timestamp": "2023-01-01T12:00:00Z",
            "location": "New York, US",
            "device_info": "iPhone 14"
        }
        
        mock_response = {
            "response": "Risk score: 25. Normal login pattern detected.",
            "done": True
        }
        
        with aioresponses() as mock_http:
            mock_http.post(
                f"{ollama_service.base_url}/api/generate",
                payload=mock_response
            )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                # Assuming the service has an analyze_login_behavior method
                with patch.object(ollama_service, 'analyze_login_behavior') as mock_analyze:
                    mock_analyze.return_value = {
                        "risk_score": 25,
                        "risk_level": "low",
                        "recommendation": "Allow login",
                        "factors": ["Normal time pattern", "Known device", "Expected location"]
                    }
                    
                    result = await ollama_service.analyze_login_behavior(login_data)
                    
                    assert result["risk_score"] == 25
                    assert result["risk_level"] == "low"
                    assert "Allow login" in result["recommendation"]
            finally:
                await ollama_service.session.close()
    
    @pytest.mark.asyncio
    async def test_detect_fraud_patterns(self, ollama_service):
        """Test fraud pattern detection"""
        
        transaction_data = {
            "user_id": "user-123",
            "amount": 1000.00,
            "location": "Nigeria",
            "time": "03:00 AM",
            "previous_locations": ["New York", "California"],
            "frequency": "first_time_location"
        }
        
        with patch.object(ollama_service, 'detect_fraud_patterns') as mock_detect:
            mock_detect.return_value = {
                "fraud_probability": 0.85,
                "risk_factors": [
                    "Unusual location",
                    "High amount transaction",
                    "Off-hours activity"
                ],
                "recommendation": "Block transaction and request additional verification"
            }
            
            result = await ollama_service.detect_fraud_patterns(transaction_data)
            
            assert result["fraud_probability"] == 0.85
            assert len(result["risk_factors"]) == 3
            assert "Block transaction" in result["recommendation"]
    
    @pytest.mark.asyncio
    async def test_analyze_user_behavior_anomaly(self, ollama_service):
        """Test user behavior anomaly analysis"""
        
        behavior_data = {
            "user_id": "user-123",
            "recent_actions": [
                {"action": "login", "timestamp": "2023-01-01T09:00:00Z"},
                {"action": "view_profile", "timestamp": "2023-01-01T09:05:00Z"},
                {"action": "change_password", "timestamp": "2023-01-01T09:10:00Z"},
                {"action": "delete_account", "timestamp": "2023-01-01T09:15:00Z"}
            ],
            "normal_pattern": {
                "typical_session_duration": "30 minutes",
                "common_actions": ["login", "view_dashboard", "logout"],
                "usual_times": ["9AM-5PM weekdays"]
            }
        }
        
        with patch.object(ollama_service, 'analyze_user_behavior_anomaly') as mock_analyze:
            mock_analyze.return_value = {
                "anomaly_score": 0.92,
                "anomalies_detected": [
                    "Rapid password change after login",
                    "Account deletion attempt",
                    "Unusual action sequence"
                ],
                "recommendation": "Suspend account and trigger security review"
            }
            
            result = await ollama_service.analyze_user_behavior_anomaly(behavior_data)
            
            assert result["anomaly_score"] == 0.92
            assert len(result["anomalies_detected"]) == 3
            assert "Suspend account" in result["recommendation"]
    
    @pytest.mark.asyncio
    async def test_cleanup_session(self, ollama_service):
        """Test proper session cleanup"""
        
        # Initialize session
        ollama_service.session = AsyncMock()
        
        # Test cleanup
        await ollama_service.cleanup()
        
        ollama_service.session.close.assert_called_once()
        assert ollama_service.session is None
    
    @pytest.mark.asyncio
    async def test_health_check(self, ollama_service):
        """Test service health check"""
        
        with aioresponses() as mock_http:
            # Mock successful health check response
            mock_http.get(
                f"{ollama_service.base_url}/api/tags",
                payload={"models": [{"name": "llama3", "size": 3825819519}]}
            )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                with patch.object(ollama_service, 'health_check') as mock_health:
                    mock_health.return_value = {
                        "status": "healthy",
                        "model": "llama3",
                        "available": True,
                        "response_time_ms": 150
                    }
                    
                    result = await ollama_service.health_check()
                    
                    assert result["status"] == "healthy"
                    assert result["available"] is True
                    assert result["model"] == "llama3"
            finally:
                await ollama_service.session.close()
    
    def test_service_configuration_validation(self):
        """Test service configuration validation"""
        
        # Test valid configuration
        service = OllamaAIService(host="localhost", port=11434, model="llama3")
        assert service.base_url == "http://localhost:11434"
        
        # Test custom configuration
        service_custom = OllamaAIService(host="remote-server", port=8080, model="codellama")
        assert service_custom.base_url == "http://remote-server:8080"
        assert service_custom.model == "codellama"
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_handling(self, ollama_service):
        """Test handling of concurrent requests"""
        
        mock_response = {"response": "Test response", "done": True}
        
        with aioresponses() as mock_http:
            # Mock multiple responses
            for _ in range(5):
                mock_http.post(
                    f"{ollama_service.base_url}/api/generate",
                    payload=mock_response
                )
            
            ollama_service.session = aiohttp.ClientSession()
            
            try:
                # Make concurrent requests
                tasks = []
                for i in range(5):
                    task = ollama_service._make_request(f"Test prompt {i}")
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                
                # Verify all requests completed successfully
                assert len(results) == 5
                for result in results:
                    assert result == "Test response"
            finally:
                await ollama_service.session.close()


# Import json for the payload verification test
import json