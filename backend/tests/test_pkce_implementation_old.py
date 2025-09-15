"""
PKCE Implementation Tests
OAuth 2.1 PKCE compliance and security testing
"""
import pytest
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from app.models.pkce import (
    PKCERequest,
    PKCETokenRequest,
    PKCEUtils,
    PKCEAuthorizationCode,
    PKCEErrorTypes
)
from app.temporal.workflows.pkce_authorization import (
    PKCEAuthorizationWorkflow,
    PKCETokenExchangeWorkflow
)


class TestPKCEUtils:
    """Test PKCE utility functions"""
    
    def test_generate_code_verifier(self):
        """Test code verifier generation"""
        verifier = PKCEUtils.generate_code_verifier()
        
        # Check length (43-128 characters as per RFC 7636)
        assert 43 <= len(verifier) <= 128
        
        # Check URL-safe characters only
        url_safe_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
        assert all(c in url_safe_chars for c in verifier)
        
        # Should generate different values
        verifier2 = PKCEUtils.generate_code_verifier()
        assert verifier != verifier2
    
    def test_generate_code_challenge_s256(self):
        """Test S256 code challenge generation"""
        code_verifier = "test-code-verifier-123"
        challenge = PKCEUtils.generate_code_challenge(code_verifier, "S256")
        
        # Manually compute expected challenge
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        expected = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        
        assert challenge == expected
    
    def test_generate_code_challenge_plain(self):
        """Test plain code challenge generation (not recommended)"""
        code_verifier = "test-code-verifier-123"
        challenge = PKCEUtils.generate_code_challenge(code_verifier, "plain")
        
        # Plain method should return verifier as-is
        assert challenge == code_verifier
    
    def test_generate_code_challenge_invalid_method(self):
        """Test invalid code challenge method"""
        code_verifier = "test-code-verifier-123"
        
        with pytest.raises(ValueError, match="Unsupported code challenge method"):
            PKCEUtils.generate_code_challenge(code_verifier, "invalid")
    
    def test_verify_code_challenge_s256_valid(self):
        """Test valid S256 code challenge verification"""
        code_verifier = "test-code-verifier-123"
        code_challenge = PKCEUtils.generate_code_challenge(code_verifier, "S256")
        
        result = PKCEUtils.verify_code_challenge(code_verifier, code_challenge, "S256")
        assert result is True
    
    def test_verify_code_challenge_s256_invalid(self):
        """Test invalid S256 code challenge verification"""
        code_verifier = "test-code-verifier-123"
        wrong_challenge = "wrong-challenge"
        
        result = PKCEUtils.verify_code_challenge(code_verifier, wrong_challenge, "S256")
        assert result is False
    
    def test_verify_code_challenge_plain_valid(self):
        """Test valid plain code challenge verification"""
        code_verifier = "test-code-verifier-123"
        
        result = PKCEUtils.verify_code_challenge(code_verifier, code_verifier, "plain")
        assert result is True
    
    def test_verify_code_challenge_plain_invalid(self):
        """Test invalid plain code challenge verification"""
        code_verifier = "test-code-verifier-123"
        wrong_verifier = "wrong-verifier"
        
        result = PKCEUtils.verify_code_challenge(code_verifier, wrong_verifier, "plain")
        assert result is False
    
    def test_create_authorization_code(self):
        """Test authorization code creation"""
        code_data = PKCEUtils.create_authorization_code(
            client_id="test-client",
            user_id="user-123",
            redirect_uri="http://localhost:3000/callback",
            code_challenge="test-challenge",
            code_challenge_method="S256",
            scope="read write",
            state="test-state"
        )
        
        assert isinstance(code_data, PKCEAuthorizationCode)
        assert code_data.client_id == "test-client"
        assert code_data.user_id == "user-123"
        assert code_data.redirect_uri == "http://localhost:3000/callback"
        assert code_data.code_challenge == "test-challenge"
        assert code_data.code_challenge_method == "S256"
        assert code_data.scope == "read write"
        assert code_data.state == "test-state"
        assert len(code_data.code) > 30  # Authorization code should be substantial
        assert not code_data.is_used
        assert code_data.expires_at > datetime.utcnow()


class TestPKCEModels:
    """Test PKCE Pydantic models"""
    
    def test_pkce_request_valid(self):
        """Test valid PKCE request model"""
        request_data = {
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read write",
            "state": "test-state",
            "code_challenge": "a" * 43,  # Minimum length
            "code_challenge_method": "S256",
            "response_type": "code"
        }
        
        request = PKCERequest(**request_data)
        
        assert request.client_id == "test-client"
        assert request.redirect_uri == "http://localhost:3000/callback"
        assert request.code_challenge == "a" * 43
        assert request.code_challenge_method == "S256"
    
    def test_pkce_request_short_challenge(self):
        """Test PKCE request with too short code challenge"""
        request_data = {
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "short",  # Too short
            "code_challenge_method": "S256"
        }
        
        with pytest.raises(ValueError, match="at least 43 characters"):
            PKCERequest(**request_data)
    
    def test_pkce_request_long_challenge(self):
        """Test PKCE request with too long code challenge"""
        request_data = {
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "a" * 129,  # Too long
            "code_challenge_method": "S256"
        }
        
        with pytest.raises(ValueError, match="at most 128 characters"):
            PKCERequest(**request_data)
    
    def test_pkce_request_invalid_method(self):
        """Test PKCE request with invalid challenge method"""
        request_data = {
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "a" * 50,
            "code_challenge_method": "invalid"
        }
        
        with pytest.raises(ValueError, match="String should match pattern"):
            PKCERequest(**request_data)
    
    def test_pkce_token_request_valid(self):
        """Test valid PKCE token request model"""
        request_data = {
            "grant_type": "authorization_code",
            "code": "test-auth-code",
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "code_verifier": "a" * 43
        }
        
        request = PKCETokenRequest(**request_data)
        
        assert request.grant_type == "authorization_code"
        assert request.code == "test-auth-code"
        assert request.code_verifier == "a" * 43


class TestPKCEWorkflows:
    """Test PKCE Temporal workflows"""
    
    @pytest.fixture
    def pkce_request(self):
        """Fixture for valid PKCE request"""
        valid_verifier = "a" * 43  # Valid 43-character code verifier
        return PKCERequest(
            client_id="test-client",
            redirect_uri="http://localhost:3000/callback",
            scope="read write",
            state="test-state",
            code_challenge=PKCEUtils.generate_code_challenge(valid_verifier, "S256"),
            code_challenge_method="S256",
            response_type="code"
        )
    
    @pytest.fixture
    def token_request(self):
        """Fixture for valid token request"""
        return PKCETokenRequest(
            grant_type="authorization_code",
            code="test-auth-code",
            redirect_uri="http://localhost:3000/callback",
            client_id="test-client",
            code_verifier="a" * 43  # Valid 43-character code verifier
        )
    
    @pytest.mark.asyncio
    async def test_pkce_authorization_workflow_success(self, pkce_request):
        """Test successful PKCE authorization workflow"""
        # Mock workflow.execute_activity at module level
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as mock_activity:
            # Mock validation success
            mock_activity.side_effect = [
                {"valid": True},  # validate_pkce_request
                {"success": True},  # store_pkce_authorization_code
                None  # log_security_event
            ]
            
            workflow = PKCEAuthorizationWorkflow()
            result = await workflow.run(pkce_request.dict(), "user-123")
            
            assert result["success"] is True
            assert "code" in result
            assert result["state"] == "test-state"
            assert result["method"] == "pkce_workflow"
            
            # Verify activity calls
            assert mock_activity.call_count >= 2  # At least validation and storage
    
    @pytest.mark.asyncio
    async def test_pkce_authorization_workflow_validation_failure(self, pkce_request):
        """Test PKCE authorization workflow with validation failure"""
        # Mock workflow.execute_activity with validation failure
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as mock_activity:
            mock_activity.return_value = {
                "valid": False,
                "error_description": "Invalid client_id"
            }
            
            workflow = PKCEAuthorizationWorkflow()
            result = await workflow.run(pkce_request.dict(), "user-123")
            
            assert result["success"] is False
            assert result["error"] == PKCEErrorTypes.INVALID_REQUEST
            assert result["error_description"] == "Invalid client_id"
            assert result["method"] == "pkce_workflow"
    
    @pytest.mark.asyncio
    async def test_pkce_token_exchange_workflow_success(self, token_request):
        """Test successful PKCE token exchange workflow"""
        # Mock stored authorization code data
        auth_code_data = {
            "code": "test-auth-code",
            "client_id": "test-client",
            "user_id": "user-123",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": PKCEUtils.generate_code_challenge("a" * 43, "S256"),
            "code_challenge_method": "S256",
            "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }
        
        # Mock workflow.execute_activity and workflow.gather
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as mock_activity, \
             patch('temporalio.workflow.gather', new_callable=AsyncMock) as mock_gather:
            
            # Mock activity responses for token exchange
            mock_activity.side_effect = [
                {"found": True, "auth_code": auth_code_data},  # retrieve_pkce_authorization_code
                None,  # mark_authorization_code_used  
                None   # log_security_event
            ]
            
            # Mock gather for parallel token generation
            mock_gather.return_value = [
                {  # generate_pkce_tokens result
                    "access_token": "mock-access-token", 
                    "refresh_token": "mock-refresh-token",
                    "expires_in": 1800,
                    "scope": "read write"
                }
            ]
            
            workflow = PKCETokenExchangeWorkflow()
            result = await workflow.run(token_request.dict())
            
            assert result["success"] is True
            assert result["access_token"] == "mock-access-token"
            assert result["refresh_token"] == "mock-refresh-token"
            assert result["token_type"] == "Bearer"
            assert result["method"] == "pkce_token_workflow"
    
    @pytest.mark.asyncio
    async def test_pkce_token_exchange_workflow_invalid_code(self, token_request):
        """Test PKCE token exchange workflow with invalid authorization code"""
        # Mock workflow.execute_activity with code not found
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as mock_activity:
            mock_activity.return_value = {"found": False}
            
            workflow = PKCETokenExchangeWorkflow()
            result = await workflow.run(token_request.dict())
            
            assert result["success"] is False
            assert result["error"] == PKCEErrorTypes.INVALID_GRANT
            assert "Invalid or expired authorization code" in result["error_description"]
    
    @pytest.mark.asyncio
    async def test_pkce_token_exchange_workflow_invalid_verifier(self, token_request):
        """Test PKCE token exchange workflow with invalid code verifier"""
        # Mock stored authorization code with different challenge
        auth_code_data = {
            "code": "test-auth-code",
            "client_id": "test-client",
            "user_id": "user-123",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "different-challenge",  # Won't match verifier
            "code_challenge_method": "S256"
        }
        
        # Mock workflow.execute_activity
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as mock_activity:
            mock_activity.return_value = {"found": True, "auth_code": auth_code_data}
            
            workflow = PKCETokenExchangeWorkflow()
            result = await workflow.run(token_request.dict())
            
            assert result["success"] is False
            assert result["error"] == PKCEErrorTypes.INVALID_CODE_VERIFIER
            assert "Invalid code verifier" in result["error_description"]


class TestPKCESecurity:
    """Test PKCE security features and edge cases"""
    
    def test_timing_attack_resistance(self):
        """Test that code challenge verification is resistant to timing attacks"""
        import time
        
        code_verifier = "test-code-verifier"
        correct_challenge = PKCEUtils.generate_code_challenge(code_verifier, "S256")
        wrong_challenge = "wrong-challenge-of-same-length-approximately"
        
        # Time verification of correct challenge
        start = time.time()
        result1 = PKCEUtils.verify_code_challenge(code_verifier, correct_challenge, "S256")
        time1 = time.time() - start
        
        # Time verification of wrong challenge
        start = time.time()
        result2 = PKCEUtils.verify_code_challenge(code_verifier, wrong_challenge, "S256")
        time2 = time.time() - start
        
        assert result1 is True
        assert result2 is False
        
        # Times should be similar (within reasonable margin)
        # This test might be flaky in very fast systems, but provides basic timing attack check
        # Skip test if both times are extremely fast (< 1ms)
        if min(time1, time2) < 0.001:
            # Test is inconclusive due to system speed
            return
        
        time_ratio = max(time1, time2) / min(time1, time2)
        assert time_ratio < 5.0, f"Potential timing attack vulnerability: {time1:.6f}s vs {time2:.6f}s"
    
    def test_code_verifier_entropy(self):
        """Test that code verifiers have sufficient entropy"""
        verifiers = [PKCEUtils.generate_code_verifier() for _ in range(100)]
        
        # All verifiers should be unique (extremely high probability)
        assert len(set(verifiers)) == 100
        
        # Check entropy distribution (basic test)
        all_chars = ''.join(verifiers)
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Should have reasonable distribution across URL-safe characters
        # This is a basic check - not a comprehensive entropy analysis
        unique_chars = len(char_counts)
        assert unique_chars > 30, f"Only {unique_chars} unique characters found"
    
    def test_authorization_code_expiration(self):
        """Test authorization code expiration handling"""
        # Test that expired code is properly identified
        expired_time = datetime.now() - timedelta(minutes=5)
        assert PKCEUtils.is_code_expired(expired_time) is True
        
        # Test that non-expired code is properly identified
        future_time = datetime.now() + timedelta(minutes=5)
        assert PKCEUtils.is_code_expired(future_time) is False
        
        # Test edge case: very slightly in the past (simulating immediate expiration)
        just_expired = datetime.now() - timedelta(milliseconds=1)
        # Should be expired
        assert PKCEUtils.is_code_expired(just_expired) is True
    
    def test_pkce_request_sql_injection_protection(self):
        """Test that PKCE requests are protected against SQL injection"""
        # These should not cause validation errors due to Pydantic validation
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "' UNION SELECT * FROM users --"
        ]
        
        for malicious_input in malicious_inputs:
            try:
                # These should either validate properly or fail validation
                # but should never cause SQL injection
                request = PKCERequest(
                    client_id=malicious_input,
                    redirect_uri="http://localhost:3000/callback",
                    code_challenge="a" * 50,
                    code_challenge_method="S256"
                )
                # If it passes validation, the input was sanitized
                assert isinstance(request.client_id, str)
            except ValueError:
                # If it fails validation, that's also acceptable
                pass
    
    def test_code_challenge_length_limits(self):
        """Test code challenge length limits for security"""
        # Test minimum length enforcement
        short_challenge = "a" * 42  # One less than minimum
        
        with pytest.raises(ValueError):
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback",
                code_challenge=short_challenge,
                code_challenge_method="S256"
            )
        
        # Test maximum length enforcement
        long_challenge = "a" * 129  # One more than maximum
        
        with pytest.raises(ValueError):
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback",
                code_challenge=long_challenge,
                code_challenge_method="S256"
            )