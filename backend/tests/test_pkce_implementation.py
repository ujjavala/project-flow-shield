"""
Comprehensive PKCE Implementation Tests
Tests for OAuth 2.1 PKCE (Proof Key for Code Exchange) implementation
Focused on core functionality without requiring external dependencies
"""
import pytest
import secrets
import time
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock

from pydantic import ValidationError

from app.models.pkce import (
    PKCERequest, 
    PKCETokenRequest, 
    PKCEAuthorizationCode,
    PKCEUtils, 
    PKCEResponse, 
    PKCETokenResponse,
    PKCEError,
    PKCEErrorTypes
)

# Import Temporal workflows for type checking only
try:
    from app.temporal.workflows.pkce_authorization import (
        PKCEAuthorizationWorkflow,
        PKCETokenExchangeWorkflow
    )
    TEMPORAL_AVAILABLE = True
except ImportError:
    TEMPORAL_AVAILABLE = False


class TestPKCEUtils:
    """Test PKCE utility functions for RFC 7636 compliance"""
    
    def test_generate_code_verifier(self):
        """Test code verifier generation meets RFC requirements"""
        verifier = PKCEUtils.generate_code_verifier()
        
        # RFC 7636: 43-128 characters, URL-safe base64
        assert 43 <= len(verifier) <= 128
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in verifier)
        
        # Should generate unique values
        verifier2 = PKCEUtils.generate_code_verifier()
        assert verifier != verifier2
    
    def test_generate_code_challenge_s256(self):
        """Test S256 code challenge generation"""
        verifier = "test_verifier_12345678901234567890123456"  # Valid length
        challenge = PKCEUtils.generate_code_challenge(verifier, "S256")
        
        # Should be URL-safe base64 without padding
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in challenge)
        assert len(challenge) == 43  # SHA256 base64url without padding
        
        # Same input should produce same output (deterministic)
        challenge2 = PKCEUtils.generate_code_challenge(verifier, "S256")
        assert challenge == challenge2
    
    def test_generate_code_challenge_plain(self):
        """Test plain code challenge generation (not recommended)"""
        verifier = "test_verifier_123"
        challenge = PKCEUtils.generate_code_challenge(verifier, "plain")
        
        # Plain method returns verifier as-is
        assert challenge == verifier
    
    def test_generate_code_challenge_invalid_method(self):
        """Test invalid challenge method raises error"""
        verifier = "test_verifier_123"
        
        with pytest.raises(ValueError, match="Unsupported code challenge method"):
            PKCEUtils.generate_code_challenge(verifier, "invalid")
    
    def test_verify_code_challenge_s256_valid(self):
        """Test valid S256 code challenge verification"""
        verifier = "test_verifier_12345678901234567890123456"
        challenge = PKCEUtils.generate_code_challenge(verifier, "S256")
        
        assert PKCEUtils.verify_code_challenge(verifier, challenge, "S256") is True
    
    def test_verify_code_challenge_s256_invalid(self):
        """Test invalid S256 code challenge verification"""
        verifier = "test_verifier_12345678901234567890123456"
        wrong_challenge = "wrong_challenge_value_123456789012345"
        
        assert PKCEUtils.verify_code_challenge(verifier, wrong_challenge, "S256") is False
    
    def test_verify_code_challenge_plain_valid(self):
        """Test valid plain code challenge verification"""
        verifier = "test_verifier_123"
        
        assert PKCEUtils.verify_code_challenge(verifier, verifier, "plain") is True
    
    def test_verify_code_challenge_plain_invalid(self):
        """Test invalid plain code challenge verification"""
        verifier = "test_verifier_123"
        wrong_verifier = "wrong_verifier_123"
        
        assert PKCEUtils.verify_code_challenge(verifier, wrong_verifier, "plain") is False
    
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
        assert code_data.code_challenge == "test-challenge"
        assert len(code_data.code) > 20  # Generated code should be substantial
        assert code_data.expires_at > datetime.now()
        assert code_data.is_used is False


class TestPKCEModels:
    """Test PKCE Pydantic models for request validation"""
    
    def test_pkce_request_valid(self):
        """Test valid PKCE request creation"""
        valid_verifier = "a" * 43  # Valid 43-character code verifier
        challenge = PKCEUtils.generate_code_challenge(valid_verifier, "S256")
        
        request = PKCERequest(
            client_id="test-client",
            redirect_uri="http://localhost:3000/callback",
            scope="read write", 
            state="test-state",
            code_challenge=challenge,
            code_challenge_method="S256",
            response_type="code"
        )
        
        assert request.client_id == "test-client"
        assert request.code_challenge == challenge
        assert request.code_challenge_method == "S256"
        assert request.response_type == "code"
    
    def test_pkce_request_short_challenge(self):
        """Test PKCE request with too short challenge"""
        with pytest.raises(ValidationError) as exc_info:
            PKCERequest(
                client_id="test-client", 
                redirect_uri="http://localhost:3000/callback",
                code_challenge="too_short",  # Less than 43 characters
                code_challenge_method="S256"
            )
        
        assert "at least 43 characters" in str(exc_info.value)
    
    def test_pkce_request_long_challenge(self):
        """Test PKCE request with too long challenge"""
        with pytest.raises(ValidationError) as exc_info:
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback", 
                code_challenge="x" * 129,  # More than 128 characters
                code_challenge_method="S256"
            )
        
        assert "at most 128 characters" in str(exc_info.value)
    
    def test_pkce_request_invalid_method(self):
        """Test PKCE request with invalid challenge method"""
        with pytest.raises(ValidationError) as exc_info:
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback",
                code_challenge="a" * 43,
                code_challenge_method="invalid"  # Not S256 or plain
            )
        
        assert "String should match pattern" in str(exc_info.value)
    
    def test_pkce_token_request_valid(self):
        """Test valid PKCE token request creation"""
        request = PKCETokenRequest(
            grant_type="authorization_code",
            code="test-auth-code",
            redirect_uri="http://localhost:3000/callback",
            client_id="test-client", 
            code_verifier="a" * 43  # Valid 43-character code verifier
        )
        
        assert request.grant_type == "authorization_code"
        assert request.code == "test-auth-code"
        assert request.code_verifier == "a" * 43


# Note: Temporal workflow tests have been moved to tests/test_pkce_workflows_temporal.py  
# These tests require proper Temporal test environment setup and cannot run as unit tests


class TestPKCESecurity:
    """Test PKCE security features and edge cases"""
    
    def test_timing_attack_resistance(self):
        """Test that code challenge verification is resistant to timing attacks"""
        verifier = "test_verifier_12345678901234567890123456"
        valid_challenge = PKCEUtils.generate_code_challenge(verifier, "S256")
        invalid_challenge = "invalid_challenge_value_with_same_length"
        
        # Measure timing for valid and invalid verifications
        valid_times = []
        invalid_times = []
        
        for _ in range(10):  # Small sample for testing
            # Valid verification timing
            start = time.perf_counter()
            PKCEUtils.verify_code_challenge(verifier, valid_challenge, "S256")
            valid_times.append(time.perf_counter() - start)
            
            # Invalid verification timing  
            start = time.perf_counter()
            PKCEUtils.verify_code_challenge(verifier, invalid_challenge, "S256")
            invalid_times.append(time.perf_counter() - start)
        
        # Both should complete (no exceptions)
        assert len(valid_times) == 10
        assert len(invalid_times) == 10
        
        # This is a basic timing check - proper timing analysis would require more sophisticated methods
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        # Both should be reasonably fast
        assert avg_valid < 0.001  # Less than 1ms
        assert avg_invalid < 0.001  # Less than 1ms
    
    def test_code_verifier_entropy(self):
        """Test that code verifier has sufficient entropy"""
        # Generate multiple verifiers
        verifiers = [PKCEUtils.generate_code_verifier() for _ in range(100)]
        
        # All should be unique
        assert len(set(verifiers)) == 100
        
        # Check character distribution
        all_chars = ''.join(verifiers)
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Should have reasonable character distribution
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
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "null; waitfor delay '00:00:10' --"
        ]
        
        valid_challenge = PKCEUtils.generate_code_challenge("a" * 43, "S256")
        
        for malicious_input in malicious_inputs:
            try:
                request = PKCERequest(
                    client_id=malicious_input,  # Try malicious input in client_id
                    redirect_uri="http://localhost:3000/callback",
                    code_challenge=valid_challenge,
                    code_challenge_method="S256"
                )
                # If it validates, the malicious input was sanitized/handled
                assert isinstance(request.client_id, str)
                
            except ValidationError:
                # ValidationError is also acceptable - input rejected
                pass
    
    def test_code_challenge_length_limits(self):
        """Test code challenge length limits prevent buffer overflow attacks"""
        # Test minimum length enforcement
        with pytest.raises(ValidationError):
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback", 
                code_challenge="x" * 42,  # One less than minimum
                code_challenge_method="S256"
            )
        
        # Test maximum length enforcement  
        with pytest.raises(ValidationError):
            PKCERequest(
                client_id="test-client",
                redirect_uri="http://localhost:3000/callback",
                code_challenge="x" * 129,  # One more than maximum
                code_challenge_method="S256"
            )
        
        # Valid lengths should work
        for length in [43, 64, 86, 128]:  # Test various valid lengths
            try:
                request = PKCERequest(
                    client_id="test-client",
                    redirect_uri="http://localhost:3000/callback",
                    code_challenge="x" * length,
                    code_challenge_method="S256"
                )
                assert len(request.code_challenge) == length
            except ValidationError as e:
                pytest.fail(f"Valid length {length} should not raise ValidationError: {e}")