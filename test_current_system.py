#!/usr/bin/env python3
"""
Comprehensive test script for AI-Powered Authentication System
Tests both basic functionality and AI capabilities when available.
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
TEMPORAL_UI = "http://localhost:8081"
FRONTEND_URL = "http://localhost:3000"

def test_api_health():
    """Test basic API health"""
    print("🔍 Testing API Health...")
    response = requests.get(f"{BASE_URL}/health")
    if response.status_code == 200:
        print("✅ API Health: OK")
        print(f"   Response: {response.json()}")
        return True
    else:
        print("❌ API Health: FAILED")
        return False

def test_ai_health():
    """Test AI endpoints availability"""
    print("🤖 Testing AI Health...")
    try:
        response = requests.get(f"{BASE_URL}/ai/health")
        if response.status_code == 200:
            print("✅ AI Health: OK")
            print(f"   AI Status: {response.json()}")
            return True
        else:
            print("⚠️ AI Health: Not Available (Expected if running basic setup)")
            return False
    except Exception as e:
        print("⚠️ AI Health: Not Available (Expected if running basic setup)")
        return False

def test_basic_registration():
    """Test basic user registration"""
    print("👤 Testing Basic Registration...")
    timestamp = int(time.time())
    test_data = {
        "email": f"test{timestamp}@example.com",
        "password": "TestPass123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = requests.post(f"{BASE_URL}/user/register", json=test_data)
    if response.status_code == 200:
        result = response.json()
        print("✅ Basic Registration: SUCCESS")
        print(f"   User ID: {result.get('user_id')}")
        print(f"   Method: {result.get('method', 'unknown')}")
        if 'fraud_score' in result:
            print(f"   Fraud Score: {result['fraud_score']}")
        return result
    else:
        print("❌ Basic Registration: FAILED")
        print(f"   Error: {response.text}")
        return None

def test_ai_registration():
    """Test AI-enhanced registration"""
    print("🧠 Testing AI-Enhanced Registration...")
    timestamp = int(time.time())
    test_data = {
        "email": f"aitest{timestamp}@example.com",
        "password": "SecurePass123!",
        "first_name": "AI",
        "last_name": "Test",
        "source": "web",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    }
    
    response = requests.post(f"{BASE_URL}/user/register", json=test_data)
    if response.status_code == 200:
        result = response.json()
        print("✅ AI Registration: SUCCESS")
        print(f"   User ID: {result.get('user_id')}")
        
        # Check for AI features
        if 'fraud_score' in result:
            print(f"   🤖 Fraud Score: {result['fraud_score']}")
        if 'ai_insights' in result:
            print(f"   🧠 AI Insights: {result['ai_insights']}")
        if 'correlation_id' in result:
            print(f"   🔗 Correlation ID: {result['correlation_id']}")
            
        return result
    else:
        print("⚠️ AI Registration: Using fallback method")
        print(f"   Response: {response.text}")
        return None

def test_password_analysis():
    """Test AI password analysis"""
    print("🔐 Testing AI Password Analysis...")
    test_data = {
        "password": "My$3cur3P@ssw0rd!2024",
        "user_context": {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com"
        }
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/analyze-password", json=test_data)
        if response.status_code == 200:
            result = response.json()
            print("✅ AI Password Analysis: SUCCESS")
            print(f"   Security Score: {result.get('security_score')}")
            print(f"   Strength Level: {result.get('strength_level')}")
            return True
        else:
            print("⚠️ AI Password Analysis: Not available")
            return False
    except Exception as e:
        print("⚠️ AI Password Analysis: Not available")
        return False

def test_temporal_ui():
    """Test Temporal UI accessibility"""
    print("🌊 Testing Temporal UI...")
    try:
        response = requests.get(TEMPORAL_UI)
        if response.status_code == 200:
            print("✅ Temporal UI: Accessible")
            return True
        else:
            print("❌ Temporal UI: Not accessible")
            return False
    except Exception as e:
        print("❌ Temporal UI: Connection failed")
        return False

def test_frontend():
    """Test frontend accessibility"""
    print("🖥️  Testing Frontend...")
    try:
        response = requests.get(FRONTEND_URL)
        if response.status_code == 200:
            print("✅ Frontend: Accessible")
            return True
        else:
            print("❌ Frontend: Not accessible")
            return False
    except Exception as e:
        print("❌ Frontend: Connection failed")
        return False

def test_redis_connection():
    """Test Redis connection for AI caching"""
    print("⚡ Testing Redis Connection...")
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis: Connected")
        return True
    except Exception as e:
        print("⚠️ Redis: Not connected (install redis-py: pip install redis)")
        return False

def main():
    """Run comprehensive system test"""
    print("🚀 AI-Powered Authentication System Test")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    results = {
        "api_health": test_api_health(),
        "ai_health": test_ai_health(),
        "basic_registration": test_basic_registration() is not None,
        "ai_registration": test_ai_registration() is not None,
        "password_analysis": test_password_analysis(),
        "temporal_ui": test_temporal_ui(),
        "frontend": test_frontend(),
        "redis": test_redis_connection()
    }
    
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    # Basic functionality
    basic_tests = ["api_health", "basic_registration", "temporal_ui", "frontend"]
    basic_passed = sum(1 for test in basic_tests if results[test])
    print(f"🔧 Basic System: {basic_passed}/{len(basic_tests)} tests passed")
    
    # AI functionality  
    ai_tests = ["ai_health", "ai_registration", "password_analysis", "redis"]
    ai_passed = sum(1 for test in ai_tests if results[test])
    print(f"🤖 AI Features: {ai_passed}/{len(ai_tests)} tests passed")
    
    total_passed = sum(results.values())
    total_tests = len(results)
    print(f"📈 Overall: {total_passed}/{total_tests} tests passed")
    
    if basic_passed == len(basic_tests):
        print("\n✅ SYSTEM STATUS: Basic authentication system is fully functional!")
        
        if ai_passed == len(ai_tests):
            print("🤖 AI STATUS: AI-enhanced features are fully operational!")
        elif ai_passed > 0:
            print("⚠️  AI STATUS: Some AI features are working, others may need setup completion")
        else:
            print("⚠️  AI STATUS: AI features not yet available (this is normal during initial setup)")
            
        print("\n🌐 Access Points:")
        print(f"   Frontend: {FRONTEND_URL}")
        print(f"   API Docs: {BASE_URL}/docs")
        print(f"   Temporal UI: {TEMPORAL_UI}")
        print(f"   API Health: {BASE_URL}/health")
        
    else:
        print("\n❌ SYSTEM STATUS: Some basic functionality issues detected")
        
    return results

if __name__ == "__main__":
    main()