#!/usr/bin/env python3

import requests
import json
from jose import jwt  # PyJWT alternative for decoding

def decode_token(token):
    """Decode JWT token to see user info"""
    try:
        # Decode without verification (for debugging)
        decoded = jwt.get_unverified_claims(token)
        return decoded
    except Exception as e:
        return f"Error decoding: {e}"

def test_user_info(email, password):
    """Get user info from successful login"""
    payload = {"email": email, "password": password}

    try:
        response = requests.post("http://localhost:8000/user/login", json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")

            # Decode token to see user details
            decoded = decode_token(token)
            return True, decoded
        else:
            return False, response.json().get("detail", "Unknown error")
    except Exception as e:
        return False, str(e)

def main():
    users = [
        ("super.admin@temporal-auth.com", "SuperAdmin123!"),
        ("manager@temporal-auth.com", "Manager123!"),
        ("moderator@temporal-auth.com", "Moderator123!"),
        ("analyst@temporal-auth.com", "Analyst123!"),
        ("user@temporal-auth.com", "User123!"),
        ("guest@temporal-auth.com", "Guest123!"),
    ]

    print("USER ROLE ANALYSIS")
    print("=" * 50)

    for email, password in users:
        success, result = test_user_info(email, password)
        if success:
            print(f"\n✅ {email}:")
            if isinstance(result, dict):
                print(f"   Token payload: {json.dumps(result, indent=4)}")
            else:
                print(f"   Token info: {result}")
        else:
            print(f"\n❌ {email}: {result}")

if __name__ == "__main__":
    main()