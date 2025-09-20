#!/usr/bin/env python3

import requests
import json

def test_login(email, password, login_type="user"):
    """Test user login and return access token if successful"""
    url = f"http://localhost:8000/{login_type}/login" if login_type == "admin/auth" else f"http://localhost:8000/{login_type}/login"

    payload = {
        "email": email,
        "password": password
    }

    if login_type == "admin/auth":
        payload["remember_me"] = False

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return True, data.get("access_token", "")
        else:
            return False, response.json().get("detail", "Unknown error")
    except Exception as e:
        return False, str(e)

def test_admin_dashboard(token):
    """Test admin dashboard access"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("http://localhost:8000/admin/", headers=headers, timeout=10)

        if response.status_code == 200:
            return True, "Admin dashboard accessible"
        elif response.status_code == 403:
            return False, "Admin privileges required"
        else:
            data = response.json() if response.headers.get('content-type') == 'application/json' else response.text
            return False, str(data)
    except Exception as e:
        return False, str(e)

def main():
    # Test users with their intended access levels
    users = [
        ("super.admin@temporal-auth.com", "SuperAdmin123!", "Should have admin access"),
        ("admin@temporal-auth.com", "Admin123!", "Should have admin access"),
        ("manager@temporal-auth.com", "Manager123!", "Should have admin access"),
        ("moderator@temporal-auth.com", "Moderator123!", "Should NOT have admin access"),
        ("analyst@temporal-auth.com", "Analyst123!", "Should NOT have admin access"),
        ("user@temporal-auth.com", "User123!", "Should NOT have admin access"),
        ("guest@temporal-auth.com", "Guest123!", "Should NOT have admin access"),
    ]

    print("=" * 80)
    print("TESTING USER ACCESS PATTERNS")
    print("=" * 80)

    for email, password, expected in users:
        print(f"\n🔍 Testing: {email}")
        print(f"   Expected: {expected}")

        # Test regular login
        success, result = test_login(email, password, "user")
        if success:
            print(f"   ✅ Regular login: SUCCESS")
            token = result

            # Test admin dashboard access
            admin_success, admin_result = test_admin_dashboard(token)
            if admin_success:
                print(f"   ✅ Admin dashboard: ACCESSIBLE")
            else:
                print(f"   ❌ Admin dashboard: {admin_result}")

        else:
            print(f"   ❌ Regular login: {result}")

        # Test admin login
        admin_login_success, admin_login_result = test_login(email, password, "admin/auth")
        if admin_login_success:
            print(f"   ✅ Admin login: SUCCESS")
        else:
            print(f"   ❌ Admin login: {admin_login_result}")

if __name__ == "__main__":
    main()