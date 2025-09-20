#!/bin/bash

echo "========================================================================"
echo "TESTING USER ACCESS PATTERNS"
echo "========================================================================"

# Function to test user login and admin access
test_user() {
  local email="$1"
  local password="$2"
  local expected="$3"

  echo ""
  echo "🔍 Testing: $email"
  echo "   Expected: $expected"

  # Create JSON payload using cat with heredoc
  json_payload=$(cat <<EOF
{"email": "$email", "password": "$password"}
EOF
)

  admin_json_payload=$(cat <<EOF
{"email": "$email", "password": "$password", "remember_me": false}
EOF
)

  # Test regular user login
  response=$(curl -s -X POST http://localhost:8000/user/login \
    -H "Content-Type: application/json" \
    -d "$json_payload")

  if echo "$response" | grep -q "access_token"; then
    echo "   ✅ Regular login: SUCCESS"

    # Extract access token
    access_token=$(echo "$response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

    # Test admin dashboard access using regular token
    dashboard_response=$(curl -s -X GET http://localhost:8000/admin/ \
      -H "Authorization: Bearer $access_token")

    if echo "$dashboard_response" | grep -q '"dashboard_data"'; then
      echo "   ✅ Admin dashboard: ACCESSIBLE"
    elif echo "$dashboard_response" | grep -q "Admin privileges required"; then
      echo "   ❌ Admin dashboard: Admin privileges required"
    else
      echo "   ❌ Admin dashboard: $(echo "$dashboard_response" | head -c 60)..."
    fi
  else
    echo "   ❌ Regular login: $(echo "$response" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4 | head -c 50)"
  fi

  # Test admin login
  admin_response=$(curl -s -X POST http://localhost:8000/admin/auth/login \
    -H "Content-Type: application/json" \
    -d "$admin_json_payload")

  if echo "$admin_response" | grep -q "access_token"; then
    echo "   ✅ Admin login: SUCCESS"
  else
    admin_error=$(echo "$admin_response" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4 | head -c 50)
    echo "   ❌ Admin login: $admin_error"
  fi
}

# Test all users
test_user "super.admin@temporal-auth.com" "SuperAdmin123!" "Should have admin access"
test_user "admin@temporal-auth.com" "Admin123!" "Should have admin access"
test_user "manager@temporal-auth.com" "Manager123!" "Should have admin access"
test_user "moderator@temporal-auth.com" "Moderator123!" "Should NOT have admin access"
test_user "analyst@temporal-auth.com" "Analyst123!" "Should NOT have admin access"
test_user "user@temporal-auth.com" "User123!" "Should NOT have admin access"
test_user "guest@temporal-auth.com" "Guest123!" "Should NOT have admin access"

echo ""
echo "========================================================================"
echo "TEST COMPLETE"
echo "========================================================================"