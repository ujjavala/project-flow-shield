#!/bin/bash

echo "🔧 Setting up FlowShield test users..."

# Wait for the backend to be ready
echo "⏳ Waiting for backend to be ready..."
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo "Waiting for backend..."
    sleep 5
done

echo "✅ Backend is ready!"

# Bootstrap IAM system
echo "🚀 Bootstrapping IAM system..."
curl -s -X POST http://localhost:8000/bootstrap-iam || echo "Bootstrap may have already run"

echo "👥 Creating test users..."

# Create all test users
create_user() {
    local email="$1"
    local username="$2"
    local password="$3"
    local first_name="$4"
    local last_name="$5"

    response=$(curl -s -X POST http://localhost:8000/user/register \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"username\":\"$username\",\"password\":\"$password\",\"first_name\":\"$first_name\",\"last_name\":\"$last_name\"}" 2>/dev/null)

    if echo "$response" | grep -q "success.*true"; then
        echo "✅ Created user: $username ($email)"
    else
        echo "ℹ️  User may already exist: $username ($email)"
    fi
}

# Create test users
create_user "user@temporal-auth.com" "regularuser" "User123!" "Regular" "User"
create_user "analyst@temporal-auth.com" "analyst" "Analyst123!" "Data" "Analyst"
create_user "manager@temporal-auth.com" "manager" "Manager123!" "Team" "Manager"
create_user "moderator@temporal-auth.com" "moderator" "Moderator123!" "Content" "Moderator"
create_user "guest@temporal-auth.com" "guestuser" "Guest123!" "Guest" "User"
create_user "super.admin@temporal-auth.com" "superadmin" "SuperAdmin123!" "Super" "Administrator"

echo ""
echo "🎉 Setup complete! All test users are ready."
echo ""
echo "🌐 Access the application:"
echo "  - User Dashboard: http://localhost:3000"
echo "  - Admin Dashboard: http://localhost:3000/admin/login"
echo "  - Temporal UI: http://localhost:8081"
echo ""
echo "📋 Test with any of the credentials from the README.md"