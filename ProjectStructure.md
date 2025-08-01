# OAuth2 Authentication System with Temporal.io

## Project Structure

```
oauth2-temporal-auth/
├── README.md
├── docker-compose.yml
├── .env.example
├── .gitignore
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   └── oauth.py
│   │   ├── database/
│   │   │   ├── __init__.py
│   │   │   ├── connection.py
│   │   │   └── migrations.py
│   │   ├── temporal/
│   │   │   ├── __init__.py
│   │   │   ├── client.py
│   │   │   ├── activities/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── email.py
│   │   │   │   ├── user.py
│   │   │   │   └── auth.py
│   │   │   └── workflows/
│   │   │       ├── __init__.py
│   │   │       ├── user_registration.py
│   │   │       ├── password_reset.py
│   │   │       └── email_verification.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── auth_service.py
│   │   │   ├── user_service.py
│   │   │   └── email_service.py
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   ├── user.py
│   │   │   └── oauth.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── security.py
│   │       ├── validators.py
│   │       └── exceptions.py
│   └── worker.py
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── package-lock.json
│   ├── public/
│   │   ├── index.html
│   │   └── favicon.ico
│   └── src/
│       ├── index.js
│       ├── App.js
│       ├── components/
│       │   ├── Auth/
│       │   │   ├── Login.js
│       │   │   ├── Register.js
│       │   │   ├── ResetPassword.js
│       │   │   └── VerifyEmail.js
│       │   ├── Dashboard/
│       │   │   └── Dashboard.js
│       │   └── Common/
│       │       ├── Header.js
│       │       └── Footer.js
│       ├── services/
│       │   ├── api.js
│       │   └── auth.js
│       ├── hooks/
│       │   └── useAuth.js
│       ├── context/
│       │   └── AuthContext.js
│       └── styles/
│           └── App.css
└── temporal/
    └── docker-compose.temporal.yml
```

## Key Features

- **OAuth2 Authentication Flow**: Complete implementation with authorization code flow
- **User Management**: Registration, login, password reset with email verification
- **Temporal Workflows**: Email sending, user verification, password reset workflows
- **Database**: PostgreSQL with proper schema and migrations
- **Email Integration**: SMTP email service for notifications
- **Security**: JWT tokens, password hashing, rate limiting
- **Frontend**: React-based UI with authentication flows
- **Docker**: Fully containerized application

## Tech Stack

- **Backend**: FastAPI (Python)
- **Frontend**: React.js
- **Database**: PostgreSQL
- **Workflow Engine**: Temporal.io
- **Authentication**: OAuth2 + JWT
- **Email**: SMTP (configurable provider)
- **Containerization**: Docker & Docker Compose