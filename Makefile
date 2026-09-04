.PHONY: demo demo-ai demo-credentials down reset logs ps validate safety audit test test-backend test-frontend

demo:
	docker compose up --build --wait

demo-ai:
	VITE_AI_ENABLED=true RISK_POLICY_AI_SHADOW_ENABLED=true PRIVILEGED_ACCESS_AGENT_AI_ENABLED=true docker compose --profile ai up --build --wait

demo-credentials:
	@docker compose run --rm --no-deps -T migrate cat /run/demo-credentials/users.json

down:
	docker compose down

reset:
	docker compose down --volumes --remove-orphans

logs:
	docker compose logs --follow --tail=200

ps:
	docker compose ps

validate:
	docker compose config --quiet
	docker compose --profile ai config --quiet

safety:
	python scripts/check_repository_safety.py

audit:
	cd backend && python -m pip_audit -r requirements.txt
	cd frontend && npm audit --omit=dev

test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest \
		tests/services/test_email_delivery.py \
		tests/services/test_bff_session_service.py \
		tests/services/test_principal_service.py \
		tests/services/test_oidc_service.py \
		tests/services/test_pkce_service.py \
		tests/services/test_rate_limit_service.py \
		tests/services/test_risk_policy_service.py \
		tests/services/test_privileged_access_advisory_service.py \
		tests/services/test_ai_prompt_privacy.py \
		tests/services/test_security_lab_service.py \
		tests/services/test_session_service.py \
		tests/services/test_strong_auth_service.py \
		tests/api/test_bff_api.py \
		tests/api/test_iam_security.py \
		tests/api/test_oidc_api.py \
		tests/api/test_pkce_api.py \
		tests/api/test_recovery_security.py \
		tests/api/test_risk_policy_login.py \
		tests/api/test_security_lab_api.py \
		tests/api/test_sensitive_error_responses.py \
		tests/temporal/test_privileged_access_workflow.py \
		tests/temporal/test_worker_registration.py \
		tests/evals/test_privileged_access_advisor_evaluation.py \
		tests/evals/test_risk_policy_evaluation.py \
		tests/test_bff_session_middleware.py \
		tests/test_rate_limiting_middleware.py \
		tests/test_safe_logging.py \
		tests/test_utils_security.py \
		--cov=app.services.principal_service \
		--cov=app.services.bff_session_service \
		--cov=app.services.risk_policy_service \
		--cov=app.services.privileged_access_advisory_service \
		--cov-fail-under=74

test-frontend:
	cd frontend && npm run test:coverage
