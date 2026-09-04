"""CLI safety and CI exit-code tests."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.security_lab_cli import main


def test_cli_rejects_non_allowlisted_target_before_network_call(capsys):
    with patch("app.services.security_lab_service.settings.SECURITY_LAB_ALLOWED_BASE_URLS", ["http://localhost:8000"]), \
         patch("app.security_lab_cli.httpx.Client") as client:
        exit_code = main(["list", "--base-url", "https://example.com", "--token", "token"])

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out)["error"] == "unsafe_target"
    client.assert_not_called()


def test_cli_returns_zero_only_for_passing_run(capsys):
    response = SimpleNamespace(
        is_success=True,
        json=lambda: {"status": "passed", "evidence": {"passed": True}},
    )
    http_client = MagicMock()
    http_client.__enter__.return_value.post.return_value = response
    with patch("app.services.security_lab_service.settings.SECURITY_LAB_ALLOWED_BASE_URLS", ["http://localhost:8000"]), \
         patch("app.security_lab_cli.httpx.Client", return_value=http_client):
        exit_code = main([
            "run", "pkce-code-replay", "--base-url", "http://localhost:8000", "--token", "token", "--seed", "3"
        ])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"