import json
import sys

import requests

from password_hygiene_checker import (
    check_pwned,
    check_strength,
    load_common_passwords,
    main,
    render_json,
    render_report,
)

COMMON = load_common_passwords()


def test_weak_password_scores_low():
    result = check_strength("123456", COMMON)
    assert result["verdict"] == "Weak"
    assert result["score"] < 40


def test_strong_password_scores_high():
    result = check_strength("K7#mQ9$vLx2!pR", COMMON)
    assert result["verdict"] == "Strong"
    assert result["score"] >= 70


def test_common_password_is_flagged():
    result = check_strength("password", COMMON)
    assert result["is_common"] is True
    assert result["verdict"] == "Weak"


class _FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError("error")


def test_check_pwned_returns_count_on_match(monkeypatch):
    password = "K7#mQ9$vLx2!pR"
    import hashlib

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    suffix = sha1[5:]
    fake_body = f"{suffix}:42\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"

    def fake_get(url, timeout=5.0):
        return _FakeResponse(fake_body)

    monkeypatch.setattr(requests, "get", fake_get)
    assert check_pwned(password) == 42


def test_check_pwned_returns_zero_when_no_match(monkeypatch):
    def fake_get(url, timeout=5.0):
        return _FakeResponse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2")

    monkeypatch.setattr(requests, "get", fake_get)
    assert check_pwned("K7#mQ9$vLx2!pR") == 0


def test_check_pwned_returns_none_on_network_error(monkeypatch):
    def fake_get(url, timeout=5.0):
        raise requests.exceptions.ConnectionError("no network")

    monkeypatch.setattr(requests, "get", fake_get)
    assert check_pwned("K7#mQ9$vLx2!pR") is None


def test_report_never_contains_the_password():
    secret = "K7#mQ9$vLx2!pR"
    strength = check_strength(secret, COMMON)
    report = render_report(strength, pwned_count=0)
    assert secret not in report


def test_json_output_is_valid_and_well_formed():
    strength = check_strength("K7#mQ9$vLx2!pR", COMMON)
    output = render_json(strength, pwned_count=42)
    payload = json.loads(output)
    assert payload["verdict"] == "Strong"
    assert payload["breach_check"]["pwned_count"] == 42
    assert payload["breach_check"]["status"] == "checked"


def test_json_output_never_contains_the_password():
    secret = "K7#mQ9$vLx2!pR"
    strength = check_strength(secret, COMMON)
    output = render_json(strength, pwned_count=None)
    assert secret not in output
    payload = json.loads(output)
    assert payload["breach_check"]["status"] == "skipped"
    assert payload["breach_check"]["pwned_count"] is None


def run_main(monkeypatch, tmp_path, password, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["password_hygiene_checker.py", "--password", password, "--output", out, "--skip-pwned-check"] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_weak_exits_nonzero_for_weak_password(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "123456", ["--fail-on-weak"]) == 1


def test_fail_on_weak_exits_zero_for_strong_password(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "K7#mQ9$vLx2!pR", ["--fail-on-weak"]) == 0


def test_no_fail_flags_always_exits_zero_even_for_weak_password(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "123456", []) == 0


def test_fail_on_pwned_exits_nonzero_when_breach_found(monkeypatch, tmp_path):
    import hashlib

    password = "K7#mQ9$vLx2!pR"
    suffix = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[5:]

    def fake_get(url, timeout=5.0):
        return _FakeResponse(f"{suffix}:99")

    monkeypatch.setattr(requests, "get", fake_get)
    out = str(tmp_path / "out.md")
    argv = ["password_hygiene_checker.py", "--password", password, "--output", out, "--fail-on-pwned"]
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 1
