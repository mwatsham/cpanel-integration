from cpanel_admin.redaction import redact


def test_redact_removes_known_secrets_and_sensitive_keys() -> None:
    value = {"token": "abc", "nested": ["prefix abc suffix"], "safe": "ok"}
    assert redact(value, secrets=("abc",)) == {
        "token": "[REDACTED]",
        "nested": ["prefix [REDACTED] suffix"],
        "safe": "ok",
    }


def test_redact_preserves_json_shapes_and_redacts_case_insensitively() -> None:
    value = {
        "Authorization": "cpanel user:secret",
        "items": ({"private_key": "pem"}, 7, True, None),
    }
    assert redact(value, secrets=("secret",)) == {
        "Authorization": "[REDACTED]",
        "items": ({"private_key": "[REDACTED]"}, 7, True, None),
    }
