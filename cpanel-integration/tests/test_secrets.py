import pytest
from cryptography.fernet import Fernet

from cpanel_admin.errors import ConfigError
from cpanel_admin.secrets import SecretCodec


def test_secret_codec_round_trip_without_plaintext_in_ciphertext() -> None:
    codec = SecretCodec(Fernet.generate_key())
    ciphertext = codec.encrypt("api-token-value")
    assert "api-token-value" not in ciphertext
    assert codec.decrypt(ciphertext) == "api-token-value"


def test_missing_master_key_has_safe_error() -> None:
    with pytest.raises(ConfigError, match="CPANEL_ADMIN_FERNET_KEY is required"):
        SecretCodec.from_environment({})


def test_malformed_master_key_has_safe_error() -> None:
    with pytest.raises(ConfigError, match="not a valid Fernet key"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY": "not-a-key"})


def test_wrong_key_does_not_expose_ciphertext() -> None:
    ciphertext = SecretCodec(Fernet.generate_key()).encrypt("secret-token")
    with pytest.raises(ConfigError, match="Unable to decrypt profile token") as error:
        SecretCodec(Fernet.generate_key()).decrypt(ciphertext)
    assert "secret-token" not in str(error.value)
    assert ciphertext not in str(error.value)
