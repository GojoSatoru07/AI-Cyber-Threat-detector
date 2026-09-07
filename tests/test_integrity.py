"""Model files are unpickled, so they must be proven to be ours before loading."""
import joblib
import pytest

from app import model as model_service
from app.integrity import IntegrityError, signature_path, signing_key


def test_training_writes_a_signature(config, dataset):
    model_service.train(config)
    assert signature_path(config.model_file).exists()


def test_signed_model_loads(config, dataset):
    model_service.train(config)
    assert model_service.load_model(config) is not None


def test_tampered_model_is_refused(config, dataset):
    """The attack this exists to stop: swapping in someone else's pickle."""
    model_service.train(config)
    hostile = config.model_file.parent / "hostile.pkl"
    joblib.dump({"not": "a model"}, hostile)
    config.model_file.write_bytes(hostile.read_bytes())

    with pytest.raises(IntegrityError, match="does not match"):
        model_service.load_model(config)


def test_unsigned_model_is_refused(config, dataset):
    model_service.train(config)
    signature_path(config.model_file).unlink()

    with pytest.raises(IntegrityError, match="no signature"):
        model_service.load_model(config)


def test_signature_from_a_different_key_is_refused(config, dataset, monkeypatch):
    model_service.train(config)
    monkeypatch.setenv("MODEL_SIGNING_KEY", "an-attacker-controlled-key")

    with pytest.raises(IntegrityError):
        model_service.load_model(config)


def test_generated_key_is_owner_only(config, dataset):
    model_service.train(config)
    key_file = config.model_file.parent / "model_signing.key"
    assert key_file.exists()
    assert oct(key_file.stat().st_mode)[-3:] == "600"


def test_key_is_stable_across_calls(config):
    first = signing_key(config.model_file.parent)
    assert signing_key(config.model_file.parent) == first


def test_api_reports_tampering(client, dataset):
    client.post("/api/train")
    config = client.application.config["APP_CONFIG"]
    config.model_file.write_bytes(b"clearly not a pickle")

    response = client.get("/api/anomalies")
    assert response.status_code == 409
    assert "signature" in response.get_json()["error"].lower()
