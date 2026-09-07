"""Integrity protection for persisted models.

`joblib.load` unpickles, and unpickling executes arbitrary code chosen by
whoever wrote the file. For a tool whose whole job is detecting attacks, an
attacker-writable `models/` directory being remote code execution is not an
acceptable footnote.

The mitigation is a keyed MAC. Every save writes `<model>.sig` containing an
HMAC-SHA256 of the model bytes; every load recomputes it and refuses to
unpickle anything that does not match. An attacker who can write the model file
but not the key cannot get their pickle executed.

This does not make loading *foreign* models safe — nothing does. It ensures the
process only ever unpickles bytes it wrote itself.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

SIGNATURE_SUFFIX = ".sig"
_KEY_ENV = "MODEL_SIGNING_KEY"
_KEY_FILE = "model_signing.key"


class IntegrityError(RuntimeError):
    """Raised when a model file fails signature verification."""


def signing_key(models_dir: Path) -> bytes:
    """The HMAC key, from the environment or a generated per-install file.

    Generating and storing a key next to the models is weaker than a real
    secret manager, but it still defeats the actual threat here: a process that
    drops a malicious pickle into models/ without also being able to read the
    key file cannot get it loaded.
    """
    from_env = os.getenv(_KEY_ENV)
    if from_env:
        return from_env.encode()

    key_path = Path(models_dir) / _KEY_FILE
    if key_path.exists():
        return key_path.read_bytes()

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    # Create with owner-only permissions rather than writing then chmod-ing,
    # which would leave a window where the key is world-readable.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("Generated a new model signing key at %s", key_path)
    return key


def signature_path(model_file: Path) -> Path:
    return Path(str(model_file) + SIGNATURE_SUFFIX)


def sign(model_file: Path, key: bytes) -> Path:
    digest = hmac.new(key, Path(model_file).read_bytes(), hashlib.sha256).hexdigest()
    path = signature_path(model_file)
    path.write_text(digest)
    return path


def verify(model_file: Path, key: bytes) -> None:
    """Raise IntegrityError unless the model matches its signature."""
    path = signature_path(model_file)
    if not path.exists():
        raise IntegrityError(
            "Model file has no signature. Refusing to unpickle it — retrain to "
            "produce a signed model."
        )
    expected = hmac.new(key, Path(model_file).read_bytes(), hashlib.sha256).hexdigest()
    # compare_digest, not ==: a plain comparison leaks the correct prefix
    # through timing.
    if not hmac.compare_digest(expected, path.read_text().strip()):
        raise IntegrityError(
            "Model signature does not match. The file was modified or written "
            "by something else. Refusing to unpickle it."
        )
