"""Application configuration, driven by environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _contamination(raw: str) -> float | str:
    if raw.strip().lower() == "auto":
        return "auto"
    value = float(raw)
    if not 0.0 < value <= 0.5:
        raise ValueError("CONTAMINATION must be in (0, 0.5] or 'auto'.")
    return value


def _env_path(name: str, default: str) -> Path:
    """Resolve an env-provided path relative to the project root."""
    value = Path(os.getenv(name, default)).expanduser()
    return value if value.is_absolute() else BASE_DIR / value


@dataclass(frozen=True)
class Config:
    """Runtime settings. Every field can be overridden by an env var."""

    # default_factory, not a direct call: a plain call would freeze the value at
    # import time, so an env var set afterwards (or by a test) would be ignored.
    data_file: Path = field(default_factory=lambda: _env_path("DATA_FILE", "data/packets.csv"))
    model_file: Path = field(default_factory=lambda: _env_path("MODEL_FILE", "models/model.pkl"))

    # "packet" scores each packet in isolation; "flow" aggregates packets into
    # (source, time window) sessions first, which is what makes scans, sweeps
    # and beaconing detectable at all. See README "Detection altitude".
    feature_set: str = field(default_factory=lambda: os.getenv("FEATURE_SET", "flow").lower())
    window_seconds: int = field(default_factory=lambda: int(os.getenv("WINDOW_SECONDS", "300")))

    # Detection algorithm: "iforest" (default) or "lof". Benchmarked in
    # scripts/benchmark_models.py — IsolationForest wins on globally-extreme
    # anomalies, LOF on contextual ones. See README.
    algorithm: str = field(default_factory=lambda: os.getenv("ALGORITHM", "iforest").lower())

    # IsolationForest hyper-parameters.
    n_estimators: int = field(default_factory=lambda: int(os.getenv("N_ESTIMATORS", "100")))
    # "auto" leaves the score offset at scikit-learn's data-independent
    # convention, which is what makes SCORE_THRESHOLD mean the same thing across
    # datasets. A numeric value re-anchors the offset to a quota of the training
    # data, and a fixed threshold then drifts with whatever you trained on.
    contamination: float | str = field(
        default_factory=lambda: _contamination(os.getenv("CONTAMINATION", "auto"))
    )
    random_state: int = field(default_factory=lambda: int(os.getenv("RANDOM_STATE", "42")))

    # Optional baseline capture to fit on. Training on the same traffic you are
    # inspecting teaches the model that the attack is part of normal — the
    # single most important thing to get right here. Point this at known-good
    # traffic and DATA_FILE at the traffic under suspicion.
    baseline_file: Path | None = field(
        default_factory=lambda: (
            _env_path("BASELINE_FILE", "") if os.getenv("BASELINE_FILE") else None
        )
    )

    # Alert threshold, calibrated at training time as this quantile of the
    # training scores. 0.0 means "nothing in the baseline may alarm". Scores are
    # only comparable within one fitted model, so calibrating against the
    # baseline is what makes the number mean anything.
    # Left unset, this resolves at training time: 0.0 with a baseline (nothing
    # in known-good traffic may alarm), or a small quota without one, because
    # fitting and scoring the same file makes 0.0 mathematically silent.
    calibration_quantile: float | None = field(
        default_factory=lambda: (
            float(os.environ["CALIBRATION_QUANTILE"])
            if os.getenv("CALIBRATION_QUANTILE")
            else None
        )
    )

    # Manual override of the calibrated threshold.
    score_threshold: float | None = field(
        default_factory=lambda: (
            float(os.environ["SCORE_THRESHOLD"]) if os.getenv("SCORE_THRESHOLD") else None
        )
    )

    # Cap on how many anomaly rows a single API response may return.
    max_results: int = field(default_factory=lambda: int(os.getenv("MAX_RESULTS", "500")))

    debug: bool = field(
        default_factory=lambda: os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    )

    def __post_init__(self) -> None:
        if self.feature_set not in {"packet", "flow"}:
            raise ValueError(
                f"Unknown FEATURE_SET {self.feature_set!r}. Expected 'packet' or 'flow'."
            )
        if self.calibration_quantile is not None and not 0.0 <= self.calibration_quantile < 1.0:
            raise ValueError("CALIBRATION_QUANTILE must be in [0.0, 1.0).")
        if self.window_seconds < 1:
            raise ValueError("WINDOW_SECONDS must be at least 1.")
        if self.algorithm not in {"iforest", "lof"}:
            raise ValueError(
                f"Unknown ALGORITHM {self.algorithm!r}. Expected 'iforest' or 'lof'."
            )

    def ensure_dirs(self) -> None:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.model_file.parent.mkdir(parents=True, exist_ok=True)
