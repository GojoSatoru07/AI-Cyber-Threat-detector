"""Training, persistence and scoring for the anomaly detector."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .config import BASE_DIR, Config
from .features import build_features, load_packets
from .integrity import sign, signing_key, verify
from .sessions import build_flow_features, flow_matrix

logger = logging.getLogger(__name__)


class ModelNotTrained(RuntimeError):
    """Raised when a prediction is requested before a model exists on disk."""


BUNDLE_VERSION = 1

# Without a clean baseline the model is fitted on the very data it will score,
# so the lowest training score *is* the most anomalous row: a 0.0 quantile can
# never fire. Fall back to a small quota and say so.
FALLBACK_QUANTILE = 0.02


def _calibration_quantile(config: Config) -> float:
    if config.calibration_quantile is not None:
        return config.calibration_quantile
    if config.baseline_file is not None:
        return 0.0
    logger.warning(
        "No BASELINE_FILE set: fitting on the traffic under inspection, so "
        "alerts are a %.0f%% quota rather than a calibrated judgement. Point "
        "BASELINE_FILE at known-good traffic for real detection.",
        FALLBACK_QUANTILE * 100,
    )
    return FALLBACK_QUANTILE


def load_for_model(config: Config, path: Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (reportable rows, numeric matrix) for the configured feature set.

    In flow mode the reportable row *is* a session — one source over one time
    window — which is also the unit an analyst can act on. In packet mode it is
    the packet.
    """
    df = load_packets(path or config.data_file)
    if config.feature_set == "flow":
        flows = build_flow_features(df, config.window_seconds)
        return flows, flow_matrix(flows)
    return df, build_features(df)


def build_estimator(config: Config):
    """Construct the configured detector.

    IsolationForest splits on raw thresholds, so it needs no scaling. LOF is
    distance-based and is meaningless unscaled here — packet_length spans a far
    wider range than protocol — so it is wrapped in a scaling pipeline.
    `novelty=True` is what makes a LOF model persistable and reusable at all.
    """
    if config.algorithm == "lof":
        return Pipeline([
            ("scale", StandardScaler()),
            ("lof", LocalOutlierFactor(
                n_neighbors=20,
                # LOF has no "auto" mode; fall back to the conventional quota.
                contamination=0.05 if config.contamination == "auto" else config.contamination,
                novelty=True,
            )),
        ])
    return IsolationForest(
        n_estimators=config.n_estimators,
        contamination=config.contamination,
        random_state=config.random_state,
    )


def train(config: Config) -> dict:
    """Fit the detector and calibrate its alert threshold.

    Fits on `baseline_file` when one is configured, otherwise on the dataset
    itself. Fitting on the traffic under inspection is the default only because
    a first-run demo has nothing else; it is methodologically weak, because an
    attack present in the training data pulls the notion of "normal" toward
    itself. The response says which file was used.
    """
    fit_path = config.baseline_file or config.data_file
    _, features = load_for_model(config, fit_path)
    model = build_estimator(config)
    model.fit(features)

    # Calibrate on the training scores: raw scores are only comparable within a
    # single fitted model, so a hard-coded threshold would drift with the data.
    training_scores = model.decision_function(features)
    quantile = _calibration_quantile(config)
    threshold = float(np.quantile(training_scores, quantile))

    bundle = {
        "version": BUNDLE_VERSION,
        "model": model,
        "algorithm": config.algorithm,
        "feature_set": config.feature_set,
        "window_seconds": config.window_seconds,
        "feature_columns": list(features.columns),
        "threshold": threshold,
        "fitted_on": _public_path(fit_path),
        "rows_trained": len(features),
    }

    config.ensure_dirs()
    joblib.dump(bundle, config.model_file)
    sign(config.model_file, signing_key(config.model_file.parent))
    logger.info("Trained %s/%s on %d rows from %s (threshold %.6f), saved to %s",
                config.algorithm, config.feature_set, len(features), fit_path,
                threshold, config.model_file)

    summary = {
        "message": "Model trained successfully.",
        "algorithm": config.algorithm,
        "feature_set": config.feature_set,
        "rows_trained": len(features),
        "features": list(features.columns),
        "contamination": config.contamination,
        "threshold": round(threshold, 6),
        "calibration_quantile": quantile,
        "fitted_on": _public_path(fit_path),
        "fitted_on_baseline": config.baseline_file is not None,
        "model_path": _public_path(config.model_file),
    }
    if config.algorithm == "iforest":
        summary["n_estimators"] = config.n_estimators
    return summary


def load_model(config: Config):
    if not Path(config.model_file).exists():
        raise ModelNotTrained(
            "No trained model found. POST to /api/train first."
        )
    # Verify before loading, never after: joblib.load() executes the pickle, so
    # checking afterwards would be checking a file that already ran.
    verify(config.model_file, signing_key(config.model_file.parent))
    bundle = joblib.load(config.model_file)

    if not isinstance(bundle, dict) or bundle.get("version") != BUNDLE_VERSION:
        raise ModelNotTrained(
            "Stored model is from an older version of this app. Retrain it."
        )
    if bundle["feature_set"] != config.feature_set:
        raise ModelNotTrained(
            f"Stored model was fitted on '{bundle['feature_set']}' features but "
            f"FEATURE_SET is '{config.feature_set}'. Retrain, or switch back."
        )
    return bundle


def detect(config: Config, limit: int | None = None) -> dict:
    """Score every packet and return the rows flagged as anomalous.

    Rows are sorted by anomaly score (most anomalous first) so a truncated
    response still shows the packets that matter most.
    """
    bundle = load_model(config)
    raw, features = load_for_model(config)
    scores = bundle["model"].decision_function(features)
    predictions = _flag(scores, bundle, config)

    results = raw.copy()
    results["anomaly_score"] = scores
    anomalies = results[predictions == -1].sort_values("anomaly_score")

    total_flagged = len(anomalies)
    cap = config.max_results if limit is None else min(limit, config.max_results)
    truncated = total_flagged > cap

    return {
        "anomalies": _to_records(anomalies.head(cap)),
        "count": total_flagged,
        "returned": min(total_flagged, cap),
        "truncated": truncated,
        "total_packets": len(results),
    }


# IANA protocol numbers worth naming in the UI.
PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

SCORE_BINS = 24


def summarize(config: Config) -> dict:
    """Aggregates for the dashboard: score distribution and protocol split.

    Computed server-side so the browser never has to hold the full dataset,
    and so the numbers on the charts are the same ones the model produced.
    """
    bundle = load_model(config)
    raw, features = load_for_model(config)

    scores = bundle["model"].decision_function(features)
    flagged = _flag(scores, bundle, config) == -1

    frame = pd.DataFrame({"score": scores, "flagged": flagged})
    if config.feature_set == "flow":
        frame["group"] = raw["src_ip"].to_numpy()
        breakdown_label, unit = "source", "sessions"
    else:
        frame["group"] = features["protocol"].astype(int).to_numpy()
        breakdown_label, unit = "protocol", "packets"

    return {
        "unit": unit,
        "breakdown_label": breakdown_label,
        "total_packets": len(frame),
        "flagged": int(frame["flagged"].sum()),
        "flag_rate": round(float(frame["flagged"].mean()), 4),
        "min_score": round(float(frame["score"].min()), 6),
        "max_score": round(float(frame["score"].max()), 6),
        "score_histogram": _score_histogram(frame),
        "protocols": _group_breakdown(frame, breakdown_label),
    }


def _score_histogram(frame: pd.DataFrame) -> list:
    """Bin anomaly scores, splitting each bin into normal vs flagged counts."""
    # Equal-width bins over the observed range. `include_lowest` only works
    # with a bin *count* — with an IntervalIndex pandas ignores it, and the
    # single lowest-scoring packet (the most anomalous one) falls out of the
    # left-open first interval and disappears from the chart.
    binned = pd.cut(frame["score"], bins=SCORE_BINS, include_lowest=True)
    grouped = frame.groupby([binned, "flagged"], observed=False).size().unstack(fill_value=0)

    bins = []
    for interval, row in grouped.iterrows():
        bins.append({
            "start": round(float(interval.left), 6),
            "end": round(float(interval.right), 6),
            "normal": int(row.get(False, 0)),
            "flagged": int(row.get(True, 0)),
        })
    return bins


def _group_breakdown(frame: pd.DataFrame, label: str) -> list:
    """Normal/flagged counts per group (protocol, or source in flow mode)."""
    grouped = frame.groupby(["group", "flagged"], observed=True).size().unstack(fill_value=0)
    rows = []
    for key, row in grouped.iterrows():
        normal, flagged = int(row.get(False, 0)), int(row.get(True, 0))
        name = PROTOCOL_NAMES.get(key, f"proto {key}") if label == "protocol" else str(key)
        rows.append({
            "protocol": int(key) if label == "protocol" else None,
            "name": name,
            "normal": normal,
            "flagged": flagged,
            "total": normal + flagged,
        })
    # Rank by flagged count, then by what share of the group's activity was
    # flagged: "1 of 1 sessions" is a stronger signal than "1 of 40".
    rows.sort(key=lambda r: (r["flagged"], r["flagged"] / r["total"]), reverse=True)
    return rows


def _flag(scores, bundle: dict, config: Config):
    """Anomalous/normal per row, judged against the calibrated threshold.

    An explicit SCORE_THRESHOLD wins; otherwise the threshold stored with the
    model is used. Either way the decision is absolute — clean traffic produces
    no alerts, instead of the fixed quota `predict()` would always emit.
    """
    threshold = config.score_threshold
    if threshold is None:
        threshold = bundle["threshold"]
    return np.where(scores < threshold, -1, 1)


def status(config: Config) -> dict:
    """Describe what the app currently has on disk, for the UI to display."""
    model_path = Path(config.model_file)
    data_path = Path(config.data_file)
    return {
        "model_trained": model_path.exists(),
        "model_path": _public_path(model_path),
        "dataset_present": data_path.exists(),
        "dataset_path": _public_path(data_path),
        "trained_at": (
            pd.Timestamp(model_path.stat().st_mtime, unit="s", tz="UTC").isoformat()
            if model_path.exists()
            else None
        ),
    }


def _public_path(path: Path) -> str:
    """A path safe to hand to a client: relative to the project root if possible.

    The API is unauthenticated, so absolute paths in responses would disclose
    the host account name and directory layout. Logs keep the full path.
    """
    try:
        return str(Path(path).relative_to(BASE_DIR))
    except ValueError:
        return Path(path).name


def _to_records(df: pd.DataFrame) -> list:
    """JSON-safe records.

    Flask's encoder chokes on numpy scalars (int64/float64), so round-trip
    through pandas' own JSON writer, which normalises them to Python types.
    """
    return json.loads(df.to_json(orient="records"))
