"""Baseline fitting and threshold calibration.

The central property: a detector must be silent on traffic that contains
nothing wrong. A quota-based detector cannot be, by construction.
"""
from dataclasses import replace

from app import model as model_service
from tests.conftest import write_sessions


def _clean_baseline(tmp_path):
    """The same shape of traffic as the fixture, minus the scanner."""
    path = tmp_path / "baseline.csv"
    write_sessions(path)
    lines = path.read_text().splitlines()
    kept = [lines[0]] + [row for row in lines[1:] if "192.168.0.66" not in row]
    path.write_text("\n".join(kept) + "\n")
    return path


def test_without_baseline_it_falls_back_to_a_quota(flow_config, flow_dataset):
    result = model_service.train(flow_config)
    assert result["fitted_on_baseline"] is False
    assert result["calibration_quantile"] == model_service.FALLBACK_QUANTILE


def test_baseline_training_reports_its_source(flow_config, flow_dataset, tmp_path):
    config = replace(flow_config, baseline_file=_clean_baseline(tmp_path))
    result = model_service.train(config)

    assert result["fitted_on_baseline"] is True
    assert result["fitted_on"].endswith("baseline.csv")
    assert result["calibration_quantile"] == 0.0


def test_baseline_trained_model_is_silent_on_clean_traffic(flow_config, tmp_path):
    """No alarm when nothing is wrong — the property a quota cannot provide."""
    baseline = _clean_baseline(tmp_path)
    config = replace(flow_config, baseline_file=baseline, data_file=baseline)
    model_service.train(config)

    assert model_service.detect(config)["count"] == 0


def test_baseline_trained_model_still_flags_the_scanner(flow_config, flow_dataset, tmp_path):
    config = replace(flow_config, baseline_file=_clean_baseline(tmp_path))
    model_service.train(config)

    flagged = {row["src_ip"] for row in model_service.detect(config)["anomalies"]}
    assert "192.168.0.66" in flagged


def test_threshold_is_stored_with_the_model(flow_config, flow_dataset):
    trained = model_service.train(flow_config)
    bundle = model_service.load_model(flow_config)

    assert bundle["threshold"] == trained["threshold"] or abs(
        bundle["threshold"] - trained["threshold"]
    ) < 1e-6
    assert bundle["feature_set"] == "flow"
    assert bundle["feature_columns"]


def test_explicit_threshold_overrides_calibration(flow_config, flow_dataset):
    model_service.train(flow_config)
    silent = replace(flow_config, score_threshold=-99.0)
    assert model_service.detect(silent)["count"] == 0

    noisy = replace(flow_config, score_threshold=99.0)
    assert model_service.detect(noisy)["count"] == model_service.detect(noisy)["total_packets"]


def test_feature_set_mismatch_is_refused(flow_config, flow_dataset):
    """A flow model must not silently score packet features, or vice versa."""
    model_service.train(flow_config)
    mismatched = replace(flow_config, feature_set="packet")

    try:
        model_service.detect(mismatched)
    except model_service.ModelNotTrained as exc:
        assert "feature" in str(exc).lower() or "FEATURE_SET" in str(exc)
    else:
        raise AssertionError("expected a refusal on feature-set mismatch")
