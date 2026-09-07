#!/usr/bin/env python3
"""End-to-end detection check: does it find the planted attacks, and stay quiet?

Exits non-zero if either property fails, so CI catches a regression in detection
quality — not just in the code around it.

    BASELINE_FILE=data/clean.csv DATA_FILE=data/attacks.csv \\
        python scripts/check_detection.py
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Config
from app.model import detect, train
from scripts.generate_packets import ATTACKS

# How many of the four planted behaviours must be found. The beacon is the
# weakest signal and depends on window alignment, so three is the gate and four
# is the goal — tighten this if the features improve.
REQUIRED_HITS = 3


def main() -> int:
    config = Config()
    if config.baseline_file is None:
        print("FAIL: set BASELINE_FILE to a known-good capture", file=sys.stderr)
        return 2

    trained = train(config)
    print(f"fitted {trained['algorithm']}/{trained['feature_set']} on "
          f"{trained['rows_trained']} rows from {trained['fitted_on']}, "
          f"threshold {trained['threshold']}")

    sources = {source: name for name, (_, source) in ATTACKS.items()}
    result = detect(config)
    flagged = [row["src_ip"] for row in result["anomalies"]]
    caught = {sources[ip] for ip in flagged if ip in sources}
    false_positives = [ip for ip in flagged if ip not in sources]

    print(f"alerts: {result['count']} of {result['total_packets']} sessions")
    print(f"caught: {sorted(caught) or 'NONE'}")
    print(f"false positives: {len(false_positives)}")

    # The same model must raise nothing on the baseline it was fitted to.
    quiet = detect(replace(config, data_file=config.baseline_file))
    print(f"alerts on clean baseline: {quiet['count']}")

    failures = []
    if len(caught) < REQUIRED_HITS:
        failures.append(f"found only {len(caught)}/{len(ATTACKS)} attacks "
                        f"(need {REQUIRED_HITS})")
    if quiet["count"] > 0:
        failures.append(f"{quiet['count']} alerts on known-good traffic")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
