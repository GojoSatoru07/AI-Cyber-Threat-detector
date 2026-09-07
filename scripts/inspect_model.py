#!/usr/bin/env python3
"""Inspect a trained model and optionally score an ad-hoc packet.

    python scripts/inspect_model.py
    python scripts/inspect_model.py --score 192.168.1.10 10.0.0.5 6 1200
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Config
from app.features import FEATURE_COLUMNS, ip_to_int


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-m", "--model", type=Path, default=None,
                        help="path to model.pkl (default: from config)")
    parser.add_argument("--score", nargs=4, metavar=("SRC_IP", "DST_IP", "PROTOCOL", "LENGTH"),
                        help="score a single packet")
    args = parser.parse_args()

    model_path = args.model or Config().model_file
    if not Path(model_path).exists():
        sys.exit(f"No model at {model_path}. Train one first (POST /api/train).")

    model = joblib.load(model_path)
    print(f"Model:      {type(model).__name__}")
    print(f"Path:       {model_path}")
    print(f"Estimators: {model.n_estimators}")
    print(f"Contamination: {model.contamination}")
    print(f"Features:   {getattr(model, 'feature_names_in_', FEATURE_COLUMNS)}")

    if args.score:
        src, dst, proto, length = args.score
        # Build a named DataFrame so sklearn matches columns by name, not order.
        row = pd.DataFrame([[ip_to_int(src), ip_to_int(dst), int(proto), int(length)]],
                           columns=FEATURE_COLUMNS)
        score = float(model.decision_function(row)[0])
        verdict = "ANOMALY" if model.predict(row)[0] == -1 else "normal"
        print(f"\nPacket {src} -> {dst} proto={proto} len={length}")
        print(f"  decision_function: {score:.6f}")
        print(f"  verdict:           {verdict}")


if __name__ == "__main__":
    main()
