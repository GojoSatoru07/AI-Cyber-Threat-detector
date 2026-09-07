# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt      # runtime deps + pytest + scapy

python scripts/generate_packets.py                                  # capture with planted attacks
python scripts/generate_packets.py -o data/baseline.csv --no-attacks
BASELINE_FILE=data/baseline.csv python run.py                       # 127.0.0.1:5000

BASELINE_FILE=data/baseline.csv python scripts/check_detection.py   # detection-quality gate

pytest                                   # whole suite
ruff check .                             # lint (ruff.toml, target py39)
pytest tests/test_model.py::test_detect_flags_the_planted_outliers   # one test
pytest -k summary                        # by keyword
```

macOS: port 5000 is taken by AirPlay Receiver, which answers `403 AirTunes`.
Use `PORT=5050 python run.py`, and hit `127.0.0.1` rather than `localhost` —
`localhost` resolves to `::1` first, where AirPlay listens.

## Architecture

Flask app factory (`create_app`) + a service layer, deliberately split so the
HTTP layer holds no logic:

- `app/config.py` — frozen `Config` dataclass, every field from an env var.
  Paths resolve against `BASE_DIR`. **Config is passed in, never read from
  globals** — that is what lets tests point the app at a `tmp_path` dataset.
- `app/features.py` — CSV load, validation, feature engineering. Raises
  `DataError` for anything wrong with the data.
- `app/model.py` — `train`, `detect`, `summarize`, `status`. Raises
  `ModelNotTrained` when no `model.pkl` exists.
- `app/routes.py` — thin handlers that call the service layer and map the two
  domain exceptions to 400 and 409 via `app_errorhandler`.

Two feature sets, chosen by `FEATURE_SET`:

- `flow` (default, `app/sessions.py`) — packets aggregated into (source, window)
  sessions with behavioural features. This is the one that can represent scans,
  sweeps and beaconing; per-packet features cannot, and no model choice fixes
  that. `WINDOW_SECONDS` must exceed the period of any beacon to be detected.
- `packet` (`app/features.py`) — the original per-packet features. IPs are packed
  32-bit integers, not summed octets (the sum collides: `192.168.1.5` and
  `5.1.168.192` both give 366).

Anything building a row for the model must use a **named DataFrame** so sklearn
matches columns by name, not position.

**`BASELINE_FILE` is the setting that matters most.** Fitting on the traffic
under inspection teaches the model the attack is normal. With a baseline the
threshold is calibrated at quantile 0.0 of the baseline scores (nothing
known-good may alarm); without one it silently degrades to a 2% quota and logs a
warning. Do not "fix" a quiet detector by removing the baseline.

The saved artifact is a **bundle** (`BUNDLE_VERSION`), not a bare estimator: it
carries the threshold, feature set, window and columns, and `load_model` refuses
a bundle whose feature set disagrees with the current config.

`contamination` is a budget, not a discovery: the model flags that fraction of
the dataset whether or not that many packets are genuinely abnormal.

`ALGORITHM` picks the detector (`iforest` default, `lof` alternative) via
`model.build_estimator`. The choice is benchmarked, not assumed — run
`scripts/benchmark_models.py` before changing the default; its `overlapping`
regime is the one that actually separates the candidates. An IF+LOF rank
ensemble was measured and rejected as worse than either alone.

## Constraints worth keeping

- **The API is unauthenticated.** Error strings and JSON responses must never
  contain absolute paths — `features.py` names files, `model.py:_public_path`
  relativises them. There are tests asserting this.
- **Packet data is attacker-influenced.** The front end renders values with
  `textContent` and builds SVG with `createElementNS`. Never introduce
  `innerHTML` with data-derived strings.
- The catch-all `Exception` handler must stay *below* the `HTTPException`
  handler in `routes.py`, or ordinary 404/405s become 500s.
- `/train` and `/anomalies` are legacy aliases for the `/api/*` routes and are
  covered by tests — keep them working.
- No front-end build step and no CDN: charts in `app/static/charts.js` are
  hand-rolled SVG. Keep it dependency-free.
- `joblib.load` unpickles, which executes code. `app/integrity.py` signs every
  saved model and **verifies before loading, never after** — checking afterwards
  would be checking a file that already ran. Do not add a load path that skips
  `verify()`.

## Data

`data/*.csv` and `models/*.pkl` are git-ignored and regenerated, never committed.
`scripts/generate_packets.py` is seeded (default 42), so datasets are
reproducible; `RANDOM_STATE` does the same for the model.
