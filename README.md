# 🛡️ AI Cyber Threat Detector

A Flask application that finds anomalous **behaviour** in network captures with
an unsupervised **IsolationForest** model. It aggregates packets into per-source
time windows, fits a model to known-good traffic, and reports the sessions that
do not look like that baseline — ranked by how anomalous they are.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# A capture containing four planted attacks, and a clean one to learn from
python scripts/generate_packets.py --output data/packets.csv
python scripts/generate_packets.py --output data/baseline.csv --no-attacks

BASELINE_FILE=data/baseline.csv python run.py     # http://127.0.0.1:5000
```

Open the page, click **Train model**, then **Detect anomalies**. On the sample
data that finds all four planted attacks — a port scan, a host sweep, a C2
beacon and a data exfil — and raises nothing at all on the clean capture.

> **macOS note:** AirPlay Receiver also listens on port 5000. If requests come
> back `403 Forbidden` from `AirTunes`, either disable it in
> System Settings → General → AirDrop & Handoff, or run `PORT=5050 python run.py`.

---

## Detection altitude — why sessions, not packets

A single packet carries almost no evidence. A port-scan packet is a small TCP
packet; so is an ACK. Scanning, sweeping, beaconing and exfiltration are
*patterns across packets*, and looking at one packet at a time destroys exactly
the structure that makes them recognisable.

So `FEATURE_SET=flow` (the default) groups packets into **(source, time window)
sessions** and derives behavioural features:

| Feature | What it exposes |
|---|---|
| `packets`, `bytes_total` | volume — bulk transfer, exfiltration |
| `mean_length`, `std_length` | uniform payload sizes, a machine-generated tell |
| `distinct_dst_ips` | host sweeps and lateral movement |
| `distinct_dst_ports` | port scans |
| `distinct_protocols` | protocol-hopping |
| `mean_interarrival`, `std_interarrival` | beaconing — a near-zero deviation is a timer, not a person |
| `small_packet_ratio` | scan and probe traffic |
| `external_dst_ratio` | traffic leaving RFC1918 space |

`FEATURE_SET=packet` keeps the original per-packet features (`src_ip_int`,
`dst_ip_int`, `protocol`, `packet_length`) and is retained for comparison. On the
sample capture it cannot isolate the port scan at all, and needs **346 alerts**
to say what flow mode says in **8**.

`WINDOW_SECONDS` matters more than it looks. It must be longer than the period
of any beacon you hope to see; too long and bursts average away. Measured on the
sample data: 60s finds 3 of 4 attacks, **300s finds 4 of 4 with no false
positives**, 600s drops back to 3.

## Fit on a baseline, not on the evidence

The most important setting is `BASELINE_FILE`.

Fitting the model on the same capture you are inspecting teaches it that
whatever attack is in there is part of normal, and pulls the score distribution
toward the attacker. Point `BASELINE_FILE` at a known-good capture and
`DATA_FILE` at the traffic under suspicion, and the threshold is calibrated as a
quantile of the *baseline* scores — so a clean capture produces **zero** alerts
instead of a fixed quota of false ones.

Measured on the sample data:

| Setup | Attacks found | Alerts on clean traffic |
|---|---|---|
| No baseline (2% quota fallback) | 2 of 4 | 2 — all false |
| `BASELINE_FILE` + calibration | **4 of 4** | **0** |

Without a baseline the app still runs, but it falls back to a quota and logs a
warning saying so. `scripts/check_detection.py` asserts both properties and runs
in CI.

---

## Project structure

```
AI-Cyber-Threat-detector/
├── app/
│   ├── __init__.py          # create_app() application factory
│   ├── config.py            # env-driven settings
│   ├── features.py          # CSV loading, validation, per-packet features
│   ├── sessions.py          # per-source windowed flow features
│   ├── integrity.py         # HMAC signing of model files
│   ├── model.py             # train / detect / summarize / status
│   ├── routes.py            # HTTP endpoints + JSON error handlers
│   ├── static/  (style.css, app.js, charts.js)
│   └── templates/index.html
├── scripts/
│   ├── benchmark_models.py  # labelled model comparison (see Model choice)
│   ├── check_detection.py   # CI gate: finds the attacks, silent on clean data
│   ├── generate_packets.py  # synthetic dataset with planted anomalies
│   ├── capture_packets.py   # live capture via scapy (needs root)
│   └── inspect_model.py     # inspect a saved model / score one packet
├── tests/                   # pytest suite (62 tests)
├── data/                    # datasets (git-ignored)
├── models/                  # trained models (git-ignored)
├── run.py                   # dev entry point
├── requirements.txt         # runtime deps
├── requirements-dev.txt     # + pytest, scapy
└── .env.example             # documented configuration
```

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | web interface |
| `GET` | `/health` | liveness probe |
| `GET` | `/api/status` | is a dataset present, is a model trained, when |
| `POST` | `/api/train` | fit and persist the model |
| `GET` | `/api/anomalies?limit=N` | flagged packets, most anomalous first |
| `GET` | `/api/summary` | dashboard aggregates: score histogram + protocol split |

`POST /train` and `GET /anomalies` still work as aliases for the two original
endpoints.

```bash
curl -X POST http://127.0.0.1:5000/api/train
curl "http://127.0.0.1:5000/api/anomalies?limit=10"
```

Errors come back as JSON with a meaningful status: `400` bad or missing dataset,
`405` wrong method, `409` no trained model yet, `500` unexpected. Details go to
the log, never the response — the API is unauthenticated, and paths in an error
body disclose the host layout.

---

## Scripts

```bash
# Synthetic data — 5000 packets, 2% anomalous, reproducible
python scripts/generate_packets.py --count 5000 --anomaly-rate 0.02 --seed 42

# Live capture (root required; only on networks you are authorised to monitor)
sudo python scripts/capture_packets.py --iface en0 --count 500

# Inspect the saved model, or score a single packet
python scripts/inspect_model.py
python scripts/inspect_model.py --score 203.0.113.9 10.0.0.5 132 60000
```

---

## Configuration

Every setting is an environment variable with a sensible default — see
[.env.example](.env.example). The ones you are most likely to change:

| Variable | Default | Meaning |
|---|---|---|
| `DATA_FILE` | `data/packets.csv` | input dataset |
| `MODEL_FILE` | `models/model.pkl` | where the trained model is stored |
| `CONTAMINATION` | `auto` | `auto`, or a quota fraction |
| `N_ESTIMATORS` | `100` | trees in the forest |
| `BASELINE_FILE` | unset | known-good capture to fit on — **set this** |
| `FEATURE_SET` | `flow` | `flow` (sessions) or `packet` |
| `WINDOW_SECONDS` | `300` | session window length |
| `CALIBRATION_QUANTILE` | auto | quantile of baseline scores used as the threshold |
| `SCORE_THRESHOLD` | unset | hard override of the calibrated threshold |
| `MODEL_SIGNING_KEY` | generated | HMAC key protecting the model file |
| `ALGORITHM` | `iforest` | detector: `iforest` or `lof` |
| `RANDOM_STATE` | `42` | seed, so runs are reproducible |
| `MAX_RESULTS` | `500` | cap on rows per API response |
| `PORT` | `5000` | dev server port |

---

## Dashboard

`Detect anomalies` also renders two charts, both fed by `/api/summary`:

- **Anomaly score distribution** — every packet binned by `decision_function`
  score, split normal vs flagged. It shows where the model actually drew its
  line and how cleanly the two populations separate.
- **Traffic by protocol** — normal vs flagged counts per protocol, busiest
  first. A protocol that is entirely flagged (GRE, ESP, SCTP in the synthetic
  data) stands out immediately.

Charts are hand-rolled inline SVG — no charting library, no CDN, no build step.
Series colours are fixed (blue = normal, orange = flagged), legended in both
charts, and validated for colour-vision deficiency; dark and light modes use
separately chosen steps rather than an automatic flip.

## Model choice

`scripts/benchmark_models.py` generates labelled traffic and measures every
candidate, so this is settled by numbers rather than preference. Three regimes,
4000 packets, ~3% anomalies, PR-AUC (higher is better):

| Model | obvious | subtle | overlapping |
|---|---|---|---|
| **IsolationForest** (default) | **1.000** | **1.000** | 0.157 |
| LocalOutlierFactor | 0.137 | 0.033 | **0.688** |
| EllipticEnvelope | 1.000 | 1.000 | 0.048 |
| OneClassSVM (rbf) | 0.967 | 0.306 | 0.144 |
| Ensemble (IF+LOF ranks) | 0.333 | 0.108 | 0.346 |

Read it like this:

- **IsolationForest is the right default.** It wins outright when anomalies are
  globally extreme — rare protocols, oversized payloads, off-subnet sources —
  which is the threat profile this app is built around.
- **LOF is four times better on contextual anomalies** (`overlapping`: every
  field individually in range, only the *combination* wrong, e.g. an ICMP packet
  carrying a TCP-sized payload). It collapses on the other two, because a tight
  cluster of extreme outliers looks locally dense to a density-ratio method.
  Set `ALGORITHM=lof` when that is the traffic you are hunting.
- **EllipticEnvelope ties on easy data and collapses on hard data** — it assumes
  one Gaussian blob. Not worth the fragility.
- **The ensemble was tried and rejected.** Averaging ranks is worse than the
  better single model in every regime; the confident model gets dragged down.

Caveat on LOF: it is transductive. Persisting one requires `novelty=True`, and
scikit-learn does not intend that mode to score its own training data — which is
exactly what this app does. Treat `ALGORITHM=lof` as exploratory.

Scaling makes no measurable difference to IsolationForest (it splits on raw
thresholds) and is mandatory for the others, so it is applied only where needed.

```bash
python scripts/benchmark_models.py                      # all three regimes
python scripts/benchmark_models.py --regime overlapping --count 8000
```

Those figures are measured on the *packet* feature set, which is where the
algorithms differ most. The larger win by far came from changing what the model
looks at, not which model looks at it — see "Detection altitude" above.

## Tests

```bash
pip install -r requirements-dev.txt
pytest              # 62 tests
ruff check .        # lint; config in ruff.toml

# Detection-quality gate: finds the planted attacks, silent on clean traffic
python scripts/generate_packets.py --output data/attacks.csv
python scripts/generate_packets.py --output data/clean.csv --no-attacks
BASELINE_FILE=data/clean.csv DATA_FILE=data/attacks.csv python scripts/check_detection.py
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of the above
on Python 3.9 and 3.12. The detection gate is the important one: it fails the
build if a change makes the detector worse, which unit tests alone would not
catch.

## Known limitations

Worth being explicit, since this is a security tool:

- **No authentication.** Anyone who can reach the port can train and read every
  flagged session.
- **Training is synchronous.** `POST /api/train` blocks for the whole fit; a
  large capture will time out the request.
- **The beacon is the weakest detection** and depends on window alignment. A
  dedicated periodicity feature (autocorrelation over a longer horizon) would be
  the next thing to add.
- **Unsupervised means unexplained.** The model says a session is unusual for
  the baseline, never *what* it is. It cannot distinguish an attack from a
  backup job that started running this week.
- **A baseline can be poisoned.** If the traffic you fit on already contains the
  attacker, they become normal by definition.

---

## Security notes

This app has **no authentication** and is not hardened for public exposure.

- It binds to `127.0.0.1` by default; exposing it more widely must be deliberate.
- `FLASK_DEBUG` is off by default. Never turn it on where others can reach the
  port — the Werkzeug debugger is remote code execution.
- Packet data is attacker-influenced input, so the UI renders every value with
  `textContent` and builds SVG with `createElementNS` — never by concatenating
  HTML strings.
- API responses report paths relative to the project root, so an unauthenticated
  caller cannot learn the host account name or directory layout.
- **Model files are pickles, and unpickling executes code.** Every saved model
  is signed with an HMAC-SHA256 (`models/model.pkl.sig`) and verified *before*
  loading, so the process only ever unpickles bytes it wrote itself. An attacker
  who can write to `models/` but cannot read the signing key cannot get their
  pickle executed. Set `MODEL_SIGNING_KEY` from a real secret store in any
  serious deployment; otherwise a per-install key is generated at `models/
  model_signing.key` with owner-only permissions.
- Capture traffic only on networks you own or have written permission to monitor.

---

## License

See [LICENSE](LICENSE).
