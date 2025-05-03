# 🛡️ AI Cyber Threat Detector

This is a Flask-based web application that uses an Isolation Forest machine learning model to detect anomalies in network packet data. It identifies potential cyber threats by analyzing packet attributes like source/destination IP, protocol, and packet length.

---

## 🚀 Features

- Train an anomaly detection model using `IsolationForest`
- Detect anomalies from packet data (`packets.csv`)
- Simple web interface (`index.html`) to initiate detection
- REST API endpoints to trigger training and anomaly detection
- Encodes IP addresses and protocol numerically for model use

---

## 🧠 Machine Learning

We use the `IsolationForest` algorithm from `scikit-learn`, suitable for unsupervised anomaly detection in high-dimensional datasets.

### Features used:
- Encoded source IP (`src_ip`)
- Encoded destination IP (`dst_ip`)
- Protocol number (`protocol`)
- Packet length (`packet_length`)

---

## 📂 Project Structure

```plaintext
AI-Cyber-Threat-Detector/
│
├── main.py                # Flask application
├── model.pkl              # Saved trained model (created after POST to /train)
├── packets.csv            # Input dataset with packet information
├── templates/
│   └── index.html         # Basic front-end interface
├── model_extractor.py     # Script to inspect the trained model
├── requirements.txt       # Python dependencies
└── README.md              # Project overview (this file)
