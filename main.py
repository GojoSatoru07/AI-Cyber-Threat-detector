from flask import Flask, request, jsonify, render_template
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

app = Flask(__name__)
MODEL_FILE = "model.pkl"
DATA_FILE = "packets.csv"

def preprocess_data(file_path):
    df = pd.read_csv(file_path)
    df['src_ip_encoded'] = df['src_ip'].apply(lambda x: sum([int(i) for i in x.split('.')]))
    df['dst_ip_encoded'] = df['dst_ip'].apply(lambda x: sum([int(i) for i in x.split('.')]))
    df['protocol_encoded'] = df['protocol']
    features = df[['src_ip_encoded', 'dst_ip_encoded', 'protocol_encoded', 'packet_length']]
    return features

@app.route('/train', methods=['POST'])
def train_model():
    try:
        features = preprocess_data(DATA_FILE)
        model = IsolationForest(n_estimators=100, contamination=0.05)
        model.fit(features)
        joblib.dump(model, MODEL_FILE)
        return jsonify({"message": "Model trained successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/anomalies', methods=['GET'])
def detect_anomalies():
    try:
        if not os.path.exists(MODEL_FILE):
            return jsonify({"error": "Model not found. Train the model first."}), 400
        model = joblib.load(MODEL_FILE)
        features = preprocess_data(DATA_FILE)
        anomalies = model.predict(features)
        results = pd.read_csv(DATA_FILE)
        results['anomaly'] = anomalies
        anomalies_detected = results[results['anomaly'] == -1]
        return jsonify({"anomalies": anomalies_detected.to_dict(orient='records')}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
