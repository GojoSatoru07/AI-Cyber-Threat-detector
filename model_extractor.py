import joblib
import sys

print("Starting...", flush=True)

model = joblib.load("model.pkl")
print("Loaded model:", model, flush=True)

params = model.get_params()
print("Model parameters:", params, flush=True)

features = [[10, 20, 1, 300]]
score = model.decision_function(features)
print("Decision function score:", score, flush=True)

input("Press Enter to exit...")  # Keeps console open
