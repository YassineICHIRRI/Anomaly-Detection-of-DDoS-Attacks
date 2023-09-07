from flask import Flask, render_template, request, jsonify

import numpy as np
import pickle
import pandas as pd 
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from io import BytesIO
import base64

app = Flask(__name__)



# Load your saved machine learning model
with open("model.pkl", "rb") as file:
    saved_model = pickle.load(file)

# Define a function for benign and DDoS attack detection
def detect_attack(samples):
    # Simulate random feature data (modify as needed)
    random_features = {
    "Fwd Packet Length Max": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Flow IAT Std": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Fwd Packet Length Std": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Fwd IAT Total": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Fwd Packet Length Mean": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Flow IAT Mean": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Bwd Packet Length Mean": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Flow IAT Max": np.random.uniform(-1.0, 1.0, samples).round(6),
    "Bwd Packet Length Std": np.random.uniform(-1.0, 1.0, samples).round(6),
}
    random_features = pd.DataFrame(random_features)

    # Predict labels
    predictions = saved_model.predict(random_features)
    
    # Count benign and DDoS attacks
    benign_count = np.count_nonzero(predictions == "BENIGN")
    ddos_count = np.count_nonzero(predictions == "DDoS")
    
    return benign_count, ddos_count

def predict_datapoint(datapoint):
    if request.method == "POST":
        feature_names = ["Fwd Packet Length Max","Flow IAT Std","Fwd Packet Length Std" ,"Fwd IAT Total", "Fwd Packet Length Mean", "Flow IAT Mean", "Bwd Packet Length Mean", "Flow IAT Max", "Bwd Packet Length Std", ]
        values = {}

        for feature_name in feature_names:
            values[feature_name] = float(request.form[feature_name])

        # Create a DataFrame using the extracted feature names and values
        manual_features = pd.DataFrame([values])

        # Predict the nature of the data point
        predictions = saved_model.predict(manual_features)
        result = predictions[0]  # Assuming one prediction

    return result
    
    
# Define a function for data visualization
def visualize_data(benign_count, ddos_count):
    labels = ["BENIGN", "DDoS"]
    counts = [benign_count, ddos_count]

    plt.figure(figsize=(8, 5))
    plt.pie(counts, labels=labels, autopct='%1.1f%%', colors=['blue', 'red'])
    plt.title("Class Distribution")

    # Save the plot as an image
    img_data = BytesIO()
    plt.savefig(img_data, format="png")
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode()

    return img_base64
@app.route("/", methods=["GET"])
def landing_page():
    return render_template("landing_page.html")


@app.route("/generate_traffic", methods=["GET", "POST"])
def generate_traffic():
    if request.method == "POST":
        samples = int(request.form["samples"])
        benign_count, ddos_count = detect_attack(samples)
        img_base64 = visualize_data(benign_count, ddos_count)
        
        # Return JSON data to update the page
        return jsonify({
            "samples": samples,
            "benign_count": benign_count,
            "ddos_count": ddos_count,
            "img_base64": img_base64
        })

    return render_template("generate_traffic.html")


@app.route("/predict_datapoint", methods=["GET", "POST"])
def predict_datapoint():
    result = None
    if request.method == "POST":
        features = ["Fwd Packet Length Max","Flow IAT Std","Fwd Packet Length Std" ,"Fwd IAT Total", "Fwd Packet Length Mean", "Flow IAT Mean", "Bwd Packet Length Mean", "Flow IAT Max", "Bwd Packet Length Std"]
        values = {}

        for feature in features:
            values[feature] = float(request.form[feature])

        # Create a DataFrame using the extracted feature names and values
        manual_features = pd.DataFrame([values])

        # Predict the nature of the data point
        predictions = saved_model.predict(manual_features)
        result = predictions[0]  # Assuming one prediction

    return render_template("manual_entry.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)