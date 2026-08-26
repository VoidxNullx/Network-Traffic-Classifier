from flask import Flask , request
from joblib import load
import pandas as pd

model = load("models/RFC.joblib")

app = Flask(__name__)
@app.route("/")
def home():
    return "Hello, Tarun"

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    row = pd.DataFrame({
        "duration": [data["duration"]],
        "connection_count": [data["connection_count"]]
    })
    print(row)
    y_prediction = model.predict(row)
    return {
        "Prediction": int(y_prediction[0])
    }

if __name__ == "__main__":
    app.run(debug=True)
    
    