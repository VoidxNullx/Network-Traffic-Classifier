import math
from flask import Flask, request, jsonify
from joblib import load
import pandas as pd

model = load("models/RFC.joblib")

app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Classifier</title>
<style>
 body{font-family:Georgia,serif;max-width:480px;margin:40px auto;padding:0 16px}
 input,button{font-size:16px;padding:8px;margin:6px 0;width:100%;box-sizing:border-box}
 #out{margin-top:16px;padding:12px;border:1px solid #000;display:none}
</style></head><body>
<h2>Network Traffic Classifier</h2>
<p>Enter connection metadata to classify it as benign or port-scan-like.</p>
<label>Duration (seconds)</label><input id="d" type="number" step="any" value="0.2">
<label>Connection count</label><input id="c" type="number" step="any" value="8">
<button onclick="go()">Classify</button>
<div id="out"></div>
<script>
async function go(){
  const o=document.getElementById('out'); o.style.display='block'; o.textContent='Working...';
  try{
    const r=await fetch('/predict',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({duration:parseFloat(d.value),connection_count:parseFloat(c.value)})});
    const j=await r.json();
    if(!r.ok){o.textContent='Error: '+(j.error||'request failed');return;}
    const p=j.Prediction;
    o.textContent='Prediction: '+p+' - '+(p===1?'Malicious (port-scan-like)':'Benign');
  }catch(e){o.textContent='Request failed.';}
}
</script></body></html>"""


@app.route("/")
def home():
    return PAGE


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid input"}), 400
    try:
        duration = float(data["duration"])
        connection_count = float(data["connection_count"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Invalid input"}), 400
    if not (math.isfinite(duration) and math.isfinite(connection_count)):
        return jsonify({"error": "Invalid input"}), 400

    row = pd.DataFrame({
        "duration": [duration],
        "connection_count": [connection_count]
    })
    y_prediction = model.predict(row)
    return {"Prediction": int(y_prediction[0])}


if __name__ == "__main__":
    app.run(debug=True)