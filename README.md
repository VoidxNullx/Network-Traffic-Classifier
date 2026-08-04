# Network Traffic Classifier

A machine learning pipeline that classifies network connections as **benign** or **malicious** (simulating port-scan detection), served through a Flask REST API.

## What this project does

Network intrusion detection systems look at connection metadata — how long a connection lasts, how many connections happen in a short window — to flag suspicious activity. This project builds a small end-to-end version of that idea:

1. Generates synthetic network traffic data with two classes: benign and malicious (port-scan-like)
2. Trains a Random Forest classifier on that data
3. Saves the trained model to disk
4. Serves it through a Flask API that returns real-time predictions

## The detection logic

The model is trained to recognize **port scanning**, which has a distinct pattern: short connection duration + high number of connections in a short window. Benign traffic looks the opposite — longer duration, fewer connections.

The synthetic data is deliberately built with **overlapping ranges** between the two classes (not cleanly separated), so the model has to learn a real decision boundary instead of trivially separating two disjoint clusters. An earlier version without overlap scored 100% accuracy — a red flag, not a win, since it meant the problem was too easy. The current version scores ~98-99%, which is a more meaningful result on data with realistic ambiguity.

A `bytes_sent` feature was considered and deliberately excluded — it's a strong signal for a *different* attack pattern (data exfiltration), not port scanning, and including it would have added noise without improving this specific model.

## Project structure
Network-Traffic-Classifier/
├── data/
│ └── generate_data.py # synthetic data generation + training
├── models/
│ └── RFC.joblib # trained model (generated, not committed)
├── api.py # Flask API serving predictions
├── requirements.txt
└── README.md

## Setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows
pip install -r requirements.txt
python data/generate_data.py      # generates data, trains model, saves to models/
python api.py                     # starts the API on localhost:5000
```

## Example request

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -Body '{"duration": 0.2, "connection_count": 8}' -ContentType "application/json"
```

Returns:
```json
{"Prediction": 1}
```

(`1` = malicious/scan-like, `0` = benign)

## What I learned building this

- Hand-labeling synthetic data forces you to actually define what an attack pattern *is*, feature by feature, instead of treating "malicious" as a black box
- 100% accuracy is a warning sign on a security dataset, not a success — it usually means the problem was made too easy
- `train_test_split` shuffles by default, but understanding *why* that matters (avoiding a test set that's 100% one class) matters more than just calling the function
- Deployment brings its own bugs unrelated to the model itself — e.g. numpy's `int64` isn't JSON-serializable, so it needs explicit conversion to a plain Python `int` before returning it from an API

## Next steps

- Swap synthetic data for a real dataset (NSL-KDD or CICIDS2017)
- Add a second model variant focused on data exfiltration detection (using `bytes_sent` as the primary signal)
- Add more features and compare model performance

## Author

Built by [Tarun](https://github.com/VoidxNullx), as part of an AI + Cybersecurity project series, alongside hands-on pentesting practice via TryHackMe and PortSwigger Web Security Academy.