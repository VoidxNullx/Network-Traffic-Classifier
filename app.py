import math
from flask import Flask, request, jsonify
from joblib import load
import pandas as pd

model = load("models/RFC.joblib")

app = Flask(__name__)

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Classifier</title>
<style>
:root{--bg:#0b1220;--panel:#111a2e;--line:#22304d;--text:#e6ecf8;--muted:#8fa0c2;
--accent:#4f8cff;--ok:#22c55e;--bad:#ef4444;--warn:#f59e0b}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
background:radial-gradient(1200px 600px at 10% -10%,#17284d 0%,transparent 60%),var(--bg);
color:var(--text);min-height:100vh}
.wrap{max-width:760px;margin:0 auto;padding:32px 18px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:24px}
.logo{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,#4f8cff,#7c5cff);
display:grid;place-items:center;font-weight:700;letter-spacing:.5px}
h1{margin:0;font-size:22px}
header p{margin:2px 0 0;color:var(--muted);font-size:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:18px;
box-shadow:0 10px 30px rgba(0,0,0,.25)}
h2{margin:0 0 4px;font-size:17px}
.sub{color:var(--muted);font-size:14px;margin:0 0 16px}
.presets{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.chip{background:#0d1526;border:1px solid var(--line);color:var(--text);border-radius:999px;
padding:7px 13px;font-size:13px;cursor:pointer;transition:.15s}
.chip:hover{border-color:var(--accent);color:#fff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input{width:100%;padding:12px 13px;font-size:16px;color:var(--text);background:#0d1526;
border:1px solid var(--line);border-radius:10px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,140,255,.2)}
.go{width:100%;margin-top:16px;padding:13px;font-size:16px;font-weight:600;color:#fff;border:0;
border-radius:10px;cursor:pointer;background:linear-gradient(135deg,#4f8cff,#7c5cff)}
.go:disabled{opacity:.6;cursor:wait}
.err{margin-top:12px;color:#fecaca;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4);
border-radius:10px;padding:10px 12px;font-size:14px;display:none}
#report{display:none;animation:rise .35s ease}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.banner{display:flex;align-items:center;gap:14px;padding:16px;border-radius:12px;margin-bottom:16px}
.banner.ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.45)}
.banner.bad{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.45)}
.dot{width:14px;height:14px;border-radius:50%}
.ok .dot{background:var(--ok)}.bad .dot{background:var(--bad)}
.banner b{font-size:18px}.banner span{display:block;color:var(--muted);font-size:14px;margin-top:2px}
.sec{margin-top:18px}
.sec h3{margin:0 0 8px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:14px}
td{padding:9px 10px;border-bottom:1px solid var(--line)}
td:first-child{color:var(--muted);width:42%}
p.t{margin:0;font-size:14.5px;line-height:1.6}
pre{margin:0;background:#0a1120;border:1px solid var(--line);border-radius:10px;padding:12px;
font-size:13px;overflow-x:auto;color:#c7d5f2}
.actions{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}
.btn{background:#0d1526;border:1px solid var(--line);color:var(--text);padding:10px 14px;border-radius:10px;
cursor:pointer;font-size:14px}
.btn:hover{border-color:var(--accent)}
.note{color:var(--muted);font-size:12.5px;margin-top:14px;line-height:1.5}
footer{text-align:center;color:var(--muted);font-size:13px;margin-top:26px}
@media print{
 body{background:#fff;color:#000}.card{box-shadow:none;border-color:#999;background:#fff}
 header,.presets,#form,.actions,footer{display:none!important}
 td,.sub,.sec h3,.banner span,.note{color:#333}pre{background:#f4f4f4;color:#000}
}
</style></head><body><div class="wrap">
<header><div class="logo">NTC</div><div><h1>Network Traffic Classifier</h1>
<p>Random Forest port-scan detection &middot; Flask REST API</p></div></header>

<div class="card" id="form">
<h2>Analyse a connection</h2>
<p class="sub">Enter connection metadata, or load an example, then classify.</p>
<div class="presets">
 <button class="chip" onclick="setv(0.2,8)">Port scan example</button>
 <button class="chip" onclick="setv(5.0,1)">Normal traffic example</button>
 <button class="chip" onclick="setv(1.0,4)">Boundary case</button>
</div>
<div class="grid">
 <div><label for="d">Connection duration (seconds)</label><input id="d" type="number" step="any" value="0.2"></div>
 <div><label for="c">Connection count (in observation window)</label><input id="c" type="number" step="any" value="8"></div>
</div>
<button class="go" id="go" onclick="classify()">Classify connection</button>
<div class="err" id="err"></div>
</div>

<div class="card" id="report">
<div class="banner" id="banner"><div class="dot"></div><div><b id="verdict"></b><span id="verdictSub"></span></div></div>
<div class="sec"><h3>Input summary</h3><table>
 <tr><td>Connection duration</td><td id="rd"></td></tr>
 <tr><td>Connection count</td><td id="rc"></td></tr>
 <tr><td>Analysed at</td><td id="rt"></td></tr></table></div>
<div class="sec"><h3>What this means</h3><p class="t" id="meaning"></p></div>
<div class="sec"><h3>Recommended action</h3><p class="t" id="action"></p></div>
<div class="sec"><h3>About the model</h3><table>
 <tr><td>Algorithm</td><td>Random Forest Classifier (scikit-learn)</td></tr>
 <tr><td>Features used</td><td>duration, connection_count</td></tr>
 <tr><td>Training data</td><td>Synthetic, with deliberately overlapping classes</td></tr>
 <tr><td>Held-out accuracy</td><td>~98&ndash;99%</td></tr>
 <tr><td>Excluded feature</td><td>bytes_sent (signal for data exfiltration, not port scanning)</td></tr></table></div>
<div class="sec"><h3>API exchange</h3><pre id="raw"></pre></div>
<p class="note">This is a demonstration trained on synthetic data. Values near the boundary between the two
classes can vary, and the result is not a substitute for a production intrusion detection system.</p>
<div class="actions"><button class="btn" onclick="copyReport()" id="cp">Copy report</button>
<button class="btn" onclick="window.print()">Print / Save as PDF</button></div>
</div>
<footer>Built by Tarun Lal &middot; BCA, JIMS Vasant Kunj</footer>
</div>
<script>
const $=id=>document.getElementById(id);
let lastText="";
function setv(d,c){$('d').value=d;$('c').value=c;$('err').style.display='none';}
function showErr(m){const e=$('err');e.textContent=m;e.style.display='block';}
async function classify(){
  $('err').style.display='none';
  const d=parseFloat($('d').value), c=parseFloat($('c').value);
  if(!isFinite(d)||!isFinite(c)){showErr('Please enter a number in both fields.');return;}
  const btn=$('go');btn.disabled=true;btn.textContent='Analysing...';
  const body=JSON.stringify({duration:d,connection_count:c});
  try{
    const r=await fetch('/predict',{method:'POST',headers:{'Content-Type':'application/json'},body:body});
    const j=await r.json();
    if(!r.ok){showErr('The API rejected the request: '+(j.error||'invalid input'));return;}
    render(d,c,j,body,r.status);
  }catch(e){showErr('Could not reach the API. Please try again.');}
  finally{btn.disabled=false;btn.textContent='Classify connection';}
}
function render(d,c,j,body,status){
  const mal=j.Prediction===1, now=new Date().toLocaleString();
  const verdict=mal?'Malicious (port-scan-like)':'Benign';
  const sub=mal?'This connection pattern resembles a port scan.':'This connection pattern looks like normal traffic.';
  const meaning=mal
   ?'The model found a pattern typical of port scanning: very short connections combined with a high number of connection attempts in a short window. Scanners probe many ports quickly and rarely keep a connection open.'
   :'The model found a pattern typical of normal use: connections that last longer with fewer attempts in the observation window, as when a user browses or transfers a file.';
  const action=mal
   ?'Review the source of this traffic in your logs, check whether it targeted many different ports or hosts, and consider rate-limiting or blocking the source if it is unexpected.'
   :'No action needed. Continue normal monitoring.';
  $('banner').className='banner '+(mal?'bad':'ok');
  $('verdict').textContent=verdict;$('verdictSub').textContent=sub;
  $('rd').textContent=d+' seconds';$('rc').textContent=c;$('rt').textContent=now;
  $('meaning').textContent=meaning;$('action').textContent=action;
  const raw='POST /predict  ->  HTTP '+status+'\n'+body+'\n'+JSON.stringify(j);
  $('raw').textContent=raw;
  lastText='NETWORK TRAFFIC CLASSIFIER - CLASSIFICATION REPORT\n'+
   'Verdict: '+verdict+'\nDuration: '+d+' s\nConnection count: '+c+'\nAnalysed at: '+now+'\n\n'+
   'What this means: '+meaning+'\nRecommended action: '+action+'\n\n'+
   'Model: Random Forest Classifier (scikit-learn); features: duration, connection_count; synthetic training data; ~98-99% held-out accuracy.';
  const rep=$('report');rep.style.display='block';rep.scrollIntoView({behavior:'smooth',block:'start'});
}
async function copyReport(){
  try{await navigator.clipboard.writeText(lastText);$('cp').textContent='Copied';}
  catch(e){$('cp').textContent='Copy failed';}
  setTimeout(()=>{$('cp').textContent='Copy report';},1800);
}
document.addEventListener('keydown',e=>{if(e.key==='Enter')classify();});
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