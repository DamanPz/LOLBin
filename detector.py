"""
LOLBin Detector — ML-based (no hardcoded rules)
================================================
Loads a trained RandomForest model from lolbin_model.pkl and uses it to
score process telemetry. No if/else detection rules — all patterns are
learned from labeled data via train_model.py.

If lolbin_model.pkl is not found, all events are returned as LOW risk
with a warning. Run train_model.py first.
"""

import os
import re
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK lookup (enrichment metadata, NOT detection rules)
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    "powershell":    ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "pwsh":          ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "cmd":           ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    "certutil":      ("T1105",     "Ingress Tool Transfer"),
    "bitsadmin":     ("T1105",     "Ingress Tool Transfer"),
    "mshta":         ("T1218.005", "Signed Binary Proxy Execution: Mshta"),
    "regsvr32":      ("T1218.010", "Signed Binary Proxy Execution: Regsvr32"),
    "rundll32":      ("T1218.011", "Signed Binary Proxy Execution: Rundll32"),
    "wmic":          ("T1047",     "Windows Management Instrumentation"),
    "msiexec":       ("T1218.007", "Signed Binary Proxy Execution: Msiexec"),
    "cscript":       ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "wscript":       ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "regsvcs":       ("T1218.009", "Signed Binary Proxy Execution: Regsvcs/Regasm"),
    "regasm":        ("T1218.009", "Signed Binary Proxy Execution: Regsvcs/Regasm"),
    "installutil":   ("T1218.004", "Signed Binary Proxy Execution: InstallUtil"),
    "schtasks":      ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "net":           ("T1136",     "Create Account"),
    "reg":           ("T1112",     "Modify Registry"),
}

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lolbin_model.pkl")

_model = None
_model_loaded = False


def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return _model
    _model_loaded = True
    if os.path.exists(MODEL_PATH):
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
            print(f"[detector] Model loaded from {MODEL_PATH}")
        except Exception as e:
            print(f"[detector] WARNING: Failed to load model: {e}")
            _model = None
    else:
        print(f"[detector] WARNING: No model found at {MODEL_PATH}. Run train_model.py first.")
        _model = None
    return _model


def _get_mitre(process_name: str):
    proc = str(process_name).lower()
    # Strip path, keep filename
    proc = os.path.basename(proc).replace(".exe", "")
    for key, val in MITRE_MAP.items():
        if key in proc:
            return val
    return ("T1059", "Command and Scripting Interpreter")


def _add_numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    """Must match feature engineering in train_model.py exactly."""
    cmd = df["command_line"].fillna("").str.lower()
    df = df.copy()
    df["cmd_length"]      = cmd.str.len()
    df["num_args"]        = cmd.str.count(r"\s")
    df["has_http"]        = cmd.str.contains(r"https?://", regex=True).astype(int)
    df["has_ip"]          = cmd.str.contains(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", regex=True).astype(int)
    df["num_special"]     = cmd.apply(lambda x: sum(1 for c in x if c in "^|&;`$%@"))
    df["has_long_token"]  = cmd.apply(lambda x: int(any(len(t) > 40 for t in x.split())))
    df["word_count"]      = cmd.str.split().apply(lambda x: len(x) if isinstance(x, list) else 0)
    return df


def _prepare_row(log: dict) -> pd.DataFrame:
    row = {
        "process_name":  str(log.get("process_name") or "").lower(),
        "command_line":  str(log.get("command_line")  or "").lower(),
        "parent_process": str(log.get("parent_process") or "").lower(),
    }
    df = pd.DataFrame([row])
    df = _add_numeric_features(df)
    return df


def _score_log(log: dict, model) -> dict:
    """Run model inference on a single log dict. Returns enriched copy."""
    result = dict(log)

    df = _prepare_row(log)

    try:
        prob        = float(model.predict_proba(df)[0][1])
        is_malicious = prob >= 0.5
    except Exception:
        prob, is_malicious = 0.0, False

    risk_score = int(round(prob * 100))

    if risk_score <= 30:
        risk_level = "LOW"
    elif risk_score <= 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    technique_id, technique_name = _get_mitre(log.get("process_name", ""))

    result["risk_score"]    = risk_score
    result["risk_level"]    = risk_level
    result["is_anomalous"]  = is_malicious
    result["anomaly_score"] = round(prob, 4)
    result["mitre_id"]      = technique_id
    result["mitre_name"]    = technique_name
    result["reason"]        = (
        f"ML confidence: {prob:.0%} malicious | {technique_id}: {technique_name}"
        if is_malicious
        else f"ML confidence: {prob:.0%} malicious | {technique_id}: {technique_name}"
    )

    return result


def _score_log_no_model(log: dict) -> dict:
    result = dict(log)
    technique_id, technique_name = _get_mitre(log.get("process_name", ""))
    result["risk_score"]    = 0
    result["risk_level"]    = "LOW"
    result["is_anomalous"]  = False
    result["anomaly_score"] = 0.0
    result["mitre_id"]      = technique_id
    result["mitre_name"]    = technique_name
    result["reason"]        = "No model loaded — run train_model.py to enable ML detection."
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API  (keeps compatibility with app.py and live_monitor.py)
# ─────────────────────────────────────────────────────────────────────────────

def detect_suspicious_activity(logs, ml_model=None):  # noqa: ARG001
    """
    Analyze a list of process log dicts and return them enriched with:
      risk_score, risk_level, is_anomalous, anomaly_score, mitre_id, reason

    ml_model param is accepted for backward compatibility but ignored —
    the module always uses the persisted lolbin_model.pkl.
    """
    model = _load_model()
    results = []
    for log in logs:
        if model is not None:
            results.append(_score_log(log, model))
        else:
            results.append(_score_log_no_model(log))
    return results


def run_detection_pipeline(log_event: dict) -> dict:
    """Single-event entry point used by live_monitor.py."""
    model = _load_model()
    if model is not None:
        return _score_log(log_event, model)
    return _score_log_no_model(log_event)


def train_anomaly_detector(normal_logs=None):  # noqa: ARG001
    """
    Kept for backward compatibility with app.py.
    The model is now trained offline via train_model.py.
    Returns None — detect_suspicious_activity loads the model internally.
    """
    return None


def extract_features(log):
    """
    Kept for backward compatibility.
    Returns a simple feature vector (not used by the new ML pipeline).
    """
    cmd = str(log.get("command_line", "")).lower()
    return [
        len(cmd),
        int("-encodedcommand" in cmd or "-enc " in cmd),
        int(any(f in cmd for f in ["bypass", "hidden", "urlcache"])),
        float(log.get("risk_score", 0)),
    ]
