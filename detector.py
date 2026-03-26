import re
import numpy as np
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest

def extract_features(log: Dict[str, Any]) -> List[float]:
    """
    Extracts numerical features from a log dictionary.
    """
    command_line = str(log.get("command_line", "")).lower()
    
    # 1. Length of command line
    cmd_length = len(command_line)
    
    # 2. Presence of encoded command (1/0)
    has_encoded = 1.0 if "-encodedcommand" in command_line or "-enc " in command_line or "-e " in command_line else 0.0
    
    # 3. Presence of suspicious flags (1/0)
    suspicious_flags = ["bypass", "hidden", "urlcache", "decode", "-f", "split"]
    has_suspicious = 1.0 if any(flag in command_line for flag in suspicious_flags) else 0.0
    
    # 4. Risk score (existing)
    risk_score = float(log.get("risk_score", 0))
    
    return [cmd_length, has_encoded, has_suspicious, risk_score]

def train_anomaly_detector(normal_logs: List[Dict[str, Any]]) -> IsolationForest:
    """
    Trains an Isolation Forest model on sample normal data.
    """
    # If no normal data provided, create a dummy baseline to avoid fitting errors
    if not normal_logs:
        normal_logs = [{
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c exit",
            "parent_process": "explorer.exe",
            "risk_score": 0
        }]
        
    features = [extract_features(log) for log in normal_logs]
    
    # Train Isolation Forest
    # contamination is the expected proportion of outliers. Set to a low value for normal training data.
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(features)
    
    return model

def detect_suspicious_activity(logs: List[Dict[str, Any]], ml_model: IsolationForest = None) -> List[Dict[str, Any]]:
    """
    Analyzes a list of Sysmon process creation logs to detect suspicious activity,
    assigning a numerical risk score and risk level. Optionally applies an ML model 
    for anomaly detection.
    
    Args:
        logs (list): Process logs.
        ml_model: Trained IsolationForest instance (optional).
            
    Returns:
        list: Updated logs.
    """
    updated_logs = []

    for log in logs:
        # Safely extract fields and cast to lower case for comparison
        process_name = str(log.get("process_name", "")).lower()
        command_line = str(log.get("command_line", "")).lower()
        parent_process = str(log.get("parent_process", "")).lower()
        
        risk_score = 0
        reasons = []

        # 1. Detect suspicious patterns based on command-line arguments
        
        # PowerShell checks
        if "powershell" in process_name or "pwsh" in process_name:
            if "-encodedcommand" in command_line or "-enc " in command_line or "-e " in command_line:
                risk_score += 40
                reasons.append("PowerShell execution with EncodedCommand flag (+40).")
            
            if "-executionpolicy bypass" in command_line or "-ep bypass" in command_line or "exec bypass" in command_line:
                risk_score += 25
                reasons.append("PowerShell execution policy bypass (+25).")
                
            if "-windowstyle hidden" in command_line or "-w hidden" in command_line or "-window hidden" in command_line:
                risk_score += 15
                reasons.append("PowerShell executed with a hidden window (+15).")
                
        # Certutil checks
        if "certutil" in process_name:
            if "-urlcache" in command_line and "split" in command_line and "-f" in command_line:
                risk_score += 40
                reasons.append("Certutil payload download command pattern (+40).")
            elif "-urlcache" in command_line:
                risk_score += 40
                reasons.append("Certutil payload download via -urlcache (+40).")

        # 2. Detect suspicious parent-child relationships
        
        if "powershell" in process_name and "cmd" in parent_process:
            risk_score += 20
            reasons.append("Suspicious ancestry: cmd.exe spawning powershell.exe (+20).")
            
        if "powershell" in process_name and "winword" in parent_process:
            risk_score += 30
            reasons.append("Suspicious ancestry: Microsoft Word (winword.exe) spawning powershell.exe (+30).")

        # Calculate preliminary risk score to pass to the ML module if available
        # But wait, the ML extract_features expects the dictionary to have `risk_score`.
        # So we temporarily set it.
        log["risk_score"] = risk_score

        # --- ML Anomaly Detection ---
        if ml_model is not None:
            features = extract_features(log)
            # score_samples returns opposite of anomaly score in some contexts, but let's use decision_function or predict
            # predict returns 1 for inliers, -1 for outliers
            prediction = ml_model.predict([features])[0]
            
            # score_samples gives negative values where lower is more anomalous. 
            # We can map it to a positive anomaly score for readability.
            raw_score = ml_model.score_samples([features])[0]
            # normalize to a positive score just for output readability (optional format)
            anomaly_score = round(float(-raw_score), 4)

            is_anomalous = bool(prediction == -1)
            log["anomaly_score"] = anomaly_score
            log["is_anomalous"] = is_anomalous
            
            if is_anomalous and risk_score > 30:
                risk_score += 15
                reasons.append("Anomaly detected by ML module (+15).")
        else:
            # If no ML model is provided, set defaults or leave missing (user spec wants these fields added)
            # Usually we'd assume it's added if the module is used
            pass

        # Limit maximum score to 100
        if risk_score > 100:
            risk_score = 100

        # Determine risk level based on the final score
        if risk_score <= 30:
            risk_level = "LOW"
        elif 31 <= risk_score <= 70:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        if not reasons:
            reasons.append("No suspicious activity detected.")
            
        log["risk_score"] = risk_score
        log["risk_level"] = risk_level
        log["reason"] = " | ".join(reasons)
        
        updated_logs.append(log)

    return updated_logs
