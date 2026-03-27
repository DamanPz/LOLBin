# LOLBins Real-Time Detection Dashboard
## Project Documentation & Presentation Outline

---

### Slide 1: Title Slide
**Title:** LOLBins Live Monitor
**Subtitle:** Real-Time Cybersecurity Detection & Analytics Dashboard
**Presenter:** [Your Name / Team Name]
**Date:** [Insert Date]

---

### Slide 2: Executive Summary
**Title: Project Objective & Overview**
* **The Goal:** Build a real-time, interactive Endpoint Detection and Response (EDR) dashboard to detect Living-off-the-Land Binaries (LOLBins).
* **Core Technologies:** Python, CustomTkinter (Modern UI), Matplotlib (Live Graphing), scikit-learn (Machine Learning), and Windows Sysmon.
* **Key Achievement:** Successfully transitioned from static, manual log analysis to a continuously running, live-monitoring pipeline capable of processing thousands of events per minute.

---

### Slide 3: System Architecture
**Title: How It Works**
* **Data Ingestion:** Utilizes `win32evtlog` to hook directly into the Windows Event Viewer, capturing Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connect) in real-time.
* **Detection Engine:** A hybrid pipeline combining strict rule-based scoring with an Unsupervised Machine Learning model (Isolation Forest).
* **Presentation Layer:** A multi-threaded CustomTkinter desktop application guaranteeing the UI never freezes during heavy log ingest bursts.

---

### Slide 4: The Detection Pipeline
**Title: Identifying the Threat**
* **Rule-Based Triggers:** Instantly flags malicious behavior (e.g., PowerShell `-ExecutionPolicy Bypass`, hidden windows, certutil `-urlcache`).
* **Telemetry Extraction:** Captures the Command Line, Parent Process Ancestry, Base64 Payloads, and SHA256 hashes for every execution.
* **ML Anomaly Detection:** Extracts feature vectors (command length, flags) to evaluate statistical deviation from a normal baseline, adding intelligent risk scores to evasive malware.

---

### Slide 5: Live Dashboard Overview
**Title: At-A-Glance Monitoring**
* **Real-Time Telemetry:** Tracks total logs processed and visualizes the log frequency as a smoothly updating Matplotlib area chart.
* **Status Cards:** Provides instant visibility into your Active Alerts and the system's current Processing Rate (Logs per second).
* **Recent Alerts Feed:** A clickable, chronological feed that allows analysts to jump directly into immediate threat investigation.

---

### Slide 6: Alert Management UI
**Title: Intelligent Triage**
* **Dynamic Table:** Alerts are categorized by Risk Score directly mapping to Severity (Low, Medium, High).
* **Noise Reduction:** A severity dropdown allows Analysts to instantly filter out the benign logs and focus exclusively on High-Risk items.
* **Status Tracking:** Visual, uniform badges tracking the resolution state of an alert (New → Reviewed → Resolved).

---

### Slide 7: Threat Investigation View
**Title: Deep-Dive Analysis**
* **Process Execution Details:** Displays exactly what process ran, its PID, the executing user, and the raw command line payload.
* **Matched Indicators:** A dynamically generated list explaining *exactly* why the ML pipeline flagged the process (e.g., *PowerShell execution policy bypass (+25)*).
* **Process Tree Visualization:** Recursively links parent/child Process IDs to build a multi-level execution chain, exposing complex nested LOLBin attacks.

---

### Slide 8: Network Activity Mapping
**Title: Sysmon Event ID 3 Integration**
* **Live Socket Caching:** Actively listens for and caches raw IPv4/IPv6 outbound network connections in the background.
* **Smart Cross-Referencing:** Pairs network sockets back to the executing process using shared Sysmon `ProcessGuid` hashes.
* **C2 Discovery:** Surfaces direct-to-IP payload downloads, immediately highlighting domain resolution failures beneath the process details.

---

### Slide 9: Future Roadmap
**Title: Next Steps & Scaling**
* **Model Maturation:** Re-training the Unsupervised ML model on extensive organizational baseline data for environment-specific anomaly detection.
* **Threat Intel Integration:** API integration to cross-reference SHA256 hashes and Domains with VirusTotal.
* **Active Remediation:** Adding an automated remediation trigger (e.g., Process Kill) directly from the dashboard.
