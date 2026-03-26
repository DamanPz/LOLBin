import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os

# Assuming sysmon parsing and detector logic are in the current directory workspace
try:
    from sysmon_parser import parse_sysmon_xml
except ImportError:
    # Dummy fallback if module missing
    def parse_sysmon_xml(filepath):
        return []

try:
    from detector import detect_suspicious_activity, train_anomaly_detector
except ImportError:
    # Dummy fallback if module missing
    def detect_suspicious_activity(logs, ml_model=None):
        return []
    def train_anomaly_detector(data):
        return None

# Create some basic normal background data to train ML model transparently
DUMMY_TRAINING_DATA = [
    { "process_name": "explorer.exe", "command_line": "explorer.exe", "parent_process": "userinit.exe", "risk_score": 0 },
    { "process_name": "svchost.exe", "command_line": "svchost.exe -k netsvcs", "parent_process": "services.exe", "risk_score": 0 },
    { "process_name": "chrome.exe", "command_line": "chrome.exe", "parent_process": "explorer.exe", "risk_score": 0 },
    { "process_name": "cmd.exe", "command_line": "cmd.exe /c vol", "parent_process": "explorer.exe", "risk_score": 0 }
]

class LOLBinsGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("LOLBins Detection System")
        self.geometry("1000x600")
        self.configure(bg="#1e1e1e")
        
        self.loaded_data = [] # Will hold raw loaded log dicts
        self.filepath = None
        
        # Prepare ML model once on startup
        self.ml_model = train_anomaly_detector(DUMMY_TRAINING_DATA)
        
        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        
        # Configure overall Treeview aesthetics for dark theme
        style.configure("Treeview", 
                        background="#2d2d2d", 
                        foreground="white", 
                        fieldbackground="#2d2d2d",
                        rowheight=25,
                        font=("Arial", 10))
                        
        style.configure("Treeview.Heading", 
                        background="#3c3c3c", 
                        foreground="white", 
                        font=("Arial", 10, "bold"),
                        relief="flat")
                        
        style.map("Treeview", background=[("selected", "#505050")])
        style.map("Treeview.Heading", background=[("active", "#4a4a4a")])
        
        # Configure button styles
        style.configure("TButton", 
                        padding=6, 
                        relief="flat", 
                        background="#007acc", 
                        foreground="white",
                        font=("Arial", 10, "bold"))
        style.map("TButton", background=[("active", "#005a9e")])

    def _build_ui(self):
        # Top Frame (Controls)
        top_frame = tk.Frame(self, bg="#1e1e1e", pady=10, padx=10)
        top_frame.pack(side="top", fill="x")
        
        self.btn_load = ttk.Button(top_frame, text="Load Log File", command=self.load_log_file)
        self.btn_load.pack(side="left", padx=(0, 10))
        
        self.btn_run = ttk.Button(top_frame, text="Run Detection", command=self.run_detection)
        self.btn_run.pack(side="left", padx=(0, 10))
        
        self.lbl_filename = tk.Label(top_frame, text="No file selected...", bg="#1e1e1e", fg="white", font=("Arial", 10, "italic"))
        self.lbl_filename.pack(side="left")
        
        # Main Frame (Table view)
        main_frame = tk.Frame(self, bg="#1e1e1e", padx=10, pady=10)
        main_frame.pack(side="top", fill="both", expand=True)

        # Scrollbar and Treeview integration
        tree_scroll = ttk.Scrollbar(main_frame)
        tree_scroll.pack(side="right", fill="y")
        
        columns = ("process_name", "risk_score", "risk_level", "anomalous", "reason")
        
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", yscrollcommand=tree_scroll.set, style="Treeview")
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.config(command=self.tree.yview)
        
        # Define Headings and Column widths
        self.tree.heading("process_name", text="Process Name", anchor="w")
        self.tree.heading("risk_score", text="Risk Score", anchor="center")
        self.tree.heading("risk_level", text="Risk Level", anchor="center")
        self.tree.heading("anomalous", text="Anomalous (Y/N)", anchor="center")
        self.tree.heading("reason", text="Reason", anchor="w")
        
        self.tree.column("process_name", width=150, minwidth=100, stretch=False)
        self.tree.column("risk_score", width=80, minwidth=80, anchor="center", stretch=False)
        self.tree.column("risk_level", width=80, minwidth=80, anchor="center", stretch=False)
        self.tree.column("anomalous", width=110, minwidth=110, anchor="center", stretch=False)
        self.tree.column("reason", width=500, minwidth=300, stretch=True)

        # Configure row colors for risk levels
        self.tree.tag_configure("HIGH", background="#801515", foreground="white")     # Darker Red
        self.tree.tag_configure("MEDIUM", background="#996300", foreground="white")   # Darker Orange
        self.tree.tag_configure("LOW", background="#2a5a2a", foreground="white")      # Darker Green

    def load_log_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=(("Log files", "*.xml *.json"), ("All Files", "*.*"))
        )
        if not filepath:
            return
            
        self.filepath = filepath
        self.lbl_filename.config(text=f"Loaded: {os.path.basename(filepath)}")
        
        # Parse based on extension
        try:
            if filepath.lower().endswith(".json"):
                with open(filepath, 'r') as f:
                    self.loaded_data = json.load(f)
            else:
                self.loaded_data = parse_sysmon_xml(filepath)
                
            if not self.loaded_data:
                messagebox.showwarning("Warning", "No events found or unable to parse log file.")
                return

            # Normalize keys (sysmon_parser outputs CamelCase, our pipeline expects snake_case)
            for item in self.loaded_data:
                if "ProcessName" in item and "process_name" not in item:
                    item["process_name"] = item.pop("ProcessName", "")
                if "CommandLine" in item and "command_line" not in item:
                    item["command_line"] = item.pop("CommandLine", "")
                if "ParentProcess" in item and "parent_process" not in item:
                    item["parent_process"] = item.pop("ParentProcess", "")
                if "User" in item and "user" not in item:
                    item["user"] = item.pop("User", "")
                if "Timestamp" in item and "timestamp" not in item:
                    item["timestamp"] = item.pop("Timestamp", "")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {str(e)}")
            self.loaded_data = []

    def run_detection(self):
        if not self.loaded_data:
            messagebox.showinfo("Info", "No data loaded! Please load a log file first.")
            return

        # Clear existing table data
        for row in self.tree.get_children():
            self.tree.delete(row)

        try:
            # Run detection pipeline logic
            analyzed_logs = detect_suspicious_activity(self.loaded_data, ml_model=self.ml_model)
            
            high_risk_found = False
            
            # Populate table
            for log in analyzed_logs:
                risk_level = log.get("risk_level", "LOW")
                
                if risk_level == "HIGH":
                    high_risk_found = True
                    tag = "HIGH"
                elif risk_level == "MEDIUM":
                    tag = "MEDIUM"
                else:
                    tag = "LOW"
                    
                self.tree.insert("", "end", values=(
                    log.get("process_name", "Unknown"),
                    log.get("risk_score", 0),
                    log.get("risk_level", "LOW"),
                    "Yes" if log.get("is_anomalous") else "No",
                    log.get("reason", "")
                ), tags=(tag,))
                
            if high_risk_found:
                messagebox.showwarning("ALERT", "High Risk Activity Detected!\nReview the logs immediately.")
                
        except Exception as e:
            messagebox.showerror("Detection Error", f"An error occurred during detection: {str(e)}")

def main():
    app = LOLBinsGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
