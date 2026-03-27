import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
import datetime
import win32evtlog
import xml.etree.ElementTree as ET
import random

try:
    from detector import run_detection_pipeline
except ImportError:
    from detector import detect_suspicious_activity, train_anomaly_detector
    dummy_data = [
        {"process_name": "cmd.exe", "command_line": "cmd.exe /c exit", "parent_process": "explorer.exe", "risk_score": 0}
    ]
    _dummy_model = train_anomaly_detector(dummy_data)
    def run_detection_pipeline(log_event):
        results = detect_suspicious_activity([log_event], ml_model=_dummy_model)
        if results:
            return results[0]
        return log_event

# Styling Constants
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
TABLE_BG = "#121826"
TEXT_COLOR = "white"
ACCENT_COLOR = "#3b82f6"
HIGH_COLOR = "#ef4444"    # red
MEDIUM_COLOR = "#f59e0b"  # orange
LOW_COLOR = "#10b981"     # green

class LOLBinsMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LOLBins Monitor (Live Data)")
        self.geometry("1400x850")
        self.configure(fg_color=BG_COLOR)
        
        # State variables
        self.total_logs = 0
        self.alerts_generated = 0
        self.processing_rate = 0
        self.activity_data = [0] * 60
        self.running = True
        self.alert_counter = 0 # Starting ID
        self.alerts_history = {} # Store full alert details
        self.alert_ui_refs = {}  # UI references for dynamic updates
        self.current_filter = "All"
        self.network_cache = {}  # Store ProcessGuid -> List of Network Event dicts

        self.setup_ui()
        self.switch_view("alerts")
        
        # Start sysmon monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_sysmon_events, daemon=True)
        self.monitor_thread.start()

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Left Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, fg_color=CARD_COLOR, corner_radius=0, width=240)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ LOLBins Monitor", font=ctk.CTkFont(size=18, weight="bold"), text_color=TEXT_COLOR)
        logo_label.grid(row=0, column=0, padx=20, pady=(30, 40), sticky="w")

        # Sidebar Buttons
        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text=" Dashboard", fg_color="transparent", text_color=TEXT_COLOR, anchor="w", corner_radius=8, height=40, font=ctk.CTkFont(size=14), command=lambda: self.switch_view("dashboard"))
        self.btn_dashboard.grid(row=1, column=0, padx=15, pady=5, sticky="ew")

        self.btn_logs = ctk.CTkButton(self.sidebar_frame, text=" Logs", fg_color="transparent", text_color=TEXT_COLOR, anchor="w", corner_radius=8, height=40, font=ctk.CTkFont(size=14), command=lambda: self.switch_view("logs"))
        self.btn_logs.grid(row=2, column=0, padx=15, pady=5, sticky="ew")

        self.btn_alerts = ctk.CTkButton(self.sidebar_frame, text=" Alerts", fg_color="transparent", text_color=TEXT_COLOR, anchor="w", corner_radius=8, height=40, font=ctk.CTkFont(size=14), command=lambda: self.switch_view("alerts"))
        self.btn_alerts.grid(row=3, column=0, padx=15, pady=5, sticky="ew")
        
        # Badge for Alerts Button
        self.badge_frame = ctk.CTkFrame(self.btn_alerts, fg_color="transparent", corner_radius=10, height=20, width=24)
        self.badge_frame.place(relx=0.9, rely=0.5, anchor="e")
        self.badge_frame.pack_propagate(False)
        self.badge_label = ctk.CTkLabel(self.badge_frame, text="", font=ctk.CTkFont(size=11, weight="bold"), text_color="white")
        self.badge_label.place(relx=0.5, rely=0.5, anchor="center")

        # Bottom Profile
        profile_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        profile_frame.grid(row=6, column=0, padx=20, pady=20, sticky="ew")
        icon_lbl = ctk.CTkLabel(profile_frame, text="AD", width=36, height=36, fg_color="#334155", corner_radius=18, font=ctk.CTkFont(weight="bold"))
        icon_lbl.pack(side="left")
        name_frame = ctk.CTkFrame(profile_frame, fg_color="transparent")
        name_frame.pack(side="left", padx=10)
        ctk.CTkLabel(name_frame, text="Admin User", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=0)
        ctk.CTkLabel(name_frame, text="Security Analyst", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="w", pady=0)

        # 2. Content Container
        self.content_container = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0)
        self.content_container.grid(row=0, column=1, sticky="nsew")

        # Initialize all Views
        self.setup_dashboard_view()
        self.setup_alerts_view()
        self.setup_logs_view()
        
        self.current_view_frame = None

    def setup_dashboard_view(self):
        self.dashboard_view = ctk.CTkFrame(self.content_container, fg_color=BG_COLOR, corner_radius=0)
        self.dashboard_view.grid_columnconfigure(0, weight=3)
        self.dashboard_view.grid_columnconfigure(1, weight=1)
        self.dashboard_view.grid_rowconfigure(1, weight=1)

        left_content = ctk.CTkFrame(self.dashboard_view, fg_color="transparent")
        left_content.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=20, pady=20)
        left_content.grid_columnconfigure((0, 1, 2, 3), weight=1)
        left_content.grid_rowconfigure(1, weight=1)

        self.card_logs_val = self.create_card(left_content, "Total Logs", "0", 0, 0)
        self.card_alerts_val = self.create_card(left_content, "Active Alerts", "0", 0, 1) # Changed title to Active Alerts
        self.card_status_val = self.create_card(left_content, "Status", "Active", 0, 2, val_color=LOW_COLOR)
        self.card_rate_val = self.create_card(left_content, "Rate", "0 /sec", 0, 3)

        graph_frame = ctk.CTkFrame(left_content, fg_color=CARD_COLOR, corner_radius=15)
        graph_frame.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(20, 0))
        self.setup_matplotlib_graph(graph_frame)

        alerts_panel = ctk.CTkFrame(self.dashboard_view, fg_color=CARD_COLOR, corner_radius=15)
        alerts_panel.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(0, 20), pady=20)
        alerts_panel.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(alerts_panel, text="Recent Alerts", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, padx=20, pady=20, sticky="w")
        self.dashboard_alerts_list = ctk.CTkScrollableFrame(alerts_panel, fg_color="transparent")
        self.dashboard_alerts_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def setup_alerts_view(self):
        self.alerts_view = ctk.CTkFrame(self.content_container, fg_color=BG_COLOR, corner_radius=0)
        
        header_frame = ctk.CTkFrame(self.alerts_view, fg_color="transparent")
        header_frame.pack(fill="x", padx=40, pady=(40, 20))
        
        ctk.CTkLabel(header_frame, text="Alert Management", font=ctk.CTkFont(size=26, weight="bold"), text_color=TEXT_COLOR).pack(side="left")
        
        status_pill = ctk.CTkFrame(header_frame, fg_color="#064e3b", corner_radius=15)
        status_pill.pack(side="right")
        ctk.CTkLabel(status_pill, text="● System Normal", text_color="#34d399", font=ctk.CTkFont(size=12, weight="bold")).pack(padx=15, pady=4)
        
        tools_frame = ctk.CTkFrame(self.alerts_view, fg_color="transparent")
        tools_frame.pack(fill="x", padx=40, pady=(0, 20))
        search_entry = ctk.CTkEntry(tools_frame, placeholder_text="Search alerts by ID, Host, or User...", width=300, height=35, fg_color=TABLE_BG, border_color="#334155")
        search_entry.pack(side="left", padx=(0, 15))
        self.filter_menu = ctk.CTkOptionMenu(tools_frame, values=["All", "High", "Medium", "Low"], width=100, height=35, fg_color=TABLE_BG, button_color=TABLE_BG, button_hover_color="#334155", text_color="#94a3b8", command=self.apply_filter)
        self.filter_menu.pack(side="left", padx=5)
        ctk.CTkButton(tools_frame, text="Export", width=80, height=35, fg_color=TABLE_BG, hover_color="#334155", border_width=1, border_color="#334155", text_color="#94a3b8").pack(side="left", padx=5)
        
        table_container = ctk.CTkFrame(self.alerts_view, fg_color=TABLE_BG, corner_radius=10, border_width=1, border_color="#1e293b")
        table_container.pack(fill="both", expand=True, padx=40, pady=(0, 40))
        
        thead = ctk.CTkFrame(table_container, fg_color="transparent", height=50)
        # Pad the right side strictly by 16px to offset the scrollbar rendering directly beneath this header.
        thead.pack(fill="x", padx=(10, 26), pady=5)
        
        self.col_weights = [1, 1, 2, 2, 2, 1, 1]
        cols = ["Alert ID", "Severity", "Process Name", "Host / User", "Timestamp", "Status", "Actions"]
        for i, (col, w) in enumerate(zip(cols, self.col_weights)):
            thead.grid_columnconfigure(i, weight=w)
            ctk.CTkLabel(thead, text=col, text_color="#94a3b8", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=i, padx=10, pady=10, sticky="w")
            
        ctk.CTkFrame(table_container, height=1, fg_color="#1e293b").pack(fill="x")
        self.alerts_table_body = ctk.CTkScrollableFrame(table_container, fg_color="transparent")
        self.alerts_table_body.pack(fill="both", expand=True, padx=10, pady=5)

    def setup_logs_view(self):
        """ Setup the detailed Alert Investigation page """
        self.logs_view = ctk.CTkFrame(self.content_container, fg_color=BG_COLOR, corner_radius=0)
        
        # Header (Back, export, resolve)
        header_frame = ctk.CTkFrame(self.logs_view, fg_color="transparent")
        header_frame.pack(fill="x", padx=40, pady=(30, 10))
        
        back_btn = ctk.CTkLabel(header_frame, text="← Back to Alerts", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8", cursor="hand2")
        back_btn.pack(side="left", anchor="n")
        back_btn.bind("<Button-1>", lambda e: self.switch_view("alerts"))
        
        actions_fr = ctk.CTkFrame(header_frame, fg_color="transparent")
        actions_fr.pack(side="right")
        ctk.CTkButton(actions_fr, text="Export\nReport", fg_color="transparent", border_width=1, border_color="#334155", text_color="#94a3b8", width=100, height=35).pack(side="left", padx=10)
        self.btn_resolve = ctk.CTkButton(actions_fr, text="✔️ Mark as Resolved", fg_color=ACCENT_COLOR, text_color="white", width=140, height=35, cursor="hand2", command=self.resolve_current_alert)
        self.btn_resolve.pack(side="left")
        
        self.current_viewed_alert_id = None
        
        # Title
        self.log_title = ctk.CTkLabel(self.logs_view, text="Alert Investigation: Select an Alert", font=ctk.CTkFont(size=24, weight="bold"), text_color="white")
        self.log_title.pack(fill="x", padx=40, pady=(0, 20), anchor="w")
        
        # Main Grid
        content_grid = ctk.CTkFrame(self.logs_view, fg_color="transparent")
        content_grid.pack(fill="both", expand=True, padx=40, pady=(0, 30))
        content_grid.grid_columnconfigure(0, weight=1)
        content_grid.grid_columnconfigure(1, weight=2)
        content_grid.grid_rowconfigure(0, weight=1)
        content_grid.grid_rowconfigure(1, weight=1)

        # 1. Alert Summary Card (Left Top)
        self.summary_card = ctk.CTkFrame(content_grid, fg_color=CARD_COLOR, corner_radius=10)
        self.summary_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))
        
        sum_top = ctk.CTkFrame(self.summary_card, fg_color="transparent")
        sum_top.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(sum_top, text="Alert Summary", text_color="#94a3b8").pack(side="left")
        self.log_sum_status = ctk.CTkLabel(sum_top, text="New", fg_color="#1e3a8a", text_color="#60a5fa", corner_radius=12, width=60)
        self.log_sum_status.pack(side="right")
        
        # Info grid inside Summary
        self.log_sum_time = self._add_info_row(self.summary_card, "Detection Time", "N/A")
        self.log_sum_sev = self._add_info_row(self.summary_card, "Severity", "N/A")
        self.log_sum_rule = self._add_info_row(self.summary_card, "Rule Name", "N/A")
        self.log_sum_tech = self._add_info_row(self.summary_card, "Technique", "T1059 - Process Execution")
        self.log_sum_host = self._add_info_row(self.summary_card, "Host", "N/A")
        self.log_sum_user = self._add_info_row(self.summary_card, "User", "N/A")

        # 2. Process Tree Visualization (Left Bottom)
        self.tree_card = ctk.CTkFrame(content_grid, fg_color=CARD_COLOR, corner_radius=10)
        self.tree_card.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(10, 0))
        ctk.CTkLabel(self.tree_card, text="Process Tree Visualization", text_color="#94a3b8").pack(anchor="w", padx=20, pady=20)
        
        self.tree_content_box = ctk.CTkScrollableFrame(self.tree_card, fg_color="transparent")
        self.tree_content_box.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # 3. Process Execution Details (Right Top)
        self.exec_card = ctk.CTkFrame(content_grid, fg_color=CARD_COLOR, corner_radius=10)
        self.exec_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=(0, 10))
        ctk.CTkLabel(self.exec_card, text="Process Execution Details", text_color="#94a3b8").pack(anchor="w", padx=20, pady=(20, 10))
        
        exec_info_frame = ctk.CTkFrame(self.exec_card, fg_color="transparent")
        exec_info_frame.pack(fill="x", padx=20)
        exec_info_frame.grid_columnconfigure((0,1,2), weight=1)
        
        self.log_exec_name = self._add_exec_info(exec_info_frame, "Process Name", "N/A", 0)
        self.log_exec_pid = self._add_exec_info(exec_info_frame, "Process ID (PID)", "N/A", 1)
        self.log_exec_parent = self._add_exec_info(exec_info_frame, "Parent Process", "N/A", 2)
        
        ctk.CTkLabel(self.exec_card, text="Command Line", text_color="#94a3b8").pack(anchor="w", padx=20, pady=(15, 5))
        cmd_box = ctk.CTkFrame(self.exec_card, fg_color="#0f172a", corner_radius=5)
        cmd_box.pack(fill="x", padx=20, pady=5)
        self.log_exec_cmd = ctk.CTkTextbox(cmd_box, fg_color="transparent", text_color="#e2e8f0", font=ctk.CTkFont(family="Consolas", size=13), height=60, wrap="word")
        self.log_exec_cmd.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_exec_cmd.insert("1.0", "N/A")
        self.log_exec_cmd.configure(state="disabled")
        
        ctk.CTkLabel(self.exec_card, text="Matched Indicators / Reason", text_color="#94a3b8").pack(anchor="w", padx=20, pady=(15, 0))
        
        reason_box = ctk.CTkFrame(self.exec_card, fg_color="#0f172a", corner_radius=5)
        reason_box.pack(fill="x", padx=20, pady=5)
        self.log_exec_reason = ctk.CTkTextbox(reason_box, fg_color="transparent", text_color="#ef4444", font=ctk.CTkFont(size=13, weight="bold"), height=70, wrap="word")
        self.log_exec_reason.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_exec_reason.insert("1.0", "N/A")
        self.log_exec_reason.configure(state="disabled")
        
        ctk.CTkLabel(self.exec_card, text="Hash (SHA256)", text_color="#94a3b8").pack(anchor="w", padx=20, pady=(15, 0))
        self.log_exec_hash = ctk.CTkLabel(self.exec_card, text="N/A", text_color="#e2e8f0", font=ctk.CTkFont(family="Consolas", size=11))
        self.log_exec_hash.pack(anchor="w", padx=20, pady=(5, 30))

        # 4. Network Activity (Right Bottom)
        self.net_card = ctk.CTkFrame(content_grid, fg_color=CARD_COLOR, corner_radius=10)
        self.net_card.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))
        ctk.CTkLabel(self.net_card, text="Network Activity", text_color="#94a3b8").pack(anchor="w", padx=20, pady=20)
        
        net_headers = ctk.CTkFrame(self.net_card, fg_color="transparent")
        # Offset right padding by 16px specifically to account for ScrollableFrame scrollbar below
        net_headers.pack(fill="x", padx=(20, 36), pady=(0, 5))
        cols = ["Direction", "Destination IP", "Domain", "Port", "Protocol"]
        for i, c in enumerate(cols):
            net_headers.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(net_headers, text=c, text_color="#94a3b8", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=i, sticky="w")
            
        ctk.CTkFrame(self.net_card, height=1, fg_color="#334155").pack(fill="x", padx=20, pady=5)
        self.net_table = ctk.CTkScrollableFrame(self.net_card, fg_color="transparent")
        self.net_table.pack(fill="both", expand=True, padx=20, pady=(0,20))

    def _add_info_row(self, parent, title, value):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=20, pady=8)
        ctk.CTkLabel(f, text=title, text_color="#94a3b8", width=100, anchor="w").pack(side="left")
        val_lbl = ctk.CTkLabel(f, text=value, text_color=TEXT_COLOR, anchor="w", justify="left")
        val_lbl.pack(side="left", fill="x", expand=True, padx=(10,0))
        ctk.CTkFrame(parent, height=1, fg_color="#334155").pack(fill="x", padx=20, pady=2)
        return val_lbl

    def _add_exec_info(self, parent, title, value, col):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.grid(row=0, column=col, sticky="w")
        ctk.CTkLabel(f, text=title, text_color="#94a3b8", font=ctk.CTkFont(size=12)).pack(anchor="w")
        val = ctk.CTkLabel(f, text=value, text_color=TEXT_COLOR, font=ctk.CTkFont(size=13, weight="bold"))
        val.pack(anchor="w", pady=2)
        return val

    def load_alert_to_logs_view(self, alert_id):
        if alert_id not in self.alerts_history: return
        self.switch_view("logs")
        self.current_viewed_alert_id = alert_id
        
        data = self.alerts_history[alert_id]
        event = data["event"]
        risk = data["risk"]
        reason = data["reason"]
        
        r_score = event.get("risk_score", 0)
        
        self.log_title.configure(text=f"Alert Investigation: {alert_id}")
        self.log_sum_time.configure(text=data["timestamp"])
        
        color = HIGH_COLOR if risk.upper() == "HIGH" else MEDIUM_COLOR if risk.upper() == "MEDIUM" else LOW_COLOR
        icon = "⚠️" if risk.upper() == "HIGH" else "⚡" if risk.upper() == "MEDIUM" else "ℹ️"
        self.log_sum_sev.configure(text=f"{icon} {risk.capitalize()} (Risk Score: {r_score})", text_color=color)
        
        self.log_sum_rule.configure(text=reason.split(" (+")[0]) # Shorten rule name
        host = event["user"].split("\\")[0] if "\\" in event["user"] else "Unknown"
        self.log_sum_host.configure(text=host)
        self.log_sum_user.configure(text=event["user"])
        
        stat = data["status"]
        pill_bg = "#1e3a8a" if stat == "New" else "#78350f" if "Review" in stat else "#14532d"
        pill_fg = "#60a5fa" if stat == "New" else "#fbbf24" if "Review" in stat else "#4ade80"
        self.log_sum_status.configure(text=stat, fg_color=pill_bg, text_color=pill_fg)

        if stat == "Resolved":
            self.btn_resolve.configure(state="disabled", fg_color="#334155")
        else:
            self.btn_resolve.configure(state="normal", fg_color=ACCENT_COLOR)

        proc_basename = event["process_name"].split("\\")[-1]
        parent_basename = event["parent_process"].split("\\")[-1]

        self.log_exec_name.configure(text=proc_basename)
        self.log_exec_pid.configure(text=event.get("process_id", "Unknown"))
        self.log_exec_parent.configure(text=f"{parent_basename} (PID: {event.get('parent_process_id', 'Unknown')})")
        
        self.log_exec_cmd.configure(state="normal")
        self.log_exec_cmd.delete("1.0", "end")
        self.log_exec_cmd.insert("1.0", event.get("command_line", "Unknown"))
        self.log_exec_cmd.configure(state="disabled")
        
        self.log_exec_reason.configure(state="normal")
        self.log_exec_reason.delete("1.0", "end")
        if risk.upper() == "LOW" or not reason:
            self.log_exec_reason.insert("1.0", "• No malicious signatures detected")
            self.log_exec_reason.configure(text_color="#10b981")
        else:
            formatted = reason.replace(" | ", "\n• ")
            if not formatted.startswith("•"): formatted = "• " + formatted
            self.log_exec_reason.insert("1.0", formatted)
            self.log_exec_reason.configure(text_color="#ef4444")
        self.log_exec_reason.configure(state="disabled")
            
        self.log_exec_hash.configure(text=event.get("sha256", "No SHA256 in log"))

        # Render Tree
        for widget in self.tree_content_box.winfo_children(): widget.destroy()
            
        p_frame = ctk.CTkFrame(self.tree_content_box, fg_color="transparent")
        p_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(p_frame, text=f"📄 {parent_basename} ({event.get('parent_process_id', 'Unknown')})", text_color="#94a3b8").pack(side="left")
        
        c_frame = ctk.CTkFrame(self.tree_content_box, fg_color="transparent")
        c_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(c_frame, text="   ↳ ", text_color="#94a3b8").pack(side="left")
        
        alert_box = ctk.CTkFrame(c_frame, fg_color="#450a0a", corner_radius=5, border_width=1, border_color="#7f1d1d")
        alert_box.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(alert_box, text=f"⭐ {proc_basename} ({event.get('process_id', 'Unknown')})", text_color="#ef4444", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=10, pady=5)
        ctk.CTkLabel(alert_box, text="ALERT", fg_color="#b91c1c", text_color="white", corner_radius=5, font=ctk.CTkFont(size=10, weight="bold")).pack(side="right", padx=10, pady=5)

        # Render Network Activity
        for w in self.net_table.winfo_children(): w.destroy()
        p_guid = str(event.get("process_guid", ""))
        net_events = self.network_cache.get(p_guid, [])
        if not net_events:
            ctk.CTkLabel(self.net_table, text="No outbound or inbound network activity mapped to this process.", text_color="#64748b").pack(pady=30)
        else:
            for idx, ne in enumerate(net_events):
                row_f = ctk.CTkFrame(self.net_table, fg_color="transparent")
                row_f.pack(fill="x", pady=5)
                for i in range(5): row_f.grid_columnconfigure(i, weight=1)
                
                clr = "#3b82f6" if ne["direction"] == "Outbound" else "#10b981"
                ctk.CTkLabel(row_f, text=ne["direction"], text_color=clr, font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w")
                ctk.CTkLabel(row_f, text=ne["dest_ip"], text_color="white").grid(row=0, column=1, sticky="w")
                dom = ne["domain"]
                ctk.CTkLabel(row_f, text=dom if dom else "-", text_color="white").grid(row=0, column=2, sticky="w")
                ctk.CTkLabel(row_f, text=ne["dest_port"], text_color="white").grid(row=0, column=3, sticky="w")
                protocol_text = ne["protocol"].capitalize() if ne["protocol"] else "Unknown"
                ctk.CTkLabel(row_f, text=protocol_text, text_color="#94a3b8").grid(row=0, column=4, sticky="w")
                
                if idx < len(net_events) - 1:
                    ctk.CTkFrame(self.net_table, height=1, fg_color="#1e293b").pack(fill="x", pady=2)

    def resolve_current_alert(self):
        if not self.current_viewed_alert_id: return
        aid = self.current_viewed_alert_id
        if self.alerts_history[aid]["status"] == "Resolved": return
        
        # 1. Update data
        self.alerts_history[aid]["status"] = "Resolved"
        
        # 2. Update active badges/stats
        if self.alerts_generated > 0:
            self.alerts_generated -= 1
            self.card_alerts_val.configure(text=str(self.alerts_generated))
            if self.alerts_generated > 0:
                self.badge_label.configure(text=str(self.alerts_generated))
            else:
                self.badge_label.configure(text="")
                self.badge_frame.configure(fg_color="transparent")
                
        # 3. Update Logs view pill immediately
        pill_bg, pill_fg = "#14532d", "#4ade80"
        self.log_sum_status.configure(text="Resolved", fg_color=pill_bg, text_color=pill_fg)
        self.btn_resolve.configure(state="disabled", fg_color="#334155")
        
        # 4. Global UI Updates (Alerts Table, Dashboard list)
        if aid in self.alert_ui_refs:
            refs = self.alert_ui_refs[aid]
            if "table_status_frame" in refs:
                refs["table_status_frame"].configure(fg_color=pill_bg)
                refs["table_status_lbl"].configure(text="Resolved", text_color=pill_fg)
            if "dashboard_status_lbl" in refs:
                # Append [Resolved] and turn green text to denote it's dealt with
                orig_text = refs["dashboard_status_lbl"].cget("text")
                if "[Resolved]" not in orig_text:
                    refs["dashboard_status_lbl"].configure(text=f"{orig_text} [Resolved]", text_color=LOW_COLOR)

    def switch_view(self, view_name):
        if self.current_view_frame:
            self.current_view_frame.pack_forget()
            
        self.btn_dashboard.configure(fg_color="transparent")
        self.btn_alerts.configure(fg_color="transparent")
        self.btn_logs.configure(fg_color="transparent")
        
        if view_name == "dashboard":
            self.dashboard_view.pack(fill="both", expand=True)
            self.btn_dashboard.configure(fg_color=ACCENT_COLOR)
            self.current_view_frame = self.dashboard_view
        elif view_name == "alerts":
            self.alerts_view.pack(fill="both", expand=True)
            self.btn_alerts.configure(fg_color=ACCENT_COLOR)
            self.current_view_frame = self.alerts_view
        elif view_name == "logs":
            self.logs_view.pack(fill="both", expand=True)
            self.btn_logs.configure(fg_color=ACCENT_COLOR)
            self.current_view_frame = self.logs_view

    # --- Dash Helpers ---
    def create_card(self, parent, title, value, row, col, val_color=TEXT_COLOR):
        card = ctk.CTkFrame(parent, fg_color=CARD_COLOR, corner_radius=15, height=120)
        card.grid(row=row, column=col, sticky="nsew", padx=10, pady=5)
        card.grid_propagate(False)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color="#94a3b8").pack(padx=20, pady=(20, 5), anchor="w")
        val_lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=28, weight="bold"), text_color=val_color)
        val_lbl.pack(padx=20, pady=(0, 20), anchor="w")
        return val_lbl

    def setup_matplotlib_graph(self, parent):
        plt.style.use('dark_background')
        self.fig, self.ax = plt.subplots(figsize=(8, 4), facecolor=CARD_COLOR)
        self.ax.set_facecolor(CARD_COLOR)
        self.ax.set_title("Activity Trend", color=TEXT_COLOR, pad=20, fontsize=16, loc="left", fontweight="bold")
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.spines['bottom'].set_color('#475569')
        self.ax.spines['left'].set_color('#475569')
        self.ax.tick_params(colors='#94a3b8', labelsize=10)
        self.ax.grid(True, linestyle="--", linewidth=0.5, color="#334155", alpha=0.7)

        self.line, = self.ax.plot(self.activity_data, color=ACCENT_COLOR, linewidth=3)
        self.fill = self.ax.fill_between(range(len(self.activity_data)), self.activity_data, color=ACCENT_COLOR, alpha=0.2)
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, 60)
        self.fig.tight_layout()
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

    def add_table_row(self, alert_id, risk, process_name, user, timestamp, status_text):
        row_frame = ctk.CTkFrame(self.alerts_table_body, fg_color="transparent")
        row_frame.pack(fill="x", pady=2)
        
        for i, w in enumerate(self.col_weights):
            row_frame.grid_columnconfigure(i, weight=w)
            
        color = HIGH_COLOR if risk.upper() == "HIGH" else MEDIUM_COLOR if risk.upper() == "MEDIUM" else LOW_COLOR
        icon = "⚠️" if risk.upper() == "HIGH" else "⚡" if risk.upper() == "MEDIUM" else "ℹ️"
        sev_text = f"{icon} {risk.capitalize()}"
        
        # ID
        ctk.CTkLabel(row_frame, text=alert_id, text_color="#94a3b8", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=12, sticky="w")
        # Severity
        ctk.CTkLabel(row_frame, text=sev_text, text_color=color, font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=1, padx=10, pady=12, sticky="w")
        # Process
        ctk.CTkLabel(row_frame, text=process_name, text_color=TEXT_COLOR, font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=10, pady=12, sticky="w")
        # Host/User
        ctk.CTkLabel(row_frame, text=user, text_color=TEXT_COLOR, font=ctk.CTkFont(size=12)).grid(row=0, column=3, padx=10, pady=12, sticky="w")
        # Timestamp
        ctk.CTkLabel(row_frame, text=timestamp, text_color="#94a3b8", font=ctk.CTkFont(size=12)).grid(row=0, column=4, padx=10, pady=12, sticky="w")
        
        # Status
        pill_bg = "#1e3a8a" if status_text == "New" else "#78350f" if "Review" in status_text else "#14532d"
        pill_fg = "#60a5fa" if status_text == "New" else "#fbbf24" if "Review" in status_text else "#4ade80"
        
        status_frame = ctk.CTkFrame(row_frame, fg_color=pill_bg, corner_radius=12, width=80, height=26)
        status_frame.grid(row=0, column=5, padx=10, pady=12, sticky="w")
        status_frame.pack_propagate(False)
        status_lbl = ctk.CTkLabel(status_frame, text=status_text, font=ctk.CTkFont(size=11, weight="bold"), text_color=pill_fg)
        status_lbl.pack(expand=True)
        
        if alert_id not in self.alert_ui_refs: self.alert_ui_refs[alert_id] = {}
        self.alert_ui_refs[alert_id]["table_status_frame"] = status_frame
        self.alert_ui_refs[alert_id]["table_status_lbl"] = status_lbl
        
        # Actions
        actions_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        actions_frame.grid(row=0, column=6, padx=10, pady=12, sticky="w")
        
        eye_btn = ctk.CTkLabel(actions_frame, text="👁️", text_color="#94a3b8", cursor="hand2", font=ctk.CTkFont(size=14))
        eye_btn.pack(side="left", padx=5)
        # Bind the eye icon to load the detailed view
        eye_btn.bind("<Button-1>", lambda event, aid=alert_id: self.load_alert_to_logs_view(aid))
        
        # Optional: bind checkmark to rapid-resolve
        check_btn = ctk.CTkLabel(actions_frame, text="✔️", text_color="#94a3b8", cursor="hand2", font=ctk.CTkFont(size=14))
        check_btn.pack(side="left", padx=5)
        check_btn.bind("<Button-1>", lambda event, aid=alert_id: self._rapid_resolve_alert(aid))

        ctk.CTkFrame(self.alerts_table_body, height=1, fg_color="#1e293b").pack(fill="x", pady=2)

    def _rapid_resolve_alert(self, alert_id):
        self.current_viewed_alert_id = alert_id
        self.resolve_current_alert()

    def apply_filter(self, choice):
        self.current_filter = choice
        self.refresh_alerts_table()
        
    def refresh_alerts_table(self):
        for widget in self.alerts_table_body.winfo_children():
            widget.destroy()
            
        for aid in list(self.alert_ui_refs.keys()):
            self.alert_ui_refs[aid].pop("table_status_frame", None)
            self.alert_ui_refs[aid].pop("table_status_lbl", None)
            
        sorted_alerts = sorted(self.alerts_history.items(), key=lambda x: x[0])
        
        for aid, data in sorted_alerts:
            risk = data["risk"]
            if self.current_filter != "All" and risk.upper() != self.current_filter.upper():
                continue
            proc = data["event"].get("process_name", "Unknown").split("\\")[-1]
            user = data["event"].get("user", "Unknown")
            self.add_table_row(aid, risk, proc, user, data["timestamp"], data["status"])

    def update_graph(self):
        self.line.set_ydata(self.activity_data)
        self.fill.remove()
        self.fill = self.ax.fill_between(range(len(self.activity_data)), self.activity_data, color=ACCENT_COLOR, alpha=0.2)
        max_val = max(100, max(self.activity_data) + 20)
        self.ax.set_ylim(0, max_val)
        self.canvas.draw()

    # --- Live Polling ---
    def handle_sysmon_error(self):
        self.card_status_val.configure(text="Error", text_color=HIGH_COLOR)

    def handle_new_alert(self, event_dict, risk, reason, process_name, user):
        timestamp = datetime.datetime.now().strftime("%b %d, %H:%M:%S")
        self.alert_counter += 1
        year = datetime.datetime.now().year
        alert_id = f"#ALT-{year}-{(self.alert_counter):03d}"
        
        status_text = "New" if risk.upper() in ["HIGH", "MEDIUM"] else "Reviewed"
        self.alerts_history[alert_id] = {
            "event": event_dict,
            "risk": risk,
            "reason": reason,
            "timestamp": timestamp,
            "status": status_text
        }

        if alert_id not in self.alert_ui_refs: self.alert_ui_refs[alert_id] = {}

        # Update Sidebar Badges and Dashboard Cards if Actionable
        if risk.upper() in ["HIGH", "MEDIUM"]:
            self.alerts_generated += 1
            self.card_alerts_val.configure(text=str(self.alerts_generated))
            self.badge_label.configure(text=str(self.alerts_generated))
            self.badge_frame.configure(fg_color=ACCENT_COLOR) # Enable visual badge color
            
            # Dashboard Overview Panel
            dash_frame = ctk.CTkFrame(self.dashboard_alerts_list, fg_color=BG_COLOR, corner_radius=10, cursor="hand2")
            dash_frame.pack(fill="x", pady=5, padx=5)
            color = HIGH_COLOR if risk.upper() == "HIGH" else MEDIUM_COLOR
            hf = ctk.CTkFrame(dash_frame, fg_color="transparent", cursor="hand2")
            hf.pack(fill="x", padx=15, pady=(15, 5))
            
            status_lbl = ctk.CTkLabel(hf, text=f"[{risk}] {process_name}", font=ctk.CTkFont(size=13, weight="bold"), text_color=color, cursor="hand2")
            status_lbl.pack(side="left")
            self.alert_ui_refs[alert_id]["dashboard_status_lbl"] = status_lbl
            
            eye_btn = ctk.CTkLabel(hf, text="👁️", cursor="hand2", text_color="#94a3b8", font=ctk.CTkFont(size=14))
            eye_btn.pack(side="right", padx=10)
            
            time_lbl = ctk.CTkLabel(hf, text=timestamp, font=ctk.CTkFont(size=11), text_color="#94a3b8", cursor="hand2")
            time_lbl.pack(side="right")
            
            user_lbl = ctk.CTkLabel(dash_frame, text=f"User: {user}", font=ctk.CTkFont(size=12), cursor="hand2")
            user_lbl.pack(fill="x", padx=15, pady=(0, 15), anchor="w")
            
            # Master Bind
            for w in [dash_frame, hf, status_lbl, eye_btn, time_lbl, user_lbl]:
                w.bind("<Button-1>", lambda e, aid=alert_id: self.load_alert_to_logs_view(aid))

        # Automatically populates table row if it matches current filter
        if self.current_filter == "All" or risk.upper() == self.current_filter.upper():
            self.add_table_row(alert_id, risk, process_name, user, timestamp, status_text)

    def update_stats_dashboard(self):
        self.card_logs_val.configure(text=str(self.total_logs))
        self.card_rate_val.configure(text=f"{self.processing_rate} /sec")
        self.activity_data.pop(0)
        self.activity_data.append(self.processing_rate)
        self.update_graph()

    def parse_sysmon_xml(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            event_id_elem = root.find(".//e:EventID", ns)
            if event_id_elem is None or event_id_elem.text not in ["1", "3"]:
                return None
            event_id = event_id_elem.text
                
            timestamp_elem = root.find(".//e:TimeCreated", ns)
            timestamp = timestamp_elem.attrib.get("SystemTime", "") if timestamp_elem is not None else ""
            
            event_data = root.find(".//e:EventData", ns)
            if event_data is None: return None
                
            data_dict = {}
            for data in event_data.findall("e:Data", ns):
                name = data.get("Name")
                value = data.text if data.text else ""
                data_dict[name] = value

            process_guid = data_dict.get("ProcessGuid", "Unknown")

            if event_id == "1":
                hashes_raw = data_dict.get("Hashes", "")
                sha256 = "Unknown"
                for h in hashes_raw.split(","):
                    if h.startswith("SHA256="):
                        sha256 = h.split("=")[1]
                        break

                return {
                    "type": "ProcessCreate",
                    "process_name": data_dict.get("Image", "Unknown"),
                    "command_line": data_dict.get("CommandLine", "Unknown"),
                    "parent_process": data_dict.get("ParentImage", "Unknown"),
                    "user": data_dict.get("User", "Unknown"),
                    "timestamp": timestamp,
                    "process_id": data_dict.get("ProcessId", "Unknown"),
                    "parent_process_id": data_dict.get("ParentProcessId", "Unknown"),
                    "process_guid": process_guid,
                    "sha256": sha256,
                    "risk_score": 0
                }
            elif event_id == "3":
                return {
                    "type": "NetworkConnect",
                    "process_guid": process_guid,
                    "direction": "Outbound" if data_dict.get("Initiated") == "true" else "Inbound",
                    "dest_ip": data_dict.get("DestinationIp", "Unknown"),
                    "dest_port": data_dict.get("DestinationPort", "Unknown"),
                    "domain": data_dict.get("DestinationHostname", ""),
                    "protocol": data_dict.get("Protocol", "Unknown"),
                    "timestamp": timestamp
                }
        except Exception:
            return None

    def monitor_sysmon_events(self):
        log_channel = "Microsoft-Windows-Sysmon/Operational"
        last_processed_timestamp = ""
        events_this_sec = 0
        last_ui_update = time.time()
        
        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            win32evtlog.EvtQuery(log_channel, flags, "*[System[(EventID=1) or (EventID=3)]]")
        except Exception as e:
            print(f"Error accessing Sysmon channel: {e}")
            self.after(0, self.handle_sysmon_error)
            return

        while self.running:
            time.sleep(1)
            
            current_time = time.time()
            try:
                flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
                query_handle = win32evtlog.EvtQuery(log_channel, flags, "*[System[(EventID=1) or (EventID=3)]]")
                events = win32evtlog.EvtNext(query_handle, 50, 100, 0)
                
                if events:
                    parsed_batch = []
                    for ev in events:
                        xml_content = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                        parsed = self.parse_sysmon_xml(xml_content)
                        if parsed:
                            parsed_batch.append(parsed)
                    
                    parsed_batch.sort(key=lambda x: x.get("timestamp", ""))
                    
                    if not last_processed_timestamp and parsed_batch:
                        last_processed_timestamp = parsed_batch[-1].get("timestamp", "")
                    
                    for parsed_event in parsed_batch:
                        ts = parsed_event.get("timestamp", "")
                        if ts > last_processed_timestamp:
                            last_processed_timestamp = ts
                            events_this_sec += 1
                            self.total_logs += 1
                            
                            if parsed_event.get("type") == "NetworkConnect":
                                p_guid = parsed_event.get("process_guid")
                                if p_guid not in self.network_cache:
                                    self.network_cache[p_guid] = []
                                self.network_cache[p_guid].append(parsed_event)
                                continue
                            
                            try:
                                result = run_detection_pipeline(parsed_event)
                                risk = result.get("risk_level", "LOW")
                                reason = result.get("reason", "No suspicious activity detected.")
                            except Exception:
                                risk = "LOW"
                                reason = "Pipeline fallback logic."
                                
                            proc_basename = parsed_event["process_name"].split("\\")[-1]
                            user = parsed_event["user"]
                            self.after(0, self.handle_new_alert, parsed_event, risk, reason, proc_basename, user)

            except Exception as e:
                pass

            if current_time - last_ui_update >= 1.0:
                self.processing_rate = events_this_sec
                events_this_sec = 0
                last_ui_update = current_time
                self.after(0, self.update_stats_dashboard)

if __name__ == "__main__":
    app = LOLBinsMonitorApp()
    app.protocol("WM_DELETE_WINDOW", app.destroy)
    app.mainloop()
