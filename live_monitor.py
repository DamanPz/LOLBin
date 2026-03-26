import win32evtlog
import xml.etree.ElementTree as ET
import time
import ctypes
import os

from detector import detect_suspicious_activity, train_anomaly_detector

def get_ml_model():
    dummy_data = [
        {"process_name": "explorer.exe", "command_line": "explorer.exe", "parent_process": "userinit.exe", "risk_score": 0},
        {"process_name": "svchost.exe", "command_line": "svchost.exe -k netsvcs", "parent_process": "services.exe", "risk_score": 0}
    ]
    return train_anomaly_detector(dummy_data)

def parse_sysmon_xml(xml_string):
    """ Parses the Event XML from PyWin32 into our expected dictionary format """
    try:
        root = ET.fromstring(xml_string)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        
        event_id_elem = root.find(".//e:EventID", ns)
        if event_id_elem is None or event_id_elem.text != "1":
            return None # Not process creation
            
        timestamp_elem = root.find(".//e:TimeCreated", ns)
        timestamp = timestamp_elem.attrib.get("SystemTime", "") if timestamp_elem is not None else ""
        
        event_data = root.find(".//e:EventData", ns)
        if event_data is None:
            return None
            
        data_dict = {}
        for data in event_data.findall("e:Data", ns):
            name = data.get("Name")
            value = data.text if data.text else ""
            data_dict[name] = value
            
        # Extract base executable name from the full path to make console output readable
        full_image_path = data_dict.get("Image", "")
        # But we must pass full process_name since our pipeline might expect it or it doesn't matter since pipeline checks `in process_name`.
        
        return {
            "process_name": full_image_path,
            "command_line": data_dict.get("CommandLine", ""),
            "parent_process": data_dict.get("ParentImage", ""),
            "user": data_dict.get("User", ""),
            "timestamp": timestamp
        }
    except Exception as e:
        return None

def main():
    print("Initializing LOLBins Real-Time Monitor...")
    ml_model = get_ml_model()
    log_channel = "Microsoft-Windows-Sysmon/Operational"
    
    print(f"Connecting to {log_channel}...")
    
    try:
        print("Ready. Monitoring for new Event ID 1 (Process Creation) logs...")
        print("Press Ctrl+C to stop.\n")
        
        last_processed_timestamp = ""
        
        while True:
            # 8. Add delay: time.sleep(2)
            time.sleep(2)
            
            # Query the newest events by reading in Reverse Direction
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(log_channel, flags, "*[System[(EventID=1)]]")
            
            # Fetch the latest 20 events
            events = win32evtlog.EvtNext(query_handle, 20, 100, 0)
            
            if not events:
                continue
                
            parsed_batch = []
            for ev in events:
                xml_content = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed = parse_sysmon_xml(xml_content)
                if parsed:
                    parsed_batch.append(parsed)
            
            # Sort chronologically by timestamp
            parsed_batch.sort(key=lambda x: x.get("timestamp", ""))
            
            # On first startup, set the baseline to the newest event so we don't spam history
            if not last_processed_timestamp:
                if parsed_batch:
                    last_processed_timestamp = parsed_batch[-1].get("timestamp", "")
                continue
                
            for parsed_event in parsed_batch:
                ts = parsed_event.get("timestamp", "")
                
                # Only process genuinely new events
                if ts > last_processed_timestamp:
                    last_processed_timestamp = ts
                    
                    # Send event to pipeline
                    results = detect_suspicious_activity([parsed_event], ml_model=ml_model)
                    
                    if results:
                        res = results[0]
                        risk = res.get("risk_level", "LOW")
                        proc = os.path.basename(res.get("process_name", "Unknown"))
                        reason = res.get("reason", "")
                        
                        if risk == "HIGH":
                            print(f"[ALERT] HIGH RISK: {proc} detected! Reason: {reason}")
                            # Trigger popup alert 
                            ctypes.windll.user32.MessageBoxW(0, f"High Risk Activity Detected!\nProcess: {proc}\nReason: {reason}", "LOLBins Alert", 0x30 | 0x0)
                        elif risk == "MEDIUM":
                            print(f"[WARNING] MEDIUM RISK: {proc} detected. Reason: {reason}")
                        else:
                            # LOW -> ignore or log silently
                            pass

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] An error occurred while monitoring: {e}")

if __name__ == "__main__":
    main()
