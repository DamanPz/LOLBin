import json
from sysmon_parser import parse_sysmon_xml

def main():
    # The sample XML log file
    log_file = "sample_sysmon.xml"
    
    print(f"--- Sysmon XML Log Parser Example ---")
    print(f"Reading and parsing logs from: {log_file}\n")
    
    # Run the parser
    events = parse_sysmon_xml(log_file)
    
    if not events:
        print("No Event ID 1 (Process Creation) logs were found, or an error occurred.")
        return
        
    print(f"Successfully extracted {len(events)} Process Creation events.\n")
    
    # Print the parsed events in a clean format
    for i, event in enumerate(events, 1):
        print(f"--- Event #{i} ---")
        print(f"[*] Timestamp      : {event.get('Timestamp')}")
        print(f"[*] User           : {event.get('User')}")
        print(f"[*] Process Name   : {event.get('ProcessName')}")
        print(f"[*] Command Line   : {event.get('CommandLine')}")
        print(f"[*] Parent Process : {event.get('ParentProcess')}")
        print("-" * 30 + "\n")

    # Optional: Save nicely formatted output to JSON to verify the "list of dictionaries" output
    output_filename = 'parsed_events.json'
    with open(output_filename, 'w') as f:
        json.dump(events, f, indent=4)
        print(f"The raw parsed Python data has been dumped to: {output_filename}")

if __name__ == "__main__":
    main()
