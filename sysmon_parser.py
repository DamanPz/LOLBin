import xml.etree.ElementTree as ET

def remove_namespace(tag: str) -> str:
    """
    Helper function to remove the XML namespace from a tag.
    Windows Event Viewer often includes a namespace like:
    '{http://schemas.microsoft.com/win/2004/08/events/event}Event'
    This simplifies it to just 'Event'.
    """
    return tag.split('}', 1)[1] if '}' in tag else tag

class SysmonParser:
    """
    A beginner-friendly parser for Windows Sysmon XML logs.
    Focuses on extracting Process Creation events (Event ID 1).
    """
    
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> list:
        """
        Parses the Sysmon XML log and returns a list of dictionaries,
        each representing a single Process Creation event (Event ID 1).
        """
        parsed_events = []

        try:
            tree = ET.parse(self.filepath)
            root = tree.getroot()
            
            # Using iter() walks through the tree to find all 'Event' elements,
            # no matter how the XML is structured at the top level.
            for event in root.iter():
                if remove_namespace(event.tag) == 'Event':
                    event_data = self._process_event(event)
                    if event_data:
                        parsed_events.append(event_data)
                        
        except FileNotFoundError:
            print(f"Error: Could not find file '{self.filepath}'.")
        except ET.ParseError as e:
            print(f"Error: Failed to parse XML in '{self.filepath}'. Details: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while parsing: {e}")
            
        return parsed_events

    def _process_event(self, event_elem: ET.Element):
        """
        Extracts relevant fields from a single Event element.
        Returns a dictionary of extracted data if it's Event ID 1, otherwise None.
        """
        system_node = None
        eventdata_node = None
        
        # Step 1: Locate the <System> and <EventData> sections
        for child in event_elem:
            tag_name = remove_namespace(child.tag)
            if tag_name == 'System':
                system_node = child
            elif tag_name == 'EventData':
                eventdata_node = child
        
        # If either critical section is missing, we can't parse it
        if system_node is None or eventdata_node is None:
            return None
            
        # Step 2: Check standard fields inside <System>
        event_id = None
        timestamp = None
        
        if system_node is not None:
            for sys_data in system_node:
                tag_name = remove_namespace(sys_data.tag)
                if tag_name == 'EventID':
                    event_id = sys_data.text
                elif tag_name == 'TimeCreated':
                    timestamp = sys_data.attrib.get('SystemTime')
                
        # We only care about Event ID 1 (Process Creation)
        if event_id != '1':
            return None
            
        # Step 3: Initialize our result dictionary
        result = {
            'EventID': 1,
            'Timestamp': timestamp,
            'ProcessName': None,
            'CommandLine': None,
            'ParentProcess': None,
            'User': None
        }
        
        # Step 4: Extract the specific telemetry from <EventData>
        if eventdata_node is not None:
            for data in eventdata_node:
                if remove_namespace(data.tag) == 'Data':
                    name = data.attrib.get('Name')
                    value = data.text
                    
                    # Match the names Sysmon uses for process creation fields
                    if name == 'Image':
                        result['ProcessName'] = value
                    elif name == 'CommandLine':
                        result['CommandLine'] = value
                    elif name == 'ParentImage':
                        result['ParentProcess'] = value
                    elif name == 'User':
                        result['User'] = value
                    
        return result

def parse_sysmon_xml(filepath: str) -> list:
    """
    Convenience function to parse Sysmon logs directly.
    Example: 
        events = parse_sysmon_xml("logs.xml")
    """
    parser = SysmonParser(filepath)
    return parser.parse()

if __name__ == "__main__":
    # Provides a basic test fallback if someone runs this module directly
    print("Sysmon Parser Module loaded successfully.")
