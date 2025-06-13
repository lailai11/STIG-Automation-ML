import xml.etree.ElementTree as ET
import os

def parse_xccdf(xml_file_path):
    """
    Parses a DISA STIG XCCDF XML file and extracts relevant rule information.

    This function navigates through the XML structure to pull out critical
    components of each STIG rule, such as its ID, severity, title,
    a detailed description, the manual check procedures, and the remediation steps.

    Args:
        xml_file_path (str): The full path to the XCCDF XML file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a STIG rule
              and contains extracted information. Returns an empty list if parsing fails.
    """
    if not os.path.exists(xml_file_path):
        print(f"Error: XML file not found at {xml_file_path}")
        return []

    rules_data = [] # List to store all parsed rule dictionaries
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot() # Get the root element of the XML tree

        # Define XML namespaces used in XCCDF documents.
        # This is crucial for correctly finding elements that belong to a namespace.
        # The primary XCCDF namespace is the default one, so we map it to an empty string
        # for direct element access within findall, while still keeping the prefix mapping
        # for other specific searches (like 'xccdf:ident' if needed, though not for V-ID).
        namespaces = {
            '': 'http://checklists.nist.gov/xccdf/1.1', # Default namespace
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'cpe': 'http://cpe.mitre.org/language/2.0'
        }
        # For ElementTree, when the root element declares a default namespace (xmlns="..."),
        # you often need to include that namespace when searching for its direct children,
        # even if they don't have an explicit prefix.
        # However, for XPath-like expressions ElementTree expects a prefix,
        # so we'll explicitly use the full qualified tag name or use a prefix.

        # Correct approach for ElementTree with default namespaces:
        # Find all <Group> elements using the full qualified name in curly braces
        # for the default namespace, or by iterating over the prefixed namespace.
        # The provided XML uses the 1.1 namespace for the root element directly.
        # Let's ensure the xccdf prefix still maps to 1.1 explicitly for clarity
        # even if it's the default.
        namespaces['xccdf'] = 'http://checklists.nist.gov/xccdf/1.1'


        # Iterate through all <Group> elements.
        # We now ensure we're looking for the 'Group' tag within the 'xccdf' namespace.
        for group in root.findall('.//xccdf:Group', namespaces):
            # The STIG ID (V-ID) is the 'id' attribute of the Group
            stig_id = group.get('id')

            # Now, find all <Rule> elements within this specific <Group>
            for rule in group.findall('xccdf:Rule', namespaces):
                rule_id = rule.get('id')
                severity = rule.get('severity') # e.g., 'high', 'medium', 'low'

                # Extract title
                # We need to explicitly use the xccdf: prefix for title, description, etc.
                title_element = rule.find('xccdf:title', namespaces)
                title = title_element.text.strip() if title_element is not None else "N/A"

                # Extract description (often in <xccdf:description>)
                description_element = rule.find('xccdf:description', namespaces)
                description = ""
                if description_element is not None:
                    # Description can contain multiple sub-elements,
                    # like <p> tags, so we join their text
                    description_parts = []
                    # Search for <p> tags within the xccdf namespace
                    for p_elem in description_element.findall('xccdf:p', namespaces):
                        if p_elem.text: # Ensure the paragraph element has text
                            description_parts.append(p_elem.text.strip())
                    description = "\n".join(description_parts).strip()
                    # Fallback: if no <p> tags, get text directly from description element
                    if not description and description_element.text:
                        description = description_element.text.strip()


                # Extract check content
                check_element = rule.find('xccdf:check', namespaces)
                check_content_element = None
                if check_element is not None:
                    # The actual check content is usually nested within <check-content>
                    check_content_element = check_element.find('xccdf:check-content', namespaces)
                check_content = check_content_element.text.strip() if check_content_element is not None and check_content_element.text else "N/A"

                # Extract fix text
                fix_element = rule.find('xccdf:fix', namespaces)
                fix_text = fix_element.text.strip() if fix_element is not None and fix_element.text else "N/A"

                rules_data.append({
                    'stig_id': stig_id,
                    'rule_id': rule_id,
                    'severity': severity,
                    'title': title,
                    'description': description,
                    'check_content': check_content,
                    'fix_text': fix_text
                })

    # Catch specific XML parsing errors
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
    # Catch any other unexpected errors during the process
    except Exception as e:
        print(f"An unexpected error occurred during parsing: {e}")

    return rules_data

# This block ensures the code inside it only runs when the script is executed directly
# (e.g., `python xccdf_parser.py`), not when imported as a module into another script.
if __name__ == "__main__":
    # Dynamically determine the path to the XML file.
    # This makes the script runnable from anywhere within the project or directly.
    # os.path.abspath(__file__) gets the current script's full path.
    # os.path.dirname(...) gets the directory of the script (src/utils).
    # os.path.join(..., '..', '..') navigates up two directories to the project root (STIG-Automation-ML).
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(base_dir, '..', '..'))
    xml_file_name = 'U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml' # Your specific STIG file name
    xml_file = os.path.join(project_root, 'data', 'raw', xml_file_name)

    print(f"Attempting to parse: {xml_file}")
    parsed_stig_rules = parse_xccdf(xml_file)

    if parsed_stig_rules:
        print(f"\nSuccessfully parsed {len(parsed_stig_rules)} STIG rules.")
        # Print the first few rules to verify the data structure and content.
        # This helps confirm the parsing is working as expected.
        for i, rule in enumerate(parsed_stig_rules[:5]): # Display details for the first 5 rules
            print(f"\n--- Rule {i+1} ---")
            print(f"STIG ID: {rule['stig_id']}")
            print(f"Rule ID: {rule['rule_id']}")
            print(f"Severity: {rule['severity']}")
            print(f"Title: {rule['title']}")
            # You can uncomment these lines to see the full content if needed,
            # but they can be very long for terminal output.
            # print(f"Description: {rule['description'][:200]}...") # Truncate for display
            # print(f"Check Content: {rule['check_content'][:200]}...")
            # print(f"Fix Text: {rule['fix_text'][:200]}...")
            print("-" * 20)
    else:
        print("No rules parsed or an error occurred during parsing.")