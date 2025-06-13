import xml.etree.ElementTree as ET
import os

def parse_xccdf(xml_file_path):
    """
    Parses a DISA STIG XCCDF XML file to extract detailed information
    about each security rule.

    This function navigates through the XML structure to pull out critical
    components of each STIG rule, such as its ID, severity, title,
    a detailed description, the manual check procedures, and the remediation steps.

    Args:
        xml_file_path (str): The absolute or relative path to the XCCDF XML file.

    Returns:
        list: A list of dictionaries. Each dictionary represents a single STIG rule
              and contains the following keys:
              - 'stig_id' (str): The V-ID for the STIG (e.g., 'V-2207183').
              - 'rule_id' (str): The unique rule identifier (e.g., 'SV-2207183r1_rule').
              - 'severity' (str): The impact level ('high', 'medium', 'low').
              - 'title' (str): The concise title of the STIG rule.
              - 'description' (str): A detailed explanation of the vulnerability and its impact.
              - 'check_content' (str): The manual procedure to verify compliance.
              - 'fix_text' (str): The instructions to remediate non-compliance.
              Returns an empty list if the file is not found or parsing fails.
    """
   
    # check if the provided XML file path exists
    if not os.path.exists(xml_file_path):
        print(f"Error: XML file not found at {xml_file_path}")
        return []
    
    rules_data = [] # list to store all parsed rule dictionaries
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Define namespaces using in XCCDF to properly find elements
        # This is crucial for XML parsing, as XCCDF uses namespaces heavily
        # for example 'xccdf:Rule' instead of just "Rule"
        namespaces = {
            'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'cpe': 'http://cpe.mitre.org/language/2.0'  
        }


        # Note: The provided XML snippet uses xccdf/1.1 for the root,
        # but common practice for modern STIGs is 1.2 or 1.1 with some 1.2 elements.
        # The ElementTree parser is usually flexible enough to handle slight version differences,
        # but if specific elements are missed, verifying the exact namespace might be needed.
        # For 'U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml', the 'xccdf:1.2' namespace
        # for elements like 'Rule', 'description', 'check', 'fix' should work.
        # The root namespace is 'http://checklists.nist.gov/xccdf/1.1'.
        # For findall, using the 1.2 namespace usually captures the elements
        # even if the root is 1.1 if they conform to 1.2 structure.
        # Let's adjust the primary xccdf namespace to 1.1 as per the provided file's root.

        namespaces['xccdf'] = 'http://checklists.nist.gov/xccdf/1.1'

        # # Iterate through all <Rule> elements found anywhere in the XML documents
        # # The './/' ensures a recursive search through all descendants
        # for rule in root.findall('.//xccdf:Rule', namespaces):
        #     # Extract attributes directly from the <Rule> tag
        #     rule_id = rule.get('id')
        #     severity = rule.get('severity') # 'high','medium','low'

        #     # Find and extract the rule title
        #     title_element = rule.find('xccdf:title', namespaces)
        #     title = title_element.text.strip() if title_element is not None else 'N/A'

        #     # Extract the rule description
        #     # Description can be complex, often containing multiple <p> tags
        #     description_element = rule.find('xccdf:description', namespaces)
        #     description = ""

        # Iterate through all <Group> element first, as STIG IDs (V-IDs) are typically
        # associated with the Group element, while Rule IDs (SV-IDs) are on the Rule
        for group in root.findall('.//xccdf:Group', namespaces):
            # The STIG ID (V-ID) is often the 'id' attribute of the group
            stig_id = group.get('id')

            # Now, find all <Rule> elements within this specific <Group>
            for rule in group.findall('xccdf:Rule', namespaces):
                rule_id = rule.get('id')
                severity = rule.get('severity') # 'high', 'medium', 'low'

            # Find and extract the rule title
            title_element = rule.find('xccdf:title', namespaces)
            title = title_element.text.strip() if title_element is not None else 'N/A'

            # Extract the rule description (often in <xccdf:description>)
            # Description can be complex, often containing multiple <p> tags
            description_element = rule.find('xccdf:description', namespaces)
            description = ""

            if description_element is not None:
                # iterate through child <p> elements to get full description text
                description_parts = []
                for p_elem in description_element.findall('xccdf:p', namespaces):
                    if p_elem.text: # Ensure the paragraph element has text
                        description_parts.append(p_elem.text.strip())
                description = "\n".join(description_parts).strip()
                # Fallback: if no <p> tags, get text directly from description element
                if not description and description_element.text:
                    description = description_element.text.strip()
            
            #Extract the check content (manual verification steps)
            check_element = rule.find('xccdf:check', namespaces)
            check_content_element = None
            if check_element is not None:
                # The actual check content is usually nested within <check-content>
                check_content_element = check_element.find('xccdf:check-content', namespaces)
            check_content = check_content_element.text.strip() if check_content_element is not None and check_content_element.text else "N/A"

            # Extract the fix text (remediate steps)
            fix_element = rule.find('xccdf:fix', namespaces)
            fix_text = fix_element.text.strip() if fix_element is not None and fix_element.text else "N/A"

            # Extract the STIG ID (V-number) from an <ident> tag with a specfici system attribute
            # This is often used for cross-referencing with other security standards (like CCI)
            stig_id = "N/A"
            for ident in rule.findall('xccdf:ident', namespaces):
                if ident.get('system') == 'http://cyber.mil/legacy/findingformat/':
                    stig_id = ident.text.strip()
                    break

            # Complete all extracted data for the current rule into a dictionary
            rules_data.append({
                'stig_id' : stig_id,
                'rule_id' : rule_id,
                'severity' : severity,
                'title' : title,
                'description' : description,
                'check_content' : check_content,
                'fix_text' : fix_text
            })
            
    # Catch specific XML parsing errors
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
    # Catch any other unexpected errors during the process
    except Exception as e:
        print(f"An unexpected error occured during parsing: {e}")
    return rules_data

# This block ensures the code inside it only runs when the script is executed directly
# (e.g., `python xccdf_parser.py`), not when imported as a module into another script.
if __name__ == "__main__":
    # Dynamically determine the path to the XML file.
    # This makes the script runnable from anywhere within the project or directly.
    # os.path.abspath(__file__) gets the current script's full path.
    # os.path.dirname(...) gets the directory of the script (src/utils).
    # os.path.join(..., '..', '..') navigate up two directories to the project root (STIG-Automation-ML).
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(base_dir, '..', '..'))
    xml_file_name = 'U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml' # my sepcific STIG file name
    xml_file = os.path.join(project_root, 'data', 'raw', xml_file_name)

    print(f"Attempting to parse: {xml_file}")
    parsed_stig_rules = parse_xccdf(xml_file)

    if parsed_stig_rules:
        print(f"\nSuccessfully parsed {len(parsed_stig_rules)} STIG rules.")
        # Print the first few rules to verify the data structure and content.
        # This helps to confirm the parsing is working as expected
        for i, rule in enumerate(parsed_stig_rules[:5]): # Deplay deatils for the first 5 rules
            print(f"\n--- Rule {i+1} ---")
            print(f"STIG ID: {rule['stig_id']}")
            print(f"Rule ID: {rule['rule_id']}")
            print(f"Severity: {rule['severity']}")
            print(f"Title: {rule['title']}")
            # you can uncomment these lines to see the full content if needed
            # but there are very long for terminal output
            # print(f"Description: {rule['description'][:200]}...") # Truncate for display
            # print(f"Check Content: {rule['check_content'][:200]}...")
            # print(f"Fix Text: {rule['fix_text'][:200]}...")
            print("-" * 20)
    else:
        print("No rules parsed or an error occured during parsing")