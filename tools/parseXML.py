#!/usr/bin/python3
import xml.etree.ElementTree as ET
import sys

def parse_file(xmlFile, parse_rule_descriptions=False, parse_findings=False):
    tree = ET.parse(xmlFile)
    root = tree.getroot()
    # This is a short cut to avoid having to type it over and over again.
    ns = { 'xccdf': 'http://checklists.nist.gov/xccdf/1.2' }
    results = root.find( 'xccdf:TestResult', ns)
    # Gather some facts about the system. Not sure if this will be meaningful
    # from a CFEngine perspective, but included just the same.
    facts = results.find('xccdf:target-facts', ns)
    hostname = OS = rel = man = model = ip = osrel = ""
    for fact in facts.findall('xccdf:target-facts', ns):
        name = fact.attrib['name']
        if name.endswith(':host_name'):
            hostname = fact.text.lower() # The hostname shows up as ALL UPPERCASE
        if name.endswith(':os_name'):
            OS = fact.text
        if name.endswith(':os_version'):
            rel = fact.text
        if name.endswith(':manufacturer'):
            man = fact.text
        if name.endswith(':model'):
            model = fact.text
        if name.endswith(':ipv4'):
            ip = fact.text
            # Do something with the data (store it, print it, etc)
            # Populate rule data.
    for group in root.findall('xccdf:Group', ns):
        # Extract the rule short name (I.E. V-240123) from the group id.
        short_name = group.attrib['id'].replace('xccdf_mil.disa.stig_group_', '')
        rule = group.findall('xccdf:Rule', ns)[0]
        rule_id = rule.attrib['id']
        level = rule.attrib['severity']

        # Convert the high/medium/low listed in report to CAT I / II / III
        if level == 'high':
            level = 'CAT I'
        if level == 'medium':
            level = 'CAT II'
        if level == 'low':
            level = 'CAT III'
        title = rule.find('xccdf:title', ns).text
        if parse_rule_descriptions:
            print (short_name, level, title)


        # Do something with the data (store it, print it, etc)
        # Rule results
    rule_results = results.findall('xccdf:rule-result', ns)
    for result in rule_results:
        rid = result.attrib['idref']
        short_name = result.attrib['idref'].replace('xccdf_mil.disa.stig_rule_S', '').split('r')[0]
        #short_name = short_name.split('r')[0]
        status = result.find('xccdf:result', ns).text
        # Do something with the data (store it, print it, etc)
        #print ("---------------")
        #print (ET.tostring(result, encoding='unicode'))
        if parse_findingss:
            print (short_name, status)

if __name__== '__main__':
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], "/path/to/XCCDF-Results.xml [--parse-descriptions] [--parse-findings]")
        sys.exit(1)

    xccdf_results_filename = sys.argv[1]

    # Check for mutually exclusive options
    if "--parse-descriptions" in sys.argv and "--parse-findings" in sys.argv:
        print("Options --parse-descriptions and --parse-findings are mutually exclusive. Choose one.")
        sys.exit(1)

    parse_rule_descriptions = "--parse-descriptions" in sys.argv
    parse_findings = "--parse-findings" in sys.argv

    parse_file(xccdf_results_filename, parse_rule_descriptions, parse_findings)
