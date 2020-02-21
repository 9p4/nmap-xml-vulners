#!/usr/bin/env python3
# Parses nmap XML data and cross-references it to a CVE database. Requires service detection enabled in scan.
# Sambhav Saggi hereby disclaims all copyright interest in the program “nmap XML Vulners” (which checks for vulnerabilities in nmap XML files) written by Sambhav Saggi.

import logging, sys
import xml.etree.ElementTree as ET
import requests
import json

logging.basicConfig(stream=sys.stderr, level=logging.INFO) # https://stackoverflow.com/questions/6579496/using-print-statements-only-to-debug/6579522#6579522

API_ENDPOINT = "https://vulners.com/api/v3/burp/software/"

TEMPLATE = "\n\n## {0} v{1} on {2}:{3} with score of {4} #{5} \n\nMore information here: [{6}]({6})\n\n{7}"

md_out = ""

def getResults(name, version, software):
    params = {
        "software": name,
        "version": version,
        "type": software
    }

    response = requests.get(API_ENDPOINT, params=params)
    jsonResponse = response.json()
    logging.info("Using URL %s", response.url)
    if response.status_code == 200 and jsonResponse['result'] == 'OK':
        logging.info("JSON Response %s", response.json())
        return jsonResponse
    else:
        return None

def getVulners(name, version, host, port):
    results = getResults(name, version, "software")
    if results is not None:
        if (results['result'] == 'OK'):
            for i in range(len(results['data']['search'])):
                issue = results['data']['search'][i]
                addIssue(
                    name, version, host, port, i,
                    issue['_source']['cvss']['score'],
                    issue['_source']['href'],
                    issue['_source']['description']
                )
            
def addIssue(name, version, host, port, num, score, link, body): # TODO: Maybe switch to a different format for arguments? Too difficult to add new features
    output = TEMPLATE.format(name, version, host, port, score, str(num + 1), link, body)
    global md_out
    md_out += output
    saveDoc(".report.temp.md")

def formatDoc():
    global md_out
    md_out = "# Scan"
    saveDoc(".report.temp.md")

def saveDoc(name):
    with open(name, "w") as file:
        file.write(md_out)
        file.close()

def activeHosts(xml):
    activeHosts = []
    for host in xml.findall('host'):
        for status in host:
            if (status.get('state') == 'up'):
                logging.info("Checking host %s: is up",
                    host.findall('address')[0].get('addr')) # Gets IPv4 addresses
                activeHosts.append(host)
    return activeHosts

def activePorts(host):
    ports = []
    for port in host.findall('ports/port'):
        if (port.findall('state')[0].get('state') != 'filtered'):
            ports.append(port)
    return ports

def internet_on(): # Based loosely on https://stackoverflow.com/questions/3764291/checking-network-connection/3764660#3764660
    try:
        requests.get('https://vulners.com')
    except: # Add exception type
        logging.fatal("No connection to https://vulners.com. Quitting!")
        sys.exit(1)

def main():
    # Check if we have connection
    internet_on()

    # Initialize document
    formatDoc()

    for i in range(1, len(sys.argv)):
        logging.info("Parsing data")
        # TODO: Switch to argparse
        xml = ET.parse(sys.argv[i]) # See https://stackoverflow.com/questions/1912434/how-do-i-parse-xml-in-python/1912483#1912483
        hosts = activeHosts(xml) # Filter out all inactive hosts
        for host in hosts:
            addr = host.findall('address')[0].get('addr')
            for port in activePorts(host):
                logging.info("Checking %s:%s", addr, port.get('portid'))
                try:
                    service = port.findall('service')[0]
                    version = port.findall('service')[0].get('version')
                    product = service.get('product')

                    if product is None:
                        product = service.get('name')

                    if version is None:
                        version = "1.0"
                    
                    getVulners(product, version, addr, port.get('portid'))
                except IndexError:
                    logging.warning("No service detected")

        filename = str(sys.argv[i].strip(".xml")) + ".md" # FIXME: Improve this. Very iffy
        saveDoc(filename)

if __name__ == '__main__':
    main()
