import nmap3
import json
def nmap_scan(targets):
    nmap = nmap3.Nmap()
    version = nmap.nmap_version()
    scanner_result = nmap.nmap_version_detection(targets, args='-A')
    iplist = list(scanner_result)
    hosts = []
    for ip in iplist[:-3]:
        host_data = {
                    'IP': ip
                }
        if "macaddress" in scanner_result[ip]:
            if scanner_result[ip]["macaddress"] is not None:
                if "addr" in scanner_result[ip]["macaddress"]:
                    host_data['mac_address'] = scanner_result[ip]["macaddress"]["addr"]
        if "osmatch" in scanner_result[ip]:
            #print(scanner_result[ip]['osmatch'][0]['name'])
            host_data['operative_system_match'] = {}
            host_data['operative_system_match']['name'] = scanner_result[ip]['osmatch'][0]['name']
            host_data['operative_system_match']['accuracy'] = scanner_result[ip]['osmatch'][0]['accuracy']
            if "osclass" in scanner_result[ip]['osmatch'][0]:
                host_data['operative_system_match']['osclass'] = {}
                if "type" in scanner_result[ip]['osmatch'][0]["osclass"]:
                    host_data['operative_system_match']['osclass']['type'] = scanner_result[ip]['osmatch'][0]["osclass"]['type']
                if "vendor" in scanner_result[ip]['osmatch'][0]["osclass"]:
                    host_data['operative_system_match']['osclass']['vendor'] = scanner_result[ip]['osmatch'][0]["osclass"]['vendor']
                if "osfamily" in scanner_result[ip]['osmatch'][0]["osclass"]:
                    host_data['operative_system_match']['osclass']['osfamily'] = scanner_result[ip]['osmatch'][0]["osclass"]['osfamily']
                if "osgen" in scanner_result[ip]['osmatch'][0]["osclass"]:
                    host_data['operative_system_match']['osclass']['osgen'] = scanner_result[ip]['osmatch'][0]["osclass"]['osgen']
        if "ports" in scanner_result[ip]:
            host_data['ports'] = scanner_result[ip]['ports']
        hosts.append(host_data)
    with open('scan_result.json', 'w') as f:
        json.dump(hosts, f,indent=4)       