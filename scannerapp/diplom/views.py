from django.shortcuts import render, redirect
from .scanner import nmap_scan
import json
from .vulners import extract_data, BDU_check
from .ml_module import *
from .secure_tools import *
# Create your views here.
# Create your views here.
def home(request):
    if request.method == 'POST':
        targets = request.POST.get('text')
        
        nmap_scan(str(targets))

    return render(request, 'diplom/base.html')

def scan_results(request):
    with open('scan_result.json', 'r') as f:
        data = json.load(f)
    return render(request, 'diplom/scan_results.html', {'data': data})


def vuln_results(request):
    hosts = extract_data('scan_result.json')

    for host in hosts:
        vulns = BDU_check(host['cur_soft'], host['cur_ver'])
        new = [dict(s) for s in set(frozenset(d.items()) for d in vulns)]
        host['vulns'] = new

    with open('hosts_vulns_results.json', 'w', encoding='utf-8') as f:
        json.dump(hosts, f,indent=4) 

    with open('hosts_vulns_results.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    return render(request, 'diplom/vuln_results.html', {'data': data})



def threats_results(request):
    bdu_list = extract_vulns()
    new_list = find_threats_depends(bdu_list)

    with open('new_list.json', 'w', encoding='utf-8') as f:
        json.dump(new_list, f, indent=4)

    with open('new_list.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    for item in data:
        item['threat_desc'] = item['threat_desc'].replace('_x000D_', '')
    return render(request, 'diplom/threats_results.html', {'data': data})

def secure_tools_results(request):
    
    return render(request, 'diplom/secure_tools_results.html')

def secure_tools(request):
    if request.method == 'POST':
        dict_data = {
            'antivirus':{
                'antivirus_type': request.POST.get('antivirus-type'),
                'antivirus_class': request.POST.get('antivirus-class'),
                'antivirus_checkboxes': request.POST.getlist('antivirus-checkboxes')
            },
            'firewall':{
                'firewall_type': request.POST.get('firewall-type'),
                'firewall_class': request.POST.get('firewall-class'),
                'firewall_checkboxes': request.POST.getlist('firewall-checkboxes')
            }
        }
        #antivirus
        szi_type_antivirus = dict_data['antivirus']['antivirus_type']
        szi_class_antivirus = dict_data['antivirus']['antivirus_class']
        data = search_and_normilize(szi_type_antivirus,szi_class_antivirus)
       
        df_data = pd.DataFrame(data)
        df_data.columns = ['Antivirus', 'Detection Rate', 'Scan Speed', 'Resource Usage', 'Cost']

        best_antivirus = select_antivirus(df_data, criteria=['Detection Rate', 'Scan Speed', 'Resource Usage', 'Cost']) 
        

        #firewall
        szi_type_firewall = dict_data['firewall']['firewall_type']
        szi_class_firewall = dict_data['firewall']['firewall_class']
        data = search_and_normilize_firewall(szi_type_firewall,szi_class_firewall)
       
        df_data = pd.DataFrame(data)
        df_data.columns = ['Antivirus', 'Detection Rate', 'Scan Speed', 'Resource Usage', 'Cost']

        best_firewall = select_firewall(df_data, criteria=['Detection Rate', 'Scan Speed', 'Resource Usage', 'Cost']) 
        
        search(best_antivirus, best_firewall)
        
    return render(request, 'diplom/secure_tools.html')
    


def secure_tools_results(request):
    with open('szi_results.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    return render(request, 'diplom/secure_tools_results.html', {'data': data})



# import nmap3
# import json

# def nmap_scan(targets):
#     nmap = nmap3.Nmap()

#     scanner_result = nmap.nmap_scan(hosts=targets, arguments="-sV -O")

#     iplist = list(scanner_result)

#     hosts = []

#     for ip in iplist:
#         host_data = {
#             'IP': ip,
#             'OS': scanner_result[ip]['osmatch'][0]['name'],
#             'OS Version': scanner_result[ip]['osmatch'][0]['osclass']['osgen'],
#             'OS CPEs': scanner_result[ip]['osmatch'][0]['osclass']['cpe'],
#             'Services': []
#         }

#         for port in scanner_result[ip]['ports']:
#             service_data = {
#                 'Port': port,
#                 'Protocol': scanner_result[ip]['ports'][port]['protocol'],
#                 'State': scanner_result[ip]['ports'][port]['state'],
#                 'Service': scanner_result[ip]['ports'][port]['service']['name'],
#                 'Product': scanner_result[ip]['ports'][port]['service']['product'],
#                 'Version': scanner_result[ip]['ports'][port]['service']['version'],
#                 'Extra Info': scanner_result[ip]['ports'][port]['service']['extrainfo'],
#                 'OS CPEs': scanner_result[ip]['ports'][port]['service']['cpe']
#             }

#             host_data['Services'].append(service_data)

#         hosts.append(host_data)

#     with open('scan_result.json', 'w') as f:
#         json.dump(hosts, f, indent=4)