import pandas as pd
import csv, re
from packaging.version import Version
import json


def BDU_check(cur_soft_title, cur_ver):
    vuln_count = 0
    vulns = []
    with open('vullist.csv', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            soft_title = str(row['Название ПО'])
            versions = row['Версия ПО']
            if cur_soft_title.lower() in soft_title.lower():
                filtered_versions = []
                for current_service_version in versions.split(','):
                    if '(' in current_service_version:
                        version_match = re.search('\((.*?)\)', current_service_version)
                        if version_match:
                            version_in_brackets = version_match.group(1)
                        else:
                            version_in_brackets = None
                        if version_in_brackets == cur_soft_title:
                            filtered_versions.append(current_service_version)
                    else:
                        filtered_versions.append(current_service_version)
                for current_service_version in filtered_versions:
                    current_service_version = re.sub(r'[^\d\.]', '', current_service_version)
                    if current_service_version and not current_service_version.startswith('.') and not current_service_version.endswith('.') and '..' not in current_service_version:
                        if '-' in current_service_version:
                            begin_version, end_version = current_service_version.split('-')
                            if Version(begin_version) <= Version(cur_ver) <= Version(end_version):
                                vuln_count += 1
                                vuln = {}
                                vuln['ID'] = str(row['Идентификатор'])
                                vuln['CVE'] = str(row['Идентификаторы других систем описаний уязвимости'])
                                vuln['ProductName'] = str(row['Название ПО'])
                                vuln['Version'] = str(row['Версия ПО'])
                                vuln['Description'] = str(row['Описание уязвимости'])
                                vuln['cvss'] = str(row['CVSS 2.0'])
                                vuln['dangerlevel'] = str(row['Уровень опасности уязвимости'])
                                vulns.append(vuln)
                        elif current_service_version.startswith('от'):
                            begin_version = re.search('[^\d.]?[\d.]+[^\d.]?', current_service_version)[0]
                            while re.search('[^\d]', begin_version[0]) is None:
                                begin_version = begin_version[1:]
                            while re.search("[\d]", begin_version[-1]) is None:
                                begin_version = begin_version[:-1]
                            if Version(begin_version) <= Version(cur_ver):
                                vuln_count += 1
                                vuln = {}
                                vuln['ID'] = str(row['Идентификатор'])
                                vuln['CVE'] = str(row['Идентификаторы других систем описаний уязвимости'])
                                vuln['ProductName'] = str(row['Название ПО'])
                                vuln['Version'] = str(row['Версия ПО'])
                                vuln['Description'] = str(row['Описание уязвимости'])
                                vuln['cvss'] = str(row['CVSS 2.0'])
                                vuln['dangerlevel'] = str(row['Уровень опасности уязвимости'])
                                vulns.append(vuln)
                        elif current_service_version.startswith('до'):
                            end_version = re.search('[^\d.]?[\d.]+[^\d.]?', current_service_version)[0]
                            while re.search('[^\d]', end_version[0]):
                                end_version = end_version[1:]
                            while re.search('[^\d]', end_version[-1]):
                                end_version = end_version[:-1]
                            if Version(cur_ver) <= Version(end_version):
                                vuln_count += 1
                                vuln = {}
                                vuln['ID'] = str(row['Идентификатор'])
                                vuln['CVE'] = str(row['Идентификаторы других систем описаний уязвимости'])
                                vuln['ProductName'] = str(row['Название ПО'])
                                vuln['Version'] = str(row['Версия ПО'])
                                vuln['Description'] = str(row['Описание уязвимости'])
                                vuln['cvss'] = str(row['CVSS 2.0'])
                                vuln['dangerlevel'] = str(row['Уровень опасности уязвимости'])
                                vulns.append(vuln)
                        elif '..' in current_service_version:
                            begin_version, end_version = current_service_version.split('..')
                            if Version(begin_version) <= Version(cur_ver) <= Version(end_version):
                                vuln_count += 1
                                vuln = {}
                                vuln['ID'] = str(row['Идентификатор'])
                                vuln['CVE'] = str(row['Идентификаторы других систем описаний уязвимости'])
                                vuln['ProductName'] = str(row['Название ПО'])
                                vuln['Version'] = str(row['Версия ПО'])
                                vuln['Description'] = str(row['Описание уязвимости'])
                                vuln['cvss'] = str(row['CVSS 2.0'])
                                vuln['dangerlevel'] = str(row['Уровень опасности уязвимости'])
                                vulns.append(vuln)
                        else:
                            if Version(current_service_version) == Version(cur_ver):
                                vuln_count += 1
                                vuln = {}
                                vuln['ID'] = str(row['Идентификатор'])
                                vuln['CVE'] = str(row['Идентификаторы других систем описаний уязвимости'])
                                vuln['ProductName'] = str(row['Название ПО'])
                                vuln['Version'] = str(row['Версия ПО'])
                                vuln['Description'] = str(row['Описание уязвимости'])
                                vuln['cvss'] = str(row['CVSS 2.0'])
                                vuln['dangerlevel'] = str(row['Уровень опасности уязвимости'])
                                vulns.append(vuln)
    #total_vuln = vuln_count
    return vulns

def extract_data(jsonfile):
    # Открыть файл JSON
    with open(jsonfile, 'r') as file:
        data = json.load(file)  

    # Создать пустой массив
    result = []

    # Итерироваться по каждому объекту в файле JSON
    for item in data:
        # Получить значения полей ip, osclass.osgen и osclass.osfamily
        ip = item['IP']
        cur_ver = item['operative_system_match']['osclass']['osgen']
        cur_ver = re.sub(r'[^\d\.]', '', cur_ver)
        if cur_ver.endswith('.'):
            cur_ver = cur_ver[:-1]
        cur_soft = ' '.join([item['operative_system_match']['osclass']['vendor'], item['operative_system_match']['osclass']['osfamily']])

        # Добавить каждый объект в массив
        result.append({'ip': ip, 'cur_soft': cur_soft, 'cur_ver': cur_ver})
    return result