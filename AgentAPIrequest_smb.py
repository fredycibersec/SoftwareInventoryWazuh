#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
from base64 import b64encode
from datetime import datetime
import requests  # To install requests, use: pip3 install requests
import urllib3
import jsmb      # To install jsmb, use: pip3 install pysmb

# Configuration
endpoint = '/agents?os.name=Microsoft Windows 11 Pro'   # Modifica el nommbre del SO a listar
protocol = 'https'
host = 'localhost'
port = '55000'
user = 'WAZUH_USER'
password = 'WAZUH_PASS'

# Colors
OKGREEN = '\033[92m'
ENDC = '\033[0m'

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Functions
def get_response(request_method, url, headers, verify=False, body=None):
    """Get API result"""
    if body is None:
        body = {}
    request_result = getattr(requests, request_method.lower())(url, headers=headers, verify=verify, data=body)
    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")
def current_date_format(date):
    day = date.day
    month = date.month
    year = date.year
    hour = date.hour
    minute = date.minute
    messsage = "{}-{}-{}_{}-{}".format(day, month, year, hour, minute)
    return messsage

# Variables
base_url = f"{protocol}://{host}:{port}"
login_url = f"{base_url}/security/user/authenticate"
basic_auth = f"{user}:{password}".encode()
headers = {
           'Authorization': f'Basic {b64encode(basic_auth).decode()}',
           'Content-Type': 'application/json'
           }
headers['Authorization'] = f'Bearer {get_response("POST", login_url, headers)["data"]["token"]}'
fecha = current_date_format(datetime.now())
csv_file = 'SoftwareInventoryWazuh/Inventario_Software_Agentes_Wazuh_'+ fecha +'.csv'  # CSV file path
ruta_smb = 'ruta/al/archivo'
mes = datetime.month
anyo = datetime.year

# Request
response = get_response("GET", url=base_url + endpoint, headers=headers)

# WORK WITH THE RESPONSE AS YOU LIKE
#print(json.dumps(response, indent=4, sort_keys=True))

with open(csv_file, 'a', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['agent_name', 'vendor', 'architecture', 'location', 'name', 'agent_id']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    print("[!] Listado de agentes a inventariar:")
    affected_items = response["data"]["affected_items"]
    for i in affected_items:
        agentlist = i["id"]
        agent = i["name"]
        print("Listando software de agente  ->" + agent + OKGREEN + " OK"+ ENDC)
        endpoint = "/syscollector/" + agentlist + "/packages"
        response = get_response("GET", url=base_url + endpoint, headers=headers)
        r = json.dumps(response, indent=4, sort_keys=True)
        #print(response)
        fields_items = response["data"]["affected_items"]
        # Write CSV file
        for item in fields_items:
            row = {
            'agent_name': agent,
            'vendor': item.get('vendor', ''),
            'architecture': item.get('architecture', ''),
            'location': item.get('location', ''),
            'name': item.get('name', ''),
            'agent_id': item.get('agent_id')
            }
            writer.writerow(row)

# Subida de fichero a ruta de red SMB 
con = jsmb.jsmb('ip','user','pass')
con.mkdir(ruta_smb, mes + anyo)
con.upload(ruta_smb, csv_file, mes + anyo)