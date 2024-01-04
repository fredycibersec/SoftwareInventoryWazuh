#!/usr/bin/env python3
import csv
import json
import logging
import shutil
from base64 import b64encode
from datetime import datetime
import requests  # To install requests, use: pip3 install requests
import urllib3
from smb.SMBConnection import SMBConnection # To install smb, use: pip3 install pysmb

# Configuration
logger = logging.getLogger(_name_)
endpoint = '/agents?os.name=Microsoft Windows 11 Pro'
protocol = 'https'
host = 'localhost'
port = '55000'
user = 'WAZUH_USER'
password = 'WAZUH_PASS'
smb_user = 'SMB_USER'
smb_pass = 'SMB_PASSWORD'
smb_localname = 'WAZUH_HOSTNAME'
smb_remotename = 'FILE_SERVER'

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
fecha_now = datetime.now()
anyo = str(fecha_now.year)
csv_file = 'Inventario_Software_Agentes_Wazuh_'+ fecha +'.csv'  # CSV file path
smb_ruta = '\\Ruta\\Donde\\Almacenar\\Inventario\\'+anyo
smb_store = 'Recurso_Raiz_SMB'
domain = "dominio.local"

# Request
response = get_response("GET", url=base_url + endpoint, headers=headers)

# WORK WITH THE RESPONSE AS YOU LIKE
#print(json.dumps(response, indent=4, sort_keys=True))
with open(csv_file, 'a', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['agent_name', 'vendor', 'architecture', 'location', 'name', 'agent_id']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    print("")
    print("[!] Listado de agentes a inventariar:")
    print("")
    affected_items = response["data"]["affected_items"]
    for i in affected_items:
        agentlist = i["id"]
        agent = i["name"]
        print("[+] Listando software de agente " + agent + " - Agent ID:" + agentlist + " ->" + OKGREEN + " OK"+ ENDC)
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
    print("")
    print("[!] Listado de agentes " + OKGREEN + "-> FINALIZADO"+ ENDC)
    print("[!] Fichero de salida ubicado en: " + csv_file)

# Subida de fichero a ruta de red SMB  (smb://FILESERVER/Usuarios/Tecnicos/Docu DHM/Wazuh/Informes Wazuh/Inventario Activos)
def put_file_smb(_filename):
    try:
        # Crear conexion SMB
        conn = SMBConnection(smb_user,
                             smb_pass,
                             smb_localname,
                             smb_remotename,
                             domain,
                             use_ntlm_v2=True,
                             sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
                             is_direct_tcp=True)
        connected = conn.connect(smb_remotename, 445)

        # Subir fichero a servidor SMB
        try:
            with open(_filename, 'rb') as fstore:
                conn.storeFile(smb_store, smb_ruta+'\\'+csv_file, fstore, timeout=30)
                print("[!] Fichero almacenado correctamente en la carpeta de red:")
                print('>> smb:\\Ruta\\Donde\\Almacenar\\Inventario\\'+anyo)
        except Exception as e:
            #print('Error almacenando el fichero de forma remota. Razon: ', e)
            logger.exception("Error almacenando el fichero de forma remota. " + str(e))
    except Exception as e:
        #print('Error estableciendo una conexion remota. Razon: ', e)
        logger.exception("Error estableciendo una conexion remota. " + str(e))
    finally:
        conn.close()
        
put_file_smb(csv_file)

# Mover el fichero a directorio SoftwareInventoryWazuh
shutil.move(csv_file, "SoftwareInventoryWazuh/"+csv_file)
