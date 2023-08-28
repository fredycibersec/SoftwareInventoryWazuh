# Software Inventory for Wazuh

<img src="https://www.servicepilot.com/images/integration/wazuh.png" width="500">

Un script hecho en Python para abusar de la API de Wazuh y listar todo el software instalado en los EndPoits con el Sistema Operativo seleccionado (Wiundows 11 Pro en este caso).

- Este script, una vez lista el contenido del software instalado en cada Endpoint elegido, inserta en un CSV (catalogado por nombre e ID de cada Endpoint), todo el software y lo transfiere a una ruta de red a través del protocolo SMB, usando Python3 durante todo el proceso.
