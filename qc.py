import argparse, getpass, logging, requests, sys, warnings
from tabulate import tabulate
warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to either get current server power state and possible power state values or execute server power state change")
parser.add_argument('-ip', help='Pass in iDRAC IP address', required=False)
parser.add_argument('-u', help='Pass in iDRAC username', required=False)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in \"true\". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--get', help='Get the Information of the Server', action="store_true", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- qc.py -ip 10.2.161.103 -u root -p calvin --get, this will get the information of the Server.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code 401 detected, check iDRAC username / password credentials")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to validate iDRAC creds, status code %s returned." % response.status_code)
        logging.warning(data)
        sys.exit(0)
    
def get_information_of_the_server():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data1 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data2 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Power' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Power' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data3 = response.json()

    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip,response.status_code))
        logging.warning(data1)
        sys.exit(0)       
    table1 = [
        ("Vendor", data['Vendor']),
        ("Model", data1['Model']),
        ("Serial Number", data1['SerialNumber']),
        ("UUID", data1['UUID']),
        ("Power State", data1['PowerState']),
        ("Bios Version", data1['BiosVersion']),
        ("Firmware Version", data2['FirmwareVersion']),
        ("Total Number of the Processors", data1['ProcessorSummary']['Count'])
    ]

    table2 = [("System Health", data1['Status']['HealthRollup']),
        ("Processor Health", data1['ProcessorSummary']['Status']['HealthRollup']),
        ("Memory Health", data1['MemorySummary']['Status']['HealthRollup']),
        ("Power Supplies Health", data3['PowerSupplies'][0]['Status']['Health'])]
    
    print("\n=================== INFORMATION OF THE SERVER ===================")
    print(tabulate(table1, headers=["Keys", "Output"], tablefmt="pretty"))
    print()

    print("\n=================== HEALTH INFORMATION OF THE SERVER ===================")
    print(tabulate(table2, headers=["Keys", "Output"], tablefmt="pretty"))
    print()

def get_boot_order():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/SecureBoot' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/SecureBoot' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip,response.status_code))
        logging.warning(data)
        sys.exit(0)  
    print("\n=================== INFORMATION OF THE BOOT ORDER ===================")
    table = [("Description" , data['Description']), ("State of Current Boot" , data['SecureBootCurrentBoot']), ("Boot Mode", data['SecureBootMode'])]
    print(tabulate(table, headers=["Keys", "Output"], tablefmt="pretty"))
    print()

def get_memory_information():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()

    memory_information = []
    for socket in ["A", "B"]:
        memory_information = []
        for socket in ["A", "B"]:
            for i in range(1, 13):
                dimm_id = f"DIMM.Socket.{socket}{i}"
                url = f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/Memory/{dimm_id}"
                headers = {'X-Auth-Token': args["x"]} if args["x"] else None
                response = requests.get(url, verify=verify_cert, headers=headers, auth=(idrac_username, idrac_password) if not headers else None)
                data1 = response.json()

                if response.status_code != 200:
                    logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip,response.status_code))
                    logging.warning(data)
                    sys.exit(0)
                memory_information.append((dimm_id, data1['Status']['Health']))

    print("\n=================== INFORMATION OF THE MEMORY ===================")
    table = [("Memory Size" , data['MemorySummary']['TotalSystemMemoryGiB'])]
    print(tabulate(table, headers=["Keys", "Output"], tablefmt="pretty"))
    print(tabulate(memory_information, headers=["Id", "Health"], tablefmt="pretty"))
    print()

def get_the_mac_address():
    url_template = 'https://%s/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Integrated.1-%d-1'
    headers = {'X-Auth-Token': args['x']} if args.get('x') else None
    auth = (idrac_username, idrac_password) if not headers else None
    mac_addresses = []
    for i in range(1, 3):
        url = url_template % (idrac_ip, i)
        response = requests.get(url, headers=headers, auth=auth, verify=verify_cert)
        data = response.json()
        mac_addresses.append((data['Description'], data['MACAddress'], data['Status']['Health']))
    print("\n=================== INFORMATION OF MAC ADDRESSES ===================")
    print(tabulate(mac_addresses, headers=["Description", "MAC Address", "Health"], tablefmt="pretty"))

def get_pcie_device_function_inventory():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/59-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/59-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data1 = response.json()
    print()
    print("\n=================== INFORMATION OF PCIE DEVICES ===================")
    
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/136-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/136-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data2 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-23' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-23' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data3 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-28' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-28' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data4 = response.json()
   
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/25-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/25-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data5 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/24-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/24-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data6 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data7 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-17' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-17' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data8 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-31' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/0-31' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data9 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/3-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/3-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data10 = response.json()

    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/137-0' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/PCIeDevices/137-0' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data11 = response.json()

    table = [(data1['@odata.type'], data1['Description']),(data2['@odata.type'], data2['Description']),(data3['@odata.type'], data3['Description']),(data4['@odata.type'], data4['Description']),
             (data5['@odata.type'], data5['Description']),(data6['@odata.type'], data6['Description']),(data7['@odata.type'], data7['Description']),(data8['@odata.type'], data8['Description']),
             (data9['@odata.type'], data9['Description']),(data10['@odata.type'], data10['Description']), (data11['@odata.type'], data11['Description'])]
    print(tabulate(table, headers=["Id", "Description"], tablefmt="pretty"))

def get_physical_drives():
    drives_info = []
    for i in range(8):
        url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Storage/NonRAID.Integrated.1-1/Drives/Disk.Bay.%d:Enclosure.Internal.0-1:NonRAID.Integrated.1-1' % (idrac_ip, i)
        if args["x"]:
            response = requests.get(url, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get(url, verify=verify_cert, auth=(idrac_username, idrac_password))
        data = response.json()
        drives_info.append((data['Id'], data['Status']['HealthRollup']))
    print("\n=================== INFORMATION OF PHYSICAL DRIVE  ===================" )
    print(tabulate(drives_info, headers=["Id", "HealthRollup"], tablefmt="pretty"))
    print()

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()
    if args["ip"] and args["ssl"] or args["u"] or args["p"] or args["x"]:
        idrac_ip = args["ip"]
        idrac_username = args["u"]
        if args["p"]:
            idrac_password = args["p"]
        if not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass("\n- Argument -p not detected, pass in iDRAC user %s password: " % args["u"])
        if args["ssl"]:
            if args["ssl"].lower() == "true":
                verify_cert = True
            elif args["ssl"].lower() == "false":
                verify_cert = False
            else:
                verify_cert = False
        else:
                verify_cert = False
        check_supported_idrac_version()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    
    if args["get"]:
        get_information_of_the_server()
        get_boot_order()
        get_memory_information()
        get_the_mac_address()
        get_pcie_device_function_inventory()
        get_physical_drives()

    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")