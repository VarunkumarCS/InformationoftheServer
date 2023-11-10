import argparse, getpass, logging, requests, sys, warnings
from tabulate import tabulate
from pprint import pprint as pp
warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
parser.add_argument('-ip', help='Pass in iDRAC IP address', required=False)
parser.add_argument('-u', help='Pass in iDRAC username', required=False)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in \"true\". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--system', help='Get the system information', action= "store_true", required=False)
parser.add_argument('--firmware', help='Get the firmware information', action= "store_true", required=False)
parser.add_argument('--boot', help='Get the boot order information', action= "store_true", required=False)
parser.add_argument('--memory', help='Get the memory information', action= "store_true", required=False)
parser.add_argument('--mac', help='Get the information about the mac addresses', action= "store_true", required=False)
parser.add_argument('--fans', help='Get the information of the fans', action= "store_true", required=False)
parser.add_argument('--drives', help='Get the information of the physical drives', action= "store_true", required=False)
parser.add_argument('--all', help='Get the Information of the Server', action="store_true", required=False)

args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- python3 qc.py -ip 10.2.161.103 -u root -p calvin --all, this will get the information of the Server.""")
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
         response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Power' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Power' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data3 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Bios' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Bios' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data5 = response.json()

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
        ("Boot Order", data5['Attributes']['SetBootOrderEn']),
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
    print(tabulate(table2, headers=["Keys", "Output"], tablefmt="pretty", missingval= "N/A"))
    print()

def get_firmware_information_of_the_server():
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
         response = requests.get('https://%s/redfish/v1/Chassis/Enclosure.Internal.0-1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Chassis/Enclosure.Internal.0-1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data3 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110220-26.35.10.12__NIC.Integrated.1-1-1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110220-26.35.10.12__NIC.Integrated.1-1-1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data6 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110220-26.35.10.12__NIC.Integrated.1-2-1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110220-26.35.10.12__NIC.Integrated.1-2-1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data7 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110222-26.35.10.12__NIC.Slot.2-1-1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110222-26.35.10.12__NIC.Slot.2-1-1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data8 = response.json()

    if args["x"]:
         response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110222-26.35.10.12__NIC.Slot.2-2-1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/Current-110222-26.35.10.12__NIC.Slot.2-2-1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data9 = response.json()

    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip,response.status_code))
        logging.warning(data1)
        sys.exit(0)       
    table1 = [
        ("Bios Version", data1['BiosVersion']),
        ("iDRAC Version", data2['FirmwareVersion']),
        ("Backplane", data3['Oem']['Dell']['DellPCIeSSDBackPlane']['FirmwareVersion']),
        ("NVIDIA ConnectX-6 Lx 2x 25G SFP28 OCP3.0 SFF - 94:6D:AE:DA:EC:80", data6["Version"]),
        ("NVIDIA ConnectX-6 Lx 2x 25G SFP28 OCP3.0 SFF - 94:6D:AE:DA:EC:81", data7["Version"]),
        ("NVIDIA ConnectX-6 Lx 2x 25G SFP28 - B8:3F:D2:96:24:F2", data8["Version"]),
        ("NVIDIA ConnectX-6 Lx 2x 25G SFP28 - B8:3F:D2:96:24:F3", data9["Version"])]

    print("\n=================== FIRMWARE INFORMATION OF THE SERVER ===================")
    print(tabulate(table1, headers=["Keys", "Output"], tablefmt="pretty"))
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
    print(tabulate(table, headers=["Keys", "Output"], tablefmt="pretty", missingval= "N/A"))
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
    print(tabulate(memory_information, headers=["Id", "Health"], tablefmt="pretty", missingval= "N/A"))
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
    print(tabulate(mac_addresses, headers=["Description", "MAC Address", "Health"], tablefmt="pretty", missingval= "N/A"))

def get_physical_drives():
    drives_info = []
    for i in range(8):
        url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Storage/CPU.1/Drives/Disk.Bay.%d:Enclosure.Internal.0-1' % (idrac_ip, i)
        if args["x"]:
            response = requests.get(url, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get(url, verify=verify_cert, auth=(idrac_username, idrac_password))
        data = response.json()
        drives_info.append((data['Id'], data['Status']['HealthRollup']))
    print("\n=================== INFORMATION OF PHYSICAL DRIVE  ===================" )
    print(tabulate(drives_info, headers=["Id", "HealthRollup"], tablefmt="pretty", missingval= "N/A"))
    print()

def get_fan_information():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Thermal' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Thermal' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()

    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip,response.status_code))
        logging.warning(data)
        sys.exit(0)  

    table1 = [("Fans", data['Fans'])]
    print("\n=================== HEALTH INFORMATION OF THE FANS ===================")
    #print(tabulate(table1, headers=["Keys"], tablefmt="pretty", missingval= "N/A"))
    pp(table1)

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
    if args["system"]:
        get_information_of_the_server()
    if args["firmware"]:
        get_firmware_information_of_the_server()
    if args["drives"]:
        get_physical_drives()
    if args["memory"]:
        get_memory_information()
    if args["fans"]:
        get_fan_information()
    if args["all"]:
        get_information_of_the_server()
        get_firmware_information_of_the_server()
        get_boot_order()
        get_the_mac_address()
        get_physical_drives()
        get_memory_information()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
