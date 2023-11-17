qc1.py
import argparse
import getpass
import logging
import requests
import sys
import warnings
from tabulate import tabulate

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
parser.add_argument('-ip', help='Pass in iDRAC IP address or range (e.g., 10.2.101-105)', required=False)
parser.add_argument('-u', help='Pass in iDRAC username', required=False)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in "true". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--system', help='Get the system information', action="store_true", required=False)
parser.add_argument('--all', help='Get the Information of the Server', action="store_true", required=False)

args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- python3 qc.py -ip 10.2.101-105 --all, this will get the information of the Servers in the range 10.2.101-105.""")
    sys.exit(0)

def check_supported_idrac_version(idrac_ip, verify_cert, idrac_username, idrac_password):
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

def get_information_of_the_server(idrac_ip, verify_cert, idrac_username, idrac_password):
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data1 = response.json()

    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get the information of the server %s, status code %s returned." % (idrac_ip, response.status_code))
        logging.warning(data1)
        sys.exit(0)

    table1 = [
        ("1", "Model", data1.get('Model', 'N/A')),
        ("2", "Serial Number", data1.get('SerialNumber', 'N/A'))
    ]

    headers = ["Index", "Keys", "Output"]
    
    print("\n=================== INFORMATION OF THE SERVER ===================")
    print(tabulate(table1, headers=headers, tablefmt="pretty"))
    print()

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()

    if args["ip"]:
        ip_range = args["ip"]
        start, _, end = ip_range.partition('-')

        if not start or not end:
            logging.error("\n- FAIL, invalid IP range format. Use a range like 10.2.101-105.")
            sys.exit(0)

        start_ip = int(start.split('.')[-1])
        end_ip = int(end)

        for i in range(start_ip, end_ip + 1):
            current_ip = ".".join(start.split('.')[:-1] + [str(i)])

            idrac_username_input = args["u"] or input("\n- Enter iDRAC username for {}: ".format(current_ip))
            idrac_password_input = args["p"] or getpass.getpass("\n- Enter iDRAC password for {}: ".format(current_ip))
            verify_cert_input = args["ssl"] == "true"  # Adjust this based on your requirements

            check_supported_idrac_version(current_ip, verify_cert_input, idrac_username_input, idrac_password_input)

            if args["system"] or args["all"]:
                get_information_of_the_server(current_ip, verify_cert_input, idrac_username_input, idrac_password_input)
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")


qc2.py
import argparse
import getpass
import logging
import requests
import sys
from tabulate import tabulate

# Suppressing SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    """Provide examples of how to execute the script."""
    print("\nUsage examples:")
    print("- python3 your_script_name.py -ip 10.2.101-105 --all")
    sys.exit(0)

def check_supported_idrac_version(idrac_ip, verify_cert, idrac_username, idrac_password):
    """Check if the iDRAC version is supported."""
    try:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip
        headers = {'X-Auth-Token': args["x"]} if args["x"] else {}
        response = requests.get(url, verify=verify_cert, headers=headers, auth=(idrac_username, idrac_password) if not args["x"] else None)

        if response.status_code == 401:
            logging.warning("\n- WARNING: Authentication failed. Check iDRAC username/password credentials.")
            sys.exit(0)
        elif response.status_code != 200:
            logging.warning(f"\n- WARNING: GET request failed to validate iDRAC creds, status code {response.status_code} returned.")
            logging.warning(response.json())
            sys.exit(0)
    except Exception as e:
        logging.error(f"\n- ERROR: An error occurred while checking iDRAC version: {str(e)}")
        sys.exit(1)

def get_information_of_the_server(idrac_ip, verify_cert, idrac_username, idrac_password):
    """Retrieve and display information about the server."""
    try:
        url = 'https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip
        headers = {'X-Auth-Token': args["x"]} if args["x"] else {}
        response = requests.get(url, verify=verify_cert, headers=headers, auth=(idrac_username, idrac_password) if not args["x"] else None)
        response.raise_for_status()

        data = response.json()
        table_data = [
            ("1", "Model", data.get('Model', 'N/A')),
            ("2", "Serial Number", data.get('SerialNumber', 'N/A'))
        ]

        headers = ["Index", "Keys", "Output"]
        print("\n=================== INFORMATION OF THE SERVER ===================")
        print(tabulate(table_data, headers=headers, tablefmt="pretty"))
        print()
    except requests.exceptions.RequestException as e:
        logging.warning(f"\n- WARNING: GET request failed to get the information of the server {idrac_ip}, error: {str(e)}")
        sys.exit(0)
    except Exception as e:
        logging.error(f"\n- ERROR: An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
    parser.add_argument('-ip', help='Pass in iDRAC IP address or range (e.g., 10.2.101-105)', required=False)
    parser.add_argument('-u', help='Pass in iDRAC username', required=False)
    parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
    parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in "true". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
    parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
    parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
    parser.add_argument('--system', help='Get the system information', action="store_true", required=False)
    parser.add_argument('--all', help='Get the Information of the Server', action="store_true", required=False)

    args = vars(parser.parse_args())

    if args["script_examples"]:
        script_examples()

    if args["ip"]:
        ip_range = args["ip"]
        start, _, end = ip_range.partition('-')

        if not start or not end:
            logging.error("\n- FAIL: Invalid IP range format. Use a range like 10.2.101-105.")
            sys.exit(0)

        start_ip = int(start.split('.')[-1])
        end_ip = int(end)

        for i in range(start_ip, end_ip + 1):
            current_ip = ".".join(start.split('.')[:-1] + [str(i)])

            idrac_username_input = args["u"] or input("\n- Enter iDRAC username for {}: ".format(current_ip))
            idrac_password_input = args["p"]
