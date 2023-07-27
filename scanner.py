import os
import platform
import ipaddress
import requests
from datetime import datetime

from dotenv import load_dotenv

# Load the environment variables from the .env file
load_dotenv()

# Access the variables using os.environ
NETBOX_URL = os.environ.get("NETBOX_URL")
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")


# Add subnet to scan
ip_subnet = "192.168.1.0/24"


def get_ip_from_subnet(ip_subnet):
    ips = ipaddress.ip_network(ip_subnet)
    ip_list = [str(ip) for ip in ips]
    # Remove the first and last elements from the ip_list
    ip_list = ip_list[1:-1]
    return ip_list

def check_ip_in_netbox(ip_address):
    headers = {
        "Authorization": f"Token {NETBOX_TOKEN}",
        "Content-Type": "application/json",
    }

    params = {
        "address": ip_address,
    }

    response = requests.get(NETBOX_URL, params=params, headers=headers, verify=False)

    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("count", 0) > 0:
                print('IP address already exists in NetBox')
                return True  # IP address already exists in NetBox
        except ValueError:
            # If the response is not JSON, handle it here (e.g., print the response)
            print("Response is not in JSON format:", response.text)
    return False

def add_ip_to_netbox(ip_address):
    if not check_ip_in_netbox(ip_address):
        headers = {
            "Authorization": f"Token {NETBOX_TOKEN}",
            "Content-Type": "application/json",
        }

        data = {
            "address": ip_address,
            "status": "active",  # You can set the desired status for the IP address
            "description": "autodiscovery"
            # Additional fields like "description", "tags", etc., can be included here
        }

        response = requests.post(NETBOX_URL, json=data, headers=headers, verify=False)

        if response.status_code == 201:
            print(f"Added {ip_address} to NetBox.")
        else:
            print(f"Failed to add {ip_address} to NetBox.")
    else:
        print(f"{ip_address} already exists in NetBox.")



ips = get_ip_from_subnet(ip_subnet)

oper = platform.system()

if (oper == "Windows"):
    ping1 = "ping -n 1 "
elif (oper == "Linux"):
    ping1 = "ping -c 1 "
else:
    ping1 = "ping -c 1 "

t1 = datetime.now()
print("Scanning in Progress:")

for addr in ips:
    print(addr)
    comm = ping1 + addr
    response = os.popen(comm)

    for line in response.readlines():
        if "ttl" in line.lower():
            # Add the IP address to NetBox if it responds to ping
            add_ip_to_netbox(addr)
            break

t2 = datetime.now()
total = t2 - t1
print("Scanning completed in: ", total)
