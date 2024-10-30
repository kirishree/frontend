import subprocess
import psutil
import ipaddress
import requests
import time
import json
import socket
import os
import netifaces as ni
import re
import ipaddress
from netaddr import IPAddress
import logging
logging.basicConfig(filename='/var/log/reachwan.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


file_path = "/etc/reach/register_info.json"
url = "http://172.104.146.239:5000/"

def get_tunnel_ip():
    interface = psutil.net_if_addrs()      
    for intfc_name in interface:    
        addresses = interface[intfc_name]
        for address in addresses:      
            if address.family == 2:  
                ip = str(address.address)                        
                if ipaddress.ip_address(ip) in ipaddress.ip_network('10.8.0.0/24'):
                    return str(address.address)
    return "None"

def get_wan_ip():
    interface = psutil.net_if_addrs()
    addresses = interface["Reach_int1"]
    wan_ip = "None"
    for address in addresses:      
        if address.family == 2:
            pre_len = IPAddress(address.netmask).netmask_bits()
            wan_ip = str(address.address)+"/"+str(pre_len)    
            return wan_ip
    return wan_ip               


def get_system_uuid():
    try:
        # Read the product_uuid file to get the system UUID
        with open('/sys/class/dmi/id/product_uuid', 'r') as file:
            uuid = file.read().strip()
        return uuid
    except Exception as e:        
        return "None"
    
def get_local_public_ip():
    try:
        command = (f"ping -c 3  8.8.8.8")
        subprocess.check_output(command.split())
        ip_service_url = "https://api64.ipify.org?format=json"
        response = requests.get(ip_service_url)
        Local_public_ip = response.json()["ip"]
        return Local_public_ip
    except Exception as e:        
        return "None"

   
def get_vpp_default_route():
    try:
        # Execute the VPP CLI command to display FIB table information
        output = subprocess.check_output(['sudo', 'vppctl', 'show ip fib'], text=True)
        
        # Parse the output to extract the default route information
        default_route_info = None
        i = 0
        for line in output.split('\n'):
            if '0.0.0.0/0' in line:                
                print("default", line)
                i = 1
                break
        if i ==1:
            for line in output.split('\n'):
                if "ipv4 via" in line:
                    print(line)
                    default_route_info = line.split("via")[1].split(" ")[1] 
                    print(default_route_info)
                    return default_route_info
    except subprocess.CalledProcessError as e:
        print("Error occurred:", e)
    return False
    
def get_default_gateway():
    try:
        return ni.gateways()['default'][ni.AF_INET][0]
    except (KeyError, IndexError):
        return False
    
def ping_gateway():
    # Restart FRR service
    os.system("sudo systemctl restart frr")
    # Check the status of the FRR service and wait until it is active
    time.sleep(2)  # Wait for 1 second before checking again        
    # Run 'systemctl is-active frr' to check if FRR is active
    status = subprocess.run(["systemctl", "is-active", "frr"], stdout=subprocess.PIPE, text=True).stdout.strip()
    if status == "active":
        df_gw = get_default_gateway()
        print(df_gw)
        if (df_gw):
            command = (f"ping -c 5 {df_gw}")
            try:
                subprocess.check_output(command.split())
                os.system("sudo systemctl restart openvpn@client")   
                return True
            except subprocess.CalledProcessError as e:
                return False           
    logging.error(f"Error: Frr is not Active-Running")
    os.system("cp /etc/frr/frr_bfstatic.conf /etc/frr/frr.conf")
    return False     
            
    
    
def change_config(file_path):
    # Read the file content
    with open(file_path, 'r') as file:
        content = file.readlines()
    # Pattern to match the line with variable part (assumes {something vary} can be any text)
    pattern1 = r"set int ip address GigabitEthernet0/3/0 .+"
    pattern2 = r"ip route add 0.0.0.0/0 via .+"
    # Replacement line
    replacement1 = "set dhcp client intfc GigabitEthernet0/3/0\n"
    replacement2 = " "
    # Replace the matching line
    with open(file_path, 'w') as file:
        for line in content:
            new_line = re.sub(pattern1, replacement1, line)
            new_line = re.sub(pattern2, replacement2, line)
            file.write(new_line)

def ping_vpp_gateway():
    try:
        command = f"vppctl ping 8.8.8.8"
        try:
            print(command)
            vpp_df_gw = get_vpp_default_route()
            if vpp_df_gw == False:
                os.system("sudo systemctl restart vpp")
                time.sleep(120)
                vpp_df_gw = get_vpp_default_route()
            else:
                vpp_out = subprocess.check_output(command.split()).decode()
                print(vpp_out)
                if "100% packet loss" in vpp_out:
                    print("VPP doesn't get internet")
                    command_vpp_gw = f"vppctl ping {vpp_df_gw}"
                    gw_out = subprocess.check_output(command_vpp_gw.split()).decode()
                    if "100% packet loss" in gw_out:
                        print("VPP's Gateway is not pinging")
                        current_vpp_gw = vpp_df_gw
                        os.system("cp /etc/vpp/bootstrap.vpp /etc/reach/reachwan/bootstrap-saved.vpp")
                        os.system("cp /etc/vpp/backup.vpp /etc/reach/reachwan/backup-saved.vpp")
                        change_config('/etc/vpp/backup.vpp')
                        change_config('/etc/vpp/boostrap.vpp')
                        os.system("sudo systemctl restart vpp")
                        time.sleep(120)
                        vpp_df_gw = get_vpp_default_route()
                        if vpp_df_gw == False:
                            os.system("cp /etc/reach/reachwan/bootstrap-saved.vpp /etc/vpp/bootstrap.vpp")
                            os.system("cp /etc/reach/reachwan/backup-saved.vpp /etc/vpp/backup.vpp ")
                            os.system("sudo systemctl restart vpp")
                            time.sleep(120)
                            vpp_df_gw = get_vpp_default_route()
            if vpp_df_gw:  
                command_vpp_gw = f"vppctl ping {vpp_df_gw}"
                gw_out = subprocess.check_output(command_vpp_gw.split()).decode()
                if "100% packet loss" in gw_out:  
                    logging.error("vpp doesn't connect with internet GW")
                # Start the vtysh process
                else:
                    with open("/etc/frr/frr.conf", "a") as f:
                        f.write(f"\n!\nip route 0.0.0.0/0 {vpp_df_gw}\n!")
                        f.close()
                    # Restart FRR service
                    os.system("sudo systemctl restart frr")
                    # Check the status of the FRR service and wait until it is active
                    while True:
                        # Run 'systemctl is-active frr' to check if FRR is active
                        status = subprocess.run(["systemctl", "is-active", "frr"], stdout=subprocess.PIPE, text=True).stdout.strip()
                        if status == "active":
                            logging.debug(f"Static route 0.0.0.0/0 via {vpp_df_gw} configured successfully.")
                            break  # Exit loop if FRR is active
                        logging.error(f"Error: Frr is not Active-Running")
                        os.system("cp /etc/frr/frr_bfstatic.conf /etc/frr/frr.conf")
                        time.sleep(1)  # Wait for 1 second before checking again                     
                    os.system("sudo systemctl restart openvpn@client")
            else:
                logging.error("vpp doesn't get any default route")
        except subprocess.CalledProcessError as e:
            logging.error("VPP doesn't get internet", e)        
    except Exception as e:        
        return "None"

def main():
    while True:
        try:
            get_df_gw = get_default_gateway()
            tunnel_ip = get_tunnel_ip() 
            wan_ip = get_wan_ip()  
            print(tunnel_ip)               
            public_ip = get_local_public_ip()            
            if public_ip != "None":
                with open(file_path, 'r') as f:
                    reg_info = json.load(f)
                    f.close()  
                if "wan_ip"  not in reg_info:
                    reg_info["wan_ip"] = 'None'
                print(reg_info)
                if reg_info["tunnel_ip"] != tunnel_ip or reg_info["public_ip"] != public_ip or wan_ip != reg_info["wan_ip"]:
                    print("hi")
                    system_uuid = get_system_uuid()                       
                    collect = {"username": reg_info["registered_mail_id"],
                                "password": reg_info["registered_password"],
                                "uuid": system_uuid,                                
                                "tunnel_ip": tunnel_ip,
                                "public_ip": public_ip,
                                "wan_ip": wan_ip
                                }                    
                    # Convert the Python dictionary to a JSON string
                    json_data = json.dumps(collect)                     
                    # Set the headers to indicate that you are sending JSON data
                    headers = {"Content-Type": "application/json"}
                    # Make the POST request
                    response = requests.post(url+"ip_update", data=json_data, headers=headers)
                    # Check the response
                    if response.status_code == 200:                        
                        reg_info["tunnel_ip"] = tunnel_ip
                        reg_info["public_ip"] = public_ip
                        reg_info["wan_ip"] = wan_ip
                        with open(file_path, 'w') as f:
                            json.dump(reg_info, f)
                            f.close()                
            else:
                if(ping_gateway()):
                    logging.error("wait until network back")
                else:
                    ping_vpp_gateway()               
                
        except Exception as e:
            logging.error(f"Error while updating tunnel ip to ReachManage:{e}")
        time.sleep(120)
if __name__ == "__main__":
    main()
