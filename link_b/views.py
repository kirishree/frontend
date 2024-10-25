from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import json
import yaml
import psutil
from netaddr import IPAddress
import netifaces as ni
from pyroute2 import IPRoute
import subprocess
import ipaddress
ipr = IPRoute()
import threading
import dns.resolver
import dns.exception
import re


file_path = "/etc/reach/reachlink_info.json"

routes_protocol_map = {
    -1: '',
    2: 'kernel',
    3: 'boot',
    4: 'static',    
    16: 'dhcp',    
}


@csrf_exempt
def addroute(request: HttpRequest):
    response = [{"message":"Successfully added"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            data1 = yaml.safe_load(f)
            f.close()
        dat=[]
        for rr in data1["network"]["ethernets"]["eth1"]:
            if rr == "routes":
                dat = data1["network"]["ethernets"]["eth1"]["routes"]
        for r in subnet_info:
           try:
              print(r["subnet"])
              print(r["gateway"])
              if (ipaddress.ip_network(r["subnet"], strict=False) and ipaddress.ip_address(r["gateway"])):
                  dat.append({"to": r["subnet"],
                        "via": r["gateway"]}
                        )
                  print(dat)
           except ValueError:
             response = [{"message":"Either subnet or Gateway is not valid IP"}]        
        data1["network"]["ethernets"]["eth1"]["routes"] = dat
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(data1, f, default_flow_style=False)
            f.close()
        os.system("sudo netplan apply")  
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route: {e}"}]
    return HttpResponse(response)   

@csrf_exempt
def delroute(request: HttpRequest):
    response = [{"message":"Successfully deleted"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            data1 = yaml.safe_load(f)
            f.close()
        dat=[]
        for rr in data1["network"]["ethernets"]["eth1"]:
            if rr == "routes":
                dat = data1["network"]["ethernets"]["eth1"]["routes"]
        
        for r in subnet_info:            
#            to_delete = {"to": r["subnet"],
 #                        "via": r["gateway"]}
            dat = [item for item in dat if item.get('to') != r['subnet']]
        data1["network"]["ethernets"]["eth1"]["routes"] = dat
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(data1, f, default_flow_style=False)
            f.close()
        os.system("sudo netplan apply")  
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route: {e}"}]
    return HttpResponse(response)    

def prefix_length_to_netmask(prefix_length):
    """
    Convert prefix length to netmask.

    Args:
    prefix_length (int): The prefix length.

    Returns:
    str: The netmask in dotted decimal notation.
    """
    netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
    return str(ipaddress.IPv4Address(netmask))

@csrf_exempt 
def checksubnet(request: HttpRequest):
  data = json.loads(request.body)  
  ip_addresses = [data["subnet"].split("/")[0]]
  for ip in ip_addresses:    
    try:
        command = (f"ip vrf exec default ping -c 5  {ip}")
        output = subprocess.check_output(command.split()).decode()
        lines = output.strip().split("\n")
        # Extract the round-trip time from the last line of output
        last_line = lines[-1].strip()
        rtt = last_line.split()[3]
        rtt_avg = rtt.split("/")[1]
        response = [{"avg_rtt":rtt_avg}]
        return JsonResponse(response, safe=False)
    except subprocess.CalledProcessError:
        rtt_avg = -1
    response = [{"avg_rtt":rtt_avg}]  
  return JsonResponse(response, safe=False)

@csrf_exempt
def traceroute_spoke(request):
   data = json.loads(request.body)
   print(data)
   host_ip = data.get('trace_ip')
   if host_ip:
      result1 = subprocess.run(['ip', 'vrf', 'exec', 'default','traceroute', '-d', host_ip], capture_output=True, text=True)
      print(result1)
      print(result1.stdout)
      return HttpResponse(result1.stdout, content_type='text/plain')
   return HttpResponse(status=400)


@csrf_exempt 
def changedefaultgw(request: HttpRequest):
  data = json.loads(request.body)  
  os.system(f"ip route replace table 10 default via {data['default_gw']}")
  response ={"message":"Fixed successfully"}
  return JsonResponse(response, safe=False)

@csrf_exempt
def delete(request):
  os.system("ip tunnel del Reach_link1")
  os.system("systemctl stop reachlink")
  os.system("systemctl disable reachlink")
  #os.system("apt remove reachlink")
  #os.system("rm -r /etc/reach")
  response = {"msg":"Successfully deleted"}
  return HttpResponse(response) 

def background_update(data):
    file_name_tar = data.get('file_name')
    url = data.get('url')
    with open(file_path, "r") as f:
        data_json = json.load(f)
        f.close()
    default_gw = data_json["default_gateway"]
    os.system("systemctl stop reachlink")
    os.system(f"ip route replace default via {default_gw}")
    os.system(f'wget {url}')
    os.system(f"tar -xvf {file_name_tar}")
    file_name = file_name_tar.split(".tar")[0]
    os.system(f"cp -r {file_name}/views.py link/views.py")
    os.system(f"cp -r {file_name}/urls.py linkgui/urls.py")
    os.system("apt remove reachlink")
    os.system(f"dpkg -i {file_name}/reachlink.deb")
    os.system(f"cp {file_name}/reachlink.service /etc/systemd/system/")
    os.system("systemctl enable reachlink")
    os.system("systemctl start reachlink")
    os.system("systemctl restart reachlinkgui")
    

@csrf_exempt
def update (request: HttpRequest):
    data = json.loads(request.body)
    background_thread = threading.Thread(target=background_update,  args=(data,))
    background_thread.start()
    response = [{"message": "Update successfull"}]
    return HttpResponse(response)

@csrf_exempt
def download_logfile(request):
    # Read the contents of the logfile
    logfile_content = ""
    if os.path.exists("/var/log/reachlink.log"):
        with open('/var/log/reachlink.log', 'r') as file:
            logfile_content = file.read()
            file.close()
    # Create an HTTP response with the logfile content as a downloadable file
    response = HttpResponse(logfile_content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="reachlink.log"'
    return response

def prefix_len_to_netmask(prefix_len):
    # Validate the prefix length
    print(prefix_len)
    prefix_len = int(prefix_len)
    if not 0 <= prefix_len <= 32:
        raise ValueError("Prefix length must be between 0 and 32")
    # Calculate the netmask using bitwise operations
    netmask = 0xffffffff ^ (1 << (32 - prefix_len)) - 1
    # Format the netmask into IP address format
    netmask_str = ".".join(str((netmask >> i) & 0xff) for i in [24, 16, 8, 0])
    return netmask_str

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Get the subnet ID and broadcast address
    subnet_id = subnet.network_address
    broadcast_ip = subnet.broadcast_address

    # Extract and return the list of host IPs (excluding subnet ID and broadcast IP)
    #host_ips = [str(ip) for ip in subnet.hosts()]
    
    if subnet.prefixlen == 31:
        # For /31, both IPs can act as hosts (point-to-point links)
        first_host = subnet.network_address
        last_host = subnet.broadcast_address
    else:
        # For other subnets, calculate first and last host IPs
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1

   
    host_ips = [first_host, last_host]    
    return {
        "Subnet_ID": str(subnet_id),
        "Broadcast_IP": str(broadcast_ip),
        "Host_IPs": host_ips
    }


def calculate_subnet_id(ip_address, netmask):
    try:
        # Split the IP address and netmask into octets
        ip_octets = [int(octet) for octet in ip_address.split('.')]
        netmask_octets = [int(octet) for octet in netmask.split('.')]
        # Calculate the subnet ID
        subnet_id_octets = [ip_octets[i] & netmask_octets[i] for i in range(4)]
        # Convert the subnet ID octets back to a string
        subnet_id = '.'.join(map(str, subnet_id_octets))
    except Exception as e:
        return ip_address       
    return subnet_id


def  validateIP(ip_address):
    octet = ip_address.split(".")
    prefix_len = ip_address.split("/")[1]
    if prefix_len == 32:
        return False
    if octet[0] == "10":
        if int(prefix_len) > 7:
            return True
    if octet[0] == "172":
        if 15 < int(octet[1]) < 32:
            if int(prefix_len) > 15:
                return True
    if octet[0] == "192" and octet[1] == "168":
        if int(prefix_len) > 23:
            return True    
    return False

@csrf_exempt
def lan_config(request):
    try:
        data = json.loads(request.body)
        ip_address = data.get("ipaddress")
        if not (validateIP(ip_address)):
            response = {"message": "Error: IP should be in private range"} 
            print(response)  
            return JsonResponse(response, safe=False)
        netmask = prefix_len_to_netmask(ip_address.split("/")[1])
        ip_addr = ip_address.split("/")[0]               
        
        ip_addresses = get_ip_addresses(ip_addr, netmask) 
        print(ip_addresses["Subnet_ID"]) 
        lan_address = ip_addresses["Subnet_ID"]
        print(ip_addresses[ "Broadcast_IP"])
        if ip_addr == ip_addresses["Subnet_ID"] or ip_addr ==  ip_addresses[ "Broadcast_IP"]:
            response = {"message": "Error: Either Subnet ID or Broadcast IP is not able to assign"}  
            print(response) 
            return JsonResponse(response, safe=False)
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            network_config = yaml.safe_load(f)
            f.close()
        network_config["network"]["ethernets"]["eth1"]["addresses"] = [ip_address]
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(network_config, f, default_flow_style=False)
            f.close()
        os.system("netplan apply")

        #configuring DHCP Range accordingly 
        
        dhcp_start_address = ip_addresses["Host_IPs"][0]
        dhcp_end_address = ip_addresses["Host_IPs"][1]                             
        domain_name = "8.8.8.8"
        optional_dns = "8.8.4.4"
        bracket = "{"
        closebracket ="}"                
        #Configure dhcpd.conf file
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet {lan_address} netmask {netmask} {bracket} \n range {dhcp_start_address} {dhcp_end_address}; \n option routers {ip_addr}; \n option subnet-mask {netmask}; \n option domain-name-servers {domain_name}, {optional_dns}; \n{closebracket}")
            f.close() 
        os.system("systemctl restart isc-dhcp-server")   
        response = {"message": "Lan address configured successfully"}            
        
    except Exception as e:
        response = {"message": f"Error: {e}"} 
    print(response)
    return JsonResponse(response, safe=False)

def validate_dns_server(dns_ip, domain='google.com'):
    try:
        # Construct the command to run a DNS query in the default VRF
        cmd = f"ip vrf exec default dig +short {domain} @{dns_ip}"

        # Run the command using subprocess and capture the output
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True, timeout=3
        )

        # Check if the command was successful and output is non-empty
        if result.returncode == 0 and result.stdout.strip():
            print(f"{dns_ip} is a valid DNS server.")
            print("Resolved IP(s):", result.stdout.strip())
            return True
        else:
            print(f"Failed to resolve {domain} using {dns_ip}.")
            print(f"Error: {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"DNS query timed out for {dns_ip}.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def get_lan_info():
    interface = psutil.net_if_addrs()
    lan_addr = "none"     
    for intfc_name in interface:
        if intfc_name == "eth1":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                                    
                    
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    lan_addr = str(address.address)+"/"+str(pre_len)
                    return lan_addr 
    return lan_addr  
def is_ip_in_network(ip, network):
    try:
        # Convert IP and network to objects
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)

        # Check if the IP is part of the network
        if ip_obj in network_obj:
            print(f"{ip} belongs to the network {network}.")
            return True
        else:
            print(f"{ip} does not belong to the network {network}.")
            return False
    except ValueError as e:
        print(f"Invalid IP or network: {e}")
        return False
@csrf_exempt
def dhcp_config(request):
    try:
        data = json.loads(request.body)
        ip_address = data.get("ipaddress")
        domain_name = data.get("primary_dns","8.8.8.8")
        optional_dns = data.get("secondary_dns", "8.8.4.4")
        if not validate_dns_server(domain_name):
            response = {"message": f"Error: Primary DNS server is not valid DNS server"} 
            return JsonResponse(response, safe=False)
        if not validate_dns_server(optional_dns):
            response = {"message": f"Error: Secondary DNS server is not valid DNS server"} 
            return JsonResponse(response, safe=False)       

        #configuring DHCP Range accordingly 
        netmask = prefix_len_to_netmask(ip_address.split("/")[1])
        ip_addr = ip_address.split("/")[0]                
        lan_address = calculate_subnet_id(ip_addr, netmask)
        ip_addresses = get_ip_addresses(ip_addr, netmask)  
        dhcp_start_address = data.get("dhcp_start_addr", ip_addresses["Host_IPs"][0])
        dhcp_end_address = data.get("dhcp_end_addr",ip_addresses["Host_IPs"][1])
        network = get_lan_info()
        if network:
            if not is_ip_in_network(dhcp_start_address, network) or dhcp_start_address == ip_addresses["Subnet_ID"]:
                response = {"message": f"Error: DHCP start address is not in LAN subnet"} 
                return JsonResponse(response, safe=False) 
            if not is_ip_in_network(dhcp_start_address, network) or dhcp_end_address == ip_addresses[ "Broadcast_IP"]:
                response = {"message": f"Error: DHCP end address is not in LAN subnet"} 
                return JsonResponse(response, safe=False)       
                                    
        
        bracket = "{"
        closebracket ="}"                
        #Configure dhcpd.conf file
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet {lan_address} netmask {netmask} {bracket} \n range {dhcp_start_address} {dhcp_end_address}; \n option routers {ip_addr}; \n option subnet-mask {netmask}; \n option domain-name-servers {domain_name}, {optional_dns}; \n{closebracket}")
            f.close() 
        os.system("systemctl restart isc-dhcp-server")   
        response = {"message": "DHCP configured successfully"}
        with open("/etc/systemd/resolved.conf", "r") as f:
            dns_data = f.read()
            f.close()
        # Define the regex pattern to match any existing IP address for the interface
        pattern = rf"DNS=\S+"

        # Check if the pattern matches
        if re.search(pattern, dns_data):           
            dns_data = re.sub(pattern, f"DNS={domain_name} {optional_dns}\n", dns_data)
        with open("/etc/systemd/resolved.conf", "w") as f:
            f.write(dns_data)
            f.close()
        os.system("sudo systemctl restart systemd-resolved")                
        
    except Exception as e:
        response = {"message": f"Error: {e}"} 
    return JsonResponse(response, safe=False)


@csrf_exempt
def lan_info(request):
    try:
        response = {}
        lan_addr = get_lan_info()
        out1 = subprocess.check_output(["awk", "/range/ {print  $2, $3} /domain-name-servers/ {print $3, $4}", "/etc/dhcp/dhcpd.conf"]).decode()
        out2 = out1.split("\n")
        dhcp_start_addr = out2[0].split(" ")[0]
        dhcp_end_addr = out2[0].split(" ")[1].split(";")[0]
        primary_dns = out2[1].split(",")[0]
        sec_dns = out2[1].split(" ")[1].split(";")[0]
        response = {"dhcp_start_addr":dhcp_start_addr,
                   "dhcp_end_addr":dhcp_end_addr,
                   "primary_dns":primary_dns,
                   "sec_dns":sec_dns,
                   "lan_ipaddr": lan_addr}
    except Exception as e:
        print(e)
    print(response)
    return JsonResponse(response, safe=False)





