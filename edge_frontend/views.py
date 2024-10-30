from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.http import HttpResponse, JsonResponse
from .forms import ContactForm, NetworkSettingsForm, LANSettingsForm, OptionalAdapterSettingsForm, TimeZoneForm, ChangePassword, PingForm, TraceRouteForm
import ipaddress
import json
import os
import psutil
import subprocess
import requests
import re
import json
import socket
import yaml
from datetime import datetime, date
url = "http://172.104.146.239:5000/"
import pymongo
from vpp_papi import VPPApiClient
import fnmatch
from netaddr import IPAddress
import time
file_path = "/etc/reach/register_info.json"
import ipaddress
sleep_time = 60
from pyroute2 import IPRoute
ipr = IPRoute()

routes_protocol_map = {
    -1: '',
    196: 'static',
    2: 'kernel',
    3: 'boot',
    4: 'static',    
    16: 'dhcp',    
}

vpp_json_dir = '/usr/share/vpp/api/'
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
  for filename in fnmatch.filter(filenames, '*.api.json'):
    jsonfiles.append(os.path.join(root, filename))

vpp = VPPApiClient(apifiles=jsonfiles, server_address='/run/vpp/api.sock')

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["reachedge_info"]
coll_routing_table = db["routing_table"]
coll_interface_details = db["edge_interface_details"]
coll_vpp_interface_info = db["vpp_interface_info"]
coll_vpp_interface_details = db["edge_vpp_interface_details"]
coll_vpp_interface_info_backup = db["vpp_interface_info_backup"]

def change_password(username, new_password):
    try:
        # Retrieve the user object
        user = User.objects.get(username=username)        
        # Change the password
        user.password = make_password(new_password)
        user.save()
        return True        
    except ObjectDoesNotExist:
        return False
    except Exception as e:
        return False

def get_system_uuid():
    try:
        # Read the product_uuid file to get the system UUID
        with open('/sys/class/dmi/id/product_uuid', 'r') as file:
            uuid = file.read().strip()
        return uuid
    except Exception as e:
        print(f"Error: {e}")
        return None

class CustomLoginView(LoginView):
    template_name = 'login.html'
    redirect_authenticated_user = True
    success_url = reverse_lazy('dashboard')  # Redirect to contact page after login

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to the login page

def get_interface_details():  
    interface = psutil.net_if_addrs()  
    for intfc_name in interface:
        if intfc_name == "Reach_int1":
            return True
    return False

def get_local_public_ip():
    try:
        command = (f"ping -c 5  8.8.8.8")
        subprocess.check_output(command.split())
        ip_service_url = "https://api64.ipify.org?format=json"
        response = requests.get(ip_service_url)
        Local_public_ip = response.json()["ip"]
        return Local_public_ip
    except Exception as e:        
        return False

def get_default_route_info():
    try:
        # Execute the VPP CLI command to display FIB table information
        output = subprocess.check_output(['sudo', 'vppctl', 'show ip fib'], text=True)
        # Parse the output to extract the default route information
        default_route_info = None
        i = 0
        for line in output.split('\n'):
            if '0.0.0.0/0' in line:                
                i = 1
            if i > 0 and i < 5:
                i = i+1
            if i == 5:
                i = i+1
                default_route_info = line.split("via")[1].split(" ")[1] 
                print(default_route_info)
                break
        return default_route_info
    except subprocess.CalledProcessError as e:
        print("Error occurred:", e)
        return None
    
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

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Extract and return the list of IP addresses (excluding network and broadcast addresses)
    return [str(ip) for ip in subnet.hosts()]

def get_routing_table():
    routing_table = []
    try:        
        ipr = IPRoute()
        routes = ipr.get_routes(family=socket.AF_INET)
        for route in routes:
            if route['type'] == 1:
                destination = "0.0.0.0"
                metric = 0
                gateway = "none"
                protocol = int(route['proto'])
                multipath = 0
                dst_len = route['dst_len']
                for attr in route['attrs']:
                    if attr[0] == 'RTA_OIF':
                        intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                    if attr[0] == 'RTA_GATEWAY':
                        gateway = attr[1]
                    if attr[0] == 'RTA_PRIORITY':
                        metric = attr[1]
                    if attr[0] == 'RTA_DST':
                        destination = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    gateway = attr2[1] 
                                    multipath = 1
                                    routing_table.append({"interface_name":str(intfc_name),
                                                    "gateway":str(gateway),
                                                    "destination":str(destination)+"/"+str(dst_len),
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map[protocol]
                                                    })
                if multipath == 0:      
                    routing_table.append({"interface_name":str(intfc_name),
                                  "gateway":str(gateway),
                                  "destination":str(destination)+"/"+str(dst_len),
                                  "metric":int(metric),
                                  "protocol":routes_protocol_map[protocol]
                                })                
        return routing_table
    except Exception as e:
        return routing_table
    
def get_interface_info():
    try:
        coll_interface_details.delete_many({})
        interface = psutil.net_if_addrs()
        intfc_ubuntu = []
        for intfc_name in interface:
            colect = {"interface_name":intfc_name}
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    colect.update({
                                    "IPv4address_noprefix":str(address.address),
                                    "IPv4address":ipaddr_prefix,
                                    "netmask":str(address.netmask),
                                    "broadcast":str(address.broadcast)
                                  })
                if address.family == 17:
                    colect.update({
                                    "mac_address":str(address.address)
                                   })         
            intfc_ubuntu.append(colect)
            coll_interface_details.insert_one(colect)
        #By using pyroute module, we get the default route info & conclude which interface is WAN.  
        # And about its Gateway
        default_route = ipr.get_default_routes(family = socket.AF_INET)
        for route in default_route:
            if int(route['proto']) == 4:
                protocol = "static"
            elif int(route['proto']) == 16:
                protocol = "DHCP"
            multipath = 0
            for attr in route['attrs']:
                if attr[0] == 'RTA_OIF':
                    intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                if attr[0] == 'RTA_GATEWAY':
                    gateway = attr[1]
                if attr[0] == 'RTA_MULTIPATH':
                    multipath = 1
                    for elem in attr[1]:
                        intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                        for attr2 in elem['attrs']:
                            if attr2[0] == 'RTA_GATEWAY':
                                gateway = attr2[1] 
                                query = {"interface_name": intfc_name}
                                update_data = {"$set": {"gateway":gateway, "type":"wan", "protocol":protocol}}
                                coll_interface_details.update_many(query, update_data)                    
            if multipath == 0:
                query = {"interface_name": intfc_name}
                update_data = {"$set": {"gateway":gateway, "type":"wan", "protocol":protocol}}
                coll_interface_details.update_many(query, update_data)
        #By using DHCP conf file, compare the IPAdress of interface & DHCP subnet addnet Address
        #If both are in same subnet, conclude the interface type is LAN               
        for intfc in coll_interface_details.find():
            if "IPv4address_noprefix" in intfc:
                if "type" not in intfc:
                    subnet_addr = subprocess.check_output(["awk", "/subnet/ {print $2}", "/etc/dhcp/dhcpd.conf"]).decode()
                    net_mask = subprocess.check_output(["awk", "/netmask/ {print $4}", "/etc/dhcp/dhcpd.conf"]).decode()
                    netmas = net_mask.split("\n")[0]
                    pre_len = str(IPAddress(netmas).netmask_bits())
                    sub_addr = subnet_addr.split("\n")[0]+"/"+pre_len
                    if ipaddress.ip_address(intfc["IPv4address_noprefix"]) in ipaddress.ip_network(sub_addr):
                        query = {"interface_name": intfc["interface_name"]}
                        update_data = {"$set": {"type":"lan"}}
                        coll_interface_details.update_many(query, update_data)  
    except Exception as e:
        response = [{"message":f"Error while getting interface details: {e}"}]
        return response     

def check_tunnel_connection():
    try:       
        command = (f"ping -c 3  10.8.0.1")
        output = subprocess.check_output(command.split()).decode()          
        return True      
    except subprocess.CalledProcessError:        
        return False   
       
def get_vpp_interface_info():
    try:
        coll_vpp_interface_details.delete_many({})
        interface = psutil.net_if_addrs()
        intfc_ubuntu = []
        for intfc_name in interface:
            colect = {"interface_name":intfc_name}
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    colect.update({
                                    "IPv4address_noprefix":str(address.address),
                                    "IPv4address":ipaddr_prefix,
                                    "netmask":str(address.netmask),
                                    "broadcast":str(address.broadcast)
                                  })
                if address.family == 17:
                    colect.update({
                                    "mac_address":str(address.address)
                                   })         
            intfc_ubuntu.append(colect)
            coll_vpp_interface_details.insert_one(colect)
        #By using pyroute module, we get the default route info & conclude which interface is WAN.  
        # And about its Gateway
        default_route = ipr.get_default_routes(family = socket.AF_INET)
        for route in default_route:
            with open("/etc/vpp/bootstrap.vpp", "r") as f:
                vpp_info = f.read()
                f.close()
            if "set int ip address GigabitEthernet0/3/0" in vpp_info:
                protocol = "static"
            else:
                protocol = "DHCP"
            multipath = 0
            for attr in route['attrs']:
                if attr[0] == 'RTA_OIF':
                    intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                if attr[0] == 'RTA_GATEWAY':
                    gateway = attr[1]
                if attr[0] == 'RTA_MULTIPATH':
                    multipath = 1
                    for elem in attr[1]:
                        intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                        for attr2 in elem['attrs']:
                            if attr2[0] == 'RTA_GATEWAY':
                                gateway = attr2[1] 
                                query = {"interface_name": intfc_name}
                                update_data = {"$set": {"gateway":gateway, "type":"wan", "protocol":protocol}}
                                coll_vpp_interface_details.update_many(query, update_data)                    
            if multipath == 0:
                query = {"interface_name": intfc_name}
                update_data = {"$set": {"gateway":gateway, "type":"wan", "protocol":protocol}}
                coll_vpp_interface_details.update_many(query, update_data)
        #By using DHCP conf file, compare the IPAdress of interface & DHCP subnet addnet Address
        #If both are in same subnet, conclude the interface type is LAN               
        for intfc in coll_vpp_interface_details.find():
            if "IPv4address_noprefix" in intfc:
                if "type" not in intfc:
                    subnet_addr = subprocess.check_output(["awk", "/subnet/ {print $2}", "/etc/dhcp/dhcpd.conf"]).decode()
                    net_mask = subprocess.check_output(["awk", "/netmask/ {print $4}", "/etc/dhcp/dhcpd.conf"]).decode()
                    netmas = net_mask.split("\n")[0]
                    pre_len = str(IPAddress(netmas).netmask_bits())
                    sub_addr = subnet_addr.split("\n")[0]+"/"+pre_len
                    if ipaddress.ip_address(intfc["IPv4address_noprefix"]) in ipaddress.ip_network(sub_addr):
                        query = {"interface_name": intfc["interface_name"]}
                        update_data = {"$set": {"type":"lan"}}
                        coll_vpp_interface_details.update_many(query, update_data)  
    except Exception as e:
        response = [{"message":f"Error while getting interface details: {e}"}]
        return response     
       
def vpp_int_details():
    try:
        vpp.connect("test-client")
    except IOError as e:
        print("An IOError occured:",e)
        vpp.disconnect()
        vpp.connect("test-client")
    #By using sw_interface_dump api, get the details of interface such that 
    #MAC address, link speed, link mtu, link status & type available in vpp
    #IPAddress of interface can get via ip_address_dump() api
    try:  
        iface_list = vpp.api.sw_interface_dump()
    except vpp.VPPApiError as e:
        response = {"message":"Vpp Api error while getting interface details"}
        vpp.disconnect()
        return response  
    get_vpp_interface_info()    
    data = []
    int_ip = []
    for iface in iface_list:
        try:
            iface_ip = vpp.api.ip_address_dump(sw_if_index=iface.sw_if_index, is_ipv6=0)
        except vpp.VPPApiError as e:
            response = {"message":"Vpp Api error while getting ip address"}
            vpp.disconnect()
            return response
        if len(iface_ip) !=0:
            for intip in iface_ip:
                int_ip = intip.prefix
        else:
              int_ip = "none"        
        flags_map = {0:"Inactive", 2:"Down", 3:"Up"}
        colect = { "int_index":iface.sw_if_index, "int_mac_address":str(iface.l2_address), "int_ipv4_address":str(int_ip), "int_name":iface.interface_name, "int_status":flags_map[iface.flags] }
        for interface in coll_vpp_interface_details.find({},{'_id':0}):
            if "mac_address" in interface:
                if str(iface.l2_address) == interface["mac_address"]:
                    if "type" in interface:
                        colect.update({ "type": interface["type"]}) 
                    if "gateway" in interface:
                        colect.update({ "gateway": interface["gateway"]})           
        data.append(colect)  
    vpp.disconnect() 
    return data

def countdown_timer(seconds):
    for remaining in range(seconds, 0, -1):
        minutes, secs = divmod(remaining, 60)
        timer = '{:02d}:{:02d}'.format(minutes, secs)
        print(f"Time left: {timer}", end='\r')
        time.sleep(1)
    print("Time's up!")

def get_city_name():
    try:
        response = requests.get('https://ipinfo.io/json')
        data = response.json()
        print(data)
        city = data.get('city') + "@" + data.get("country")
        return city
    except Exception as e:
        print(f"Error: {e}")
    return None

def register_post(form):           
    # Process form data            
            email = form.cleaned_data['Registered_mail']
            password = form.cleaned_data['password']  
            branch_location = get_city_name()                    
            reg_data = { "registered_mail_id": email,
                         "registered_password": password,
                         "branch_location": branch_location
                         }
            system_uuid = get_system_uuid()
            try:
                system_name = os.getlogin() + "@" + socket.gethostname()
            except Exception as e:
                system_name = "etel@reachwan"
            gateway = get_default_route_info()
            if gateway == None:                
                return "error"
            with open("/etc/frr/frr.conf", "a")as f:
                f.write(f"\n!\nip route 0.0.0.0/0 {gateway}\n!\n")
                f.close()
            os.system("systemctl restart frr")
            public_ip = get_local_public_ip()
            collect = { "username": reg_data["registered_mail_id"], 
                    "password": reg_data["registered_password"],
                    "uuid": system_uuid,               
                    "system_name": system_name,
                    "tunnel_ip": "None",
                    "public_ip": public_ip,
                    "branch_location": reg_data["branch_location"]
                    }
            # Convert the Python dictionary to a JSON string
            json_data = json.dumps(collect)        
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            # Make the POST request
            response = requests.post(url+"login", data=json_data, headers=headers)
            # Check the response
            if response.status_code == 200:                        
                print("POST request successful!")
                json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                json_response = json.loads(json_response)
                reg_data["registration_response"] = json_response["message"]
                reg_data["expiry_date"] = json_response["expiry_date"]
                reg_data["tunnel_ip"] = "None"
                reg_data["public_ip"] = public_ip            
                with open("/etc/reach/register_info.json", "w")as f:
                    json.dump(reg_data, f)
                    f.close()
                if reg_data["registration_response"] == "Successfully Registered" or  reg_data["registration_response"] == "This device is already Registered":
                    # Convert date string to date object
                    date_object = datetime.strptime(reg_data["expiry_date"], "%Y-%m-%d").date()
                    # Get today's date
                    today_date = date.today()
                    # Compare date_object with today's date
                    if date_object > today_date:
                        os.system("wget https://assets.cloudetel.com/cloudeteldev/reach_wan/reachedge.sh")
                        os.system("chmod +x reachedge.sh")
                        os.system("./reachedge.sh")
                        os.system("systemctl enable reachwan")
                        os.system("systemctl start reachwan")
                        if (get_interface_details()):                            
                            return "success"
                            
                        else:                            
                            return "Error in configuration"               
                    else:                        
                        return "Error your subscription expired"
                else:                    
                    return "Error: Registered"
            else:                
                return "Error not Reachable"
def wan_post(form1):
    try:
            # Process form data
            protocol = form1.cleaned_data['protocol']
            print(protocol)
            if protocol == "DHCP":
                intfc_info = vpp_int_details()
                for intfc in intfc_info:
                    if intfc['int_name'] == "GigabitEthernet0/3/0":
                        if 'int_ipv4_address' in intfc: 
                            os.system(f"sudo vppctl set int ip addr del GigabitEthernet0/3/0 {intfc['int_ipv4_address']}")
                            os.system("sudo vppctl set dhcp client intfc GigabitEthernet0/3/0")                        
                            with open("/etc/vpp/backup.vpp", "r")as f:
                                data_backup = f.read()
                                f.close()
                            with open("/etc/vpp/bootstrap.vpp", "r")as f:
                                data_boot = f.read()
                                f.close()
                            data_backup = data_backup.replace(f"set int ip address {intfc['int_name']} {intfc['int_ipv4_address']}", f"set dhcp client intfc {intfc['int_name']}")
                            data_boot = data_boot.replace(f"set int ip address {intfc['int_name']} {intfc['int_ipv4_address']}", f"set dhcp client intfc {intfc['int_name']}")
                            if 'gateway' in intfc:
                                data_backup = data_backup.replace(f"ip route add 0.0.0.0/0 via {intfc['gateway']} ", f" ")
                                data_boot = data_boot.replace(f"ip route add 0.0.0.0/0 via {intfc['gateway']} ", f" ")                                                
                            with open("/etc/vpp/bootstrap.vpp", "w")as f:
                                f.write(data_boot)
                                f.close()   
                            with open("/etc/vpp/backup.vpp", "w")as f:
                                f.write(data_backup)
                                f.close()                            
                        else:
                            os.system("sudo vppctl set dhcp client intfc GigabitEthernet0/3/0")    
                            with open("/etc/vpp/backup.vpp", "a")as f:
                                f.write("set dhcp client intfc GigabitEthernet0/3/0")
                                f.close()
                            with open("/etc/vpp/bootstrap.vpp", "a")as f:
                                f.write("set dhcp client intfc GigabitEthernet0/3/0")
                                f.close()                                            
                        response = {"message":"IPAddress changed successfully"}
                        countdown_timer(30)
                        gateway_new = get_default_route_info()
                        if gateway_new != None:
                            with open("/etc/frr/frr.conf", "a")as f:
                                f.write(f"\n!ip route 0.0.0.0/0 {gateway_new}\n!\n")
                                f.close()                                                       
                            os.system("sudo service frr restart")
                            os.system("sudo systemctl restart openvpn@client") 
                        return 'success'               
            ip_addr = form1.cleaned_data['ip_address']
            netmask = form1.cleaned_data['netmask']
            gateway = form1.cleaned_data['gateway'] 
            pri_dns = form1.cleaned_data['primary_dns']
            sec_dns = form1.cleaned_data['secondary_dns']
            pre_len = IPAddress(netmask).netmask_bits()
            ip_address = str(ip_addr) + "/" + str(pre_len)
            intfc_info = vpp_int_details()
            for intfc in intfc_info:
                if intfc['int_name'] == "GigabitEthernet0/3/0": 
                    print(intfc)
                    try:
                        vpp.connect("test-client")
                    except IOError as e:
                        print("An IOError occured:",e)
                        vpp.disconnect()
                        vpp.connect("test-client")                            
                    vpp.api.sw_interface_add_del_address(  sw_if_index=intfc["int_index"],
                                                            is_add=0,
                                                            prefix=intfc["int_ipv4_address"]
                                                        )
                    retvalue = vpp.api.sw_interface_add_del_address(   sw_if_index=intfc["int_index"],
                                                                        is_add=1,
                                                                        prefix=ip_address
                                                                    )
                    if retvalue.retval == 0:  
                        intfc_details = vpp.api.sw_interface_dump( sw_if_index=int(intfc["int_index"]))
                        vpp.disconnect()                                
                                #IP address have to change accordingly in backup configuration. 
                        with open("/etc/vpp/backup.vpp", "r")as f:
                            data_backup = f.read()
                            f.close()
                        with open("/etc/vpp/bootstrap.vpp", "r")as f:
                            data_boot = f.read()
                            f.close()
                        data_backup = data_backup.replace(f"set int ip address {intfc_details[0].interface_name} {intfc['int_ipv4_address']}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        data_backup = data_backup.replace(f"set dhcp client intfc {intfc_details[0].interface_name}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        data_boot = data_boot.replace(f"set int ip address {intfc_details[0].interface_name} {intfc['int_ipv4_address']}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        data_boot = data_boot.replace(f"set dhcp client intfc {intfc_details[0].interface_name}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        if 'gateway' in intfc:
                            data_boot = data_boot.replace(f"ip route add 0.0.0.0/0 via {intfc['gateway']}", f"ip route add 0.0.0.0/0 via {gateway}")
                            data_backup = data_backup.replace(f"ip route add 0.0.0.0/0 via {intfc['gateway']}", f"ip route add 0.0.0.0/0 via {gateway}")
                        with open("/etc/vpp/backup.vpp", "w")as f:
                            f.write(data_backup)
                            f.close()    
                        with open("/etc/vpp/bootstrap.vpp", "w")as f:
                            f.write(data_boot)
                            f.close()    
                        response = {"message":"IPAddress changed successfully"}         
                        with open("/etc/frr/frr.conf", "a")as f:
                            f.write(f"\n!ip route 0.0.0.0/0 {gateway}\n!\n")
                            f.close()                               
                        os.system("sudo service frr restart")
                        os.system("sudo systemctl restart openvpn@client") 
                        return 'success'
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"\nnameserver {pri_dns}\nnameserver {sec_dns}\n") 
                f.close()
                # Redirect or render a success page
            return 'error'
    except Exception as e:
        print(e)
        return "error"
    
def lan_post(form2):
    try:                                 
            ip_addr = form2.cleaned_data['ip_address_lan']
            netmask = form2.cleaned_data['netmask_lan']
            pre_len = IPAddress(netmask).netmask_bits()
            ip_address = str(ip_addr) + "/" + str(pre_len)
            intfc_info = vpp_int_details()
            for intfc in intfc_info:
                if intfc['int_name'] == "GigabitEthernet0/8/0": 
                    try:
                        vpp.connect("test-client")
                    except IOError as e:
                        print("An IOError occured:",e)
                        vpp.disconnect()
                        vpp.connect("test-client")                            
                    vpp.api.sw_interface_add_del_address(  sw_if_index=intfc["int_index"],
                                                            is_add=0,
                                                            prefix=intfc["int_ipv4_address"]
                                                        )
                    retvalue = vpp.api.sw_interface_add_del_address(    sw_if_index=intfc["int_index"],
                                                                        is_add=1,
                                                                        prefix=ip_address
                                                                    )
                    if retvalue.retval == 0:  
                        intfc_details = vpp.api.sw_interface_dump( sw_if_index=int(intfc["int_index"]))
                        vpp.disconnect()                                
                        #IP address have to change accordingly in backup configuration. 
                        with open("/etc/vpp/backup.vpp", "r")as f:
                            data_backup = f.read()
                            f.close()
                        with open("/etc/vpp/bootstrap.vpp", "r")as f:
                            data_boot = f.read()
                            f.close()
                        data_backup = data_backup.replace(f"set int ip address {intfc_details[0].interface_name} {intfc['int_ipv4_address']}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        data_boot = data_boot.replace(f"set int ip address {intfc_details[0].interface_name} {intfc['int_ipv4_address']}", f"set int ip address {intfc_details[0].interface_name} {ip_address}")
                        with open("/etc/vpp/backup.vpp", "w")as f:
                            f.write(data_backup)
                            f.close()    
                        with open("/etc/vpp/bootstrap.vpp", "w")as f:
                            f.write(data_boot)
                            f.close()                                             
            lan_address = calculate_subnet_id(ip_addr, netmask)
            ip_addresses = get_ip_addresses(ip_addr, netmask)  
            dhcp_start_address = ip_addresses[0]
            dhcp_end_address = ip_addresses[len(ip_addresses)-1]                             
            domain_name = "8.8.8.8"
            optional_dns = "8.8.4.4"
            bracket = "{"
            closebracket ="}"
            #Configure dhcpd.conf file
            with open("/etc/dhcp/dhcpd.conf", "w") as f:
                f.write(f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet {lan_address} netmask {netmask} {bracket} \n range {dhcp_start_address} {dhcp_end_address}; \n option routers {ip_addr}; \n option subnet-mask {netmask}; \n option domain-name-servers {domain_name}, {optional_dns}; \n{closebracket}")
                f.close() 
            os.system("systemctl restart isc-dhcp-server")
            return 'success'
    except Exception as e:
        return 'error'

@login_required
def dashboard(request):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            data_json = json.load(f)
            f.close()           
        if "expiry_date" in data_json:
            # Parse the expiry date string (format: YYYY-MM-DD)
            expiry_date = datetime.strptime(data_json["expiry_date"], "%Y-%m-%d").date()

            # Get the current date
            current_date = datetime.today().date()

            # Compare dates
            if current_date < expiry_date:
                        status = "false"
            else:
                status = "true"
        else:
            status = "true"
    else:
        status = "true"   

    print("status..:", status)
    with open("/etc/resolv.conf", "r") as f:
        dns_info = f.read()
        f.close()
    dns_info = subprocess.check_output(["awk", "/nameserver/ {print $2}", "/etc/resolv.conf"]).decode()
    primary_dns = dns_info.split("\n")[1]
    sec_dns = dns_info.split("\n")[2]
    get_vpp_interface_info()
    initial_wan_data = {}
    wan_intfc_info = coll_vpp_interface_details.find_one({"interface_name":"Reach_int1"})
    gateway_def = wan_intfc_info.get("gateway", "")
    if gateway_def == '':
        gateway_def = get_default_route_info()
        if gateway_def != None:
            with open("/etc/frr/frr.conf", "a")as f:
                f.write(f"\n!\nip route 0.0.0.0/0 {gateway_def}\n!\n")
                f.close()
            os.system("systemctl restart frr")            
    if wan_intfc_info is not None:
        initial_wan_data = {"ip_address": wan_intfc_info.get("IPv4address_noprefix", ""),
                                "netmask":wan_intfc_info.get("netmask", ""),
                                "gateway":gateway_def,
                                "primary_dns": primary_dns,
                                "secondary_dns":sec_dns,
                                "protocol":wan_intfc_info.get("protocol", "")
                                }   
    form = NetworkSettingsForm(initial = initial_wan_data)    
    return render(request, 'dashetel.html', {'form': form, 'status':status})   
@login_required
def contact(request, tab_name):
    if request.method == 'POST':

        if tab_name == 'register':
            form = ContactForm(request.POST)  # Handle form submission
            if form.is_valid():
                status = register_post(form)                
                return JsonResponse({'status': status, 'message': 'Registered successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'configurewan':
            form = NetworkSettingsForm(request.POST)  # Handle form submission
            if form.is_valid():
                print("hi")
                status = wan_post(form)                
                return JsonResponse({'status': status, 'message': 'WAN settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'configurelan':
            form = LANSettingsForm(request.POST)  # Handle form submission
            if form.is_valid():
                status = lan_post(form)                
                return JsonResponse({'status': status, 'message': 'LAN settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'timezone':
            form = TimeZoneForm(request.POST)  # Handle form submission
            if form.is_valid():
                selected_time_zone = form.cleaned_data['time_zone']
                os.system(f"timedatectl set-timezone {selected_time_zone}")
                os.system("systemctl restart reachwan.service")
                os.system("systemctl restart reachedge.service")                  
                return JsonResponse({'status': 'success', 'message': 'Time Zone settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
        if tab_name == 'changepassword':
            form = ChangePassword(request.POST)  # Handle form submission
            if form.is_valid():
                new_password = form5.cleaned_data['new_password']
                status = change_password('etel', new_password)
                if status:               
                    return JsonResponse({'status': status, 'message': 'Time Zone settings updated successfully.'})
                else:
                    return JsonResponse({'status': 'error', 'errors': form.errors})
            else:
                    return JsonResponse({'status': 'error', 'errors': form.errors})        

        logfile_content = ["ReachEdge is not configured yet"]
        if os.path.exists("/var/log/reachwan.log"):
            with open("/var/log/reachwan.log", "r") as file:
                logfile_content = file.readlines()
                file.close()   
        form = ContactForm(request.POST)
        form1 = NetworkSettingsForm(request.POST)
        form2 = LANSettingsForm(request.POST)
        form3 = OptionalAdapterSettingsForm(request.POST)
        form4 = TimeZoneForm(request.POST)
        form5 = ChangePassword(request.POST)
                      
    else:  
        if tab_name == 'register':        
            initial_reg_data = {"status": "Register your device with ReachManage",
                                "name" : " ",
                                "Registered_mail": " ",
                                "password": " ",
                                "branch_location": " "                                    
                                }
            reg_status = False
            form = ContactForm(initial = initial_reg_data) 
            return render(request, 'register.html', {'form': form})   
        elif tab_name == 'configurewan':
            with open("/etc/resolv.conf", "r") as f:
                dns_info = f.read()
                f.close()
            dns_info = subprocess.check_output(["awk", "/nameserver/ {print $2}", "/etc/resolv.conf"]).decode()
            primary_dns = dns_info.split("\n")[1]
            sec_dns = dns_info.split("\n")[2]
            get_vpp_interface_info()
            initial_wan_data = {}
            wan_intfc_info = coll_vpp_interface_details.find_one({"interface_name":"Reach_int1"})
            gateway_def = wan_intfc_info.get("gateway", "")
            if gateway_def == '':
                gateway_def = get_default_route_info()
                if gateway_def != None:
                    with open("/etc/frr/frr.conf", "a")as f:
                        f.write(f"\n!\nip route 0.0.0.0/0 {gateway_def}\n!\n")
                        f.close()
                    os.system("systemctl restart frr")            
            if wan_intfc_info is not None:
                initial_wan_data = {"ip_address": wan_intfc_info.get("IPv4address_noprefix", ""),
                                "netmask":wan_intfc_info.get("netmask", ""),
                                "gateway":gateway_def,
                                "primary_dns": primary_dns,
                                "secondary_dns":sec_dns,
                                "protocol":wan_intfc_info.get("protocol", "")
                                }   
            form = NetworkSettingsForm(initial = initial_wan_data)
            return render(request, 'configurewan.html', {'form': form})     
        elif tab_name == 'configurelan':
            lan_intfc_info = coll_vpp_interface_details.find_one({"interface_name":"Reach_int2"})
            initial_lan_data = {}
            if lan_intfc_info is not None:
                initial_lan_data = {"ip_address_lan": lan_intfc_info.get("IPv4address_noprefix", ""),
                                "netmask_lan":lan_intfc_info["netmask"]                       
                                } 
            form = LANSettingsForm(initial = initial_lan_data)
            return render(request, 'configurelan.html', {'form': form})     
        elif tab_name == 'log':         
            logfile_content = ["ReachEdge is not configured yet"]
            if os.path.exists("/var/log/reachwan.log"):
                with open("/var/log/reachwan.log", "r") as file:
                    logfile_content = file.readlines()
                    file.close() 
            logfile_content.reverse()  
            return render(request, 'log.html', {'logfile_content':logfile_content})     
        elif tab_name == 'timezone':      
            with open("/etc/timezone", "r") as f:
                time_data1 = f.read()
                f.close()
            time_data = {"current_time_zone":time_data1}
            form = TimeZoneForm(initial = time_data)  
            return render(request, 'timezone.html', {'form': form})   
        elif tab_name == 'diagnostics':        
            form1 = ChangePassword()     
            form2 = PingForm()   
            return render(request, 'diagnostics.html', {'form1': form1, 'form2':form2}) 
           
        elif tab_name == 'routingtable':           
            routing_table = get_routing_table()            
            return render(request, 'routingtable.html', {'routing_table':routing_table})
        

def ping(request):
    if request.method == 'POST':
        host_ip = request.POST.get('host_ip', None)
        if host_ip:            
            # Perform ping operation
            result = subprocess.run(['ping', '-c', '4', host_ip], capture_output=True, text=True)
            print(result)
            return HttpResponse(result.stdout, content_type='text/plain')
    return HttpResponse(status=400)

def traceroute(request):
    if request.method == 'POST':
        form7 = TraceRouteForm(request.POST)
        if form7.is_valid():
            host = form7.cleaned_data['trace_host']
            # Perform ping operation
            result1 = subprocess.run(['traceroute', '-d', host], capture_output=True, text=True)
            return HttpResponse(result1.stdout, content_type='text/plain')
    return HttpResponse(status=400)

def poweroff(request):
    os.system("init 0") 
    #print("hi")
    return HttpResponse("System shutting down...")

def restart(request):
    os.system("init 6") 
    #print("hi")       
    return HttpResponse("System restarting...")

def download_logfile(request):
    logfile_content = " "
    if os.path.exists("/var/log/reachwan.log"):
        # Read the contents of the logfile
        with open('/var/log/reachwan.log', 'r') as file:
            logfile_content = file.read()
            file.close()
    # Create an HTTP response with the logfile content as a downloadable file
    response = HttpResponse(logfile_content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="reachwan.log"'
    return response

def download_conf(request):
    conffile_content = ''
    if os.path.exists("/etc/vpp/bootstrap.vpp"):
        with open("/etc/vpp/bootstrap.vpp", "r") as f:
            conffile_content = f.read()
            f.close()
    response = HttpResponse(conffile_content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="conf.vpp"'
    return response
