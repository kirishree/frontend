import os
import subprocess
import sys
import pymongo
from pymongo.server_api import ServerApi
from pyroute2 import IPRoute
import random
import requests
import socket
import netifaces as ni
import ipaddress
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import logging
logging.basicConfig(filename='/var/log/reachlink.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
smtp_server = "p3plzcpnl506439.prod.phx3.secureserver.net"  # Your SMTP server address
smtp_port = 587  # SMTP server port (587 for TLS, 465 for SSL)
sender_email = 'reachlink@cloudetel.com'  # Your email address
sender_password = 'Etel@123!@#'  # Your email password
subject = 'Reach-link-Update'
Remote_tunnel_ip = "10.200.202.2"
subnet = ""
local_tunnel_ip = ""
location = ""
file_path = "/etc/reach/reachlink_info.json"
with open(file_path, "r") as f:
    data_json = json.load(f)
    f.close()
Remote_ip = data_json["hub_ip"]
mongo_uri = f"mongodb://cloudetel:Cloudetel0108@{Remote_ip}:27017/"
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]


# URL to which you want to send the POST request
url = "http://" + Remote_ip + ":5000/set_ass"


def get_local_public_ip():
    try:
        command = (f"ping -c 5  8.8.8.8")
        subprocess.check_output(command.split())
        ip_service_url = "https://api64.ipify.org?format=json"
        response = requests.get(ip_service_url)
        Local_public_ip = response.json()["ip"]
        return Local_public_ip
    except Exception as e:
        logging.error(f"Error while getting public IP: {str(e)}")
        return False

#Get the default gateway
def get_default_gateway():
    try:
        return ni.gateways()['default'][ni.AF_INET][0]
    except (KeyError, IndexError):
        return None
	
#Function to test the tunnel is connected active
def check_tunnel_connection():
    try:    
        
        command = (f"ping -c 10  {Remote_tunnel_ip}")
        output = subprocess.check_output(command.split()).decode()
        dft_gw = get_default_gateway()
        if dft_gw != "10.200.201.1" :
            os.system("sudo ip route replace default via 10.200.201.1")    
        return True      
    except subprocess.CalledProcessError:
        logging.error("Reachlink status: InActive")
        return False
        
def check_new_tunnel_connection():
    try:    
        
        logging.info("Waiting for Spoke linking with HUB")
        command = (f"ping -c 5  {Remote_tunnel_ip}")
        output = subprocess.check_output(command.split()).decode()              
        logging.info("Spoke Linked Successfully")
        return True      
    except subprocess.CalledProcessError:
        return check_new_tunnel_connection()
        
def post_mail(collect):
      
    json_data = json.dumps(collect, indent=4)
    receiver_email = "reachlink@cloudetel.com"  # Recipient's email address
    subject = 'Reach-link device public IP changed'
    body = f'Info from edge device.\nThis device public IP is changed.\n So please change the configuration in router and make this connection active.\n{json_data}'
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Use TLS encryption
        server.login(sender_email, sender_password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)        
        logging.info("Email sent successfully!")
    except Exception as e:       
        logging.error(f"An error occurred while sending Email: {str(e)}")
    finally:
        server.quit()  # Close the connection to the server
    
def run_command(command):
  try:
    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    return True    
  except subprocess.CalledProcessError as e:
    logging.error(f"Error occured while executing {command}: {str(e)}")
    return False
  
     
#Generation of tunnel IP
def tunnel_ip_generation():
    random_no = random.randint(2,128)
    tunnel_ip = "10.200.202." + str(random_no) + "/24"
    for tun_ip in coll_tunnel_ip.find({},{"_id":0}):
        if tunnel_ip == tun_ip["tunnel_ip"]:
            return tunnel_ip_generation()
    return tunnel_ip

def get_system_uuid():
    try:
        # Read the product_uuid file to get the system UUID
        with open('/sys/class/dmi/id/product_uuid', 'r') as file:
            uuid = file.read().strip()
        return uuid
    except Exception as e:        
        return None
#Function to get tunnel IP from cloud database
def get_tunnel_ip(Local_public_ip):
    tunnel_ip = "0.0.0.0"
    subnet = []
    sys_uuid = get_system_uuid()
    for info in coll_tunnel_ip.find({},{'_id':0}):
        if info["uuid"] == sys_uuid:
            tunnel_ip = info["tunnel_ip"]
            subnet = info["subnet"]
    coll_tunnel_ip.delete_many({"public_ip": Local_public_ip})
    
    if tunnel_ip == "0.0.0.0":  
        tunnel_ip = tunnel_ip_generation()
    with open(file_path, "r") as f:
        data_json = json.load(f)
        f.close()
    if len(subnet) == 0:
        subnet = data_json["subnet"]
    system_uuid = get_system_uuid()
    coll_tunnel_ip.insert_one({"public_ip": Local_public_ip, 
                               "tunnel_ip": tunnel_ip,
                               "branch_location": data_json["location"],
                               "subnet": subnet,
                               "vrf":"vrf1",                                                             
                               "uuid": system_uuid
                              })    
    collect = {"public_ip": Local_public_ip, 
               "tunnel_ip": tunnel_ip,
               "branch_location": data_json["location"],
               "subnet": subnet,
               "uuid": system_uuid
                }
    # Convert the Python dictionary to a JSON string
    json_data = json.dumps(collect)
    # Set the headers to indicate that you are sending JSON data
    headers = {"Content-Type": "application/json"}

    # Make the POST request
    response = requests.post(url, data=json_data, headers=headers)
    # Check the response
    if response.status_code == 200:       
        logging.info("POST request successful!")    
        
    else:        
        logging.error(f"POST request failed with status code {response.status_code}")
        
    post_mail(collect)            
    return tunnel_ip

def create_tunnel(Local_tunnel_ip):
    command = f"sudo ip tunnel add Reach_link1 mode gre local any remote {Remote_ip} ttl 255"
    status = run_command(command)
    command = f"sudo ip link set up dev Reach_link1"
    status = run_command(command)
    command = f"sudo ip link set mtu 1450 dev Reach_link1"
    status = run_command(command)
    command = f"sudo ip addr add {Local_tunnel_ip} dev Reach_link1"
    status = run_command(command)
    return status    

def create_setup():   
    
    command = "sudo ufw allow 1723"
    status = run_command(command)   
    command = "sudo ufw allow 47"
    status = run_command(command)
    Local_public_ip = get_local_public_ip()
    if Local_public_ip != False:    
        with open(file_path, "r") as f:
            data_json = json.load(f)
            f.close()
        data_json['old_public_ip'] = Local_public_ip
        logging.info("old_public_ip is updated in reachlinkinfo")            
        Local_tunnel_ip = get_tunnel_ip(Local_public_ip)    
        default_gateway = get_default_gateway()
        data_json['default_gateway'] = default_gateway
        logging.info("default_gateway is updated in reachlinkinfo")
        with open(file_path, "w") as f:
            json.dump(data_json, f)
            f.close()    
        tunnel_created = create_tunnel(Local_tunnel_ip)
        if tunnel_created:            
            logging.info("Spoke side configuration completed")
            logging.info("Wait until it links with HUB")        
            tunnel_status = check_new_tunnel_connection()
            if tunnel_status:
                Remote_ip_sub = Remote_ip + "/32"
                command = f"sudo ip route replace {Remote_ip_sub} via {default_gateway}"
                status = run_command(command)                
                command = f"sudo ip route replace 0.0.0.0/0 via {Remote_tunnel_ip}"
                status = run_command(command)               
        else:
            logging.error("Error in tunnel creation")
    else:
        logging.error("Pl check your internet connection")


def main():
    while(1):
        tunnel_created = False
        command = 'sudo ip tunnel show'
        output = subprocess.check_output(command.split()).decode()
        out = output.split("\n")
        for x in out:
            y = x.split(" ")            
            if y[0] == "Reach_link1:":
                tunnel_created = True                
        if tunnel_created == False:            
            logging.info("Start to create tunnel")
            create_setup()
        status = check_tunnel_connection()
        if status == False:
            with open(file_path, "r") as f:
                data_json = json.load(f)
                f.close()
            logging.info("Reachlink tunnel is not reachable, so it starts to reconnect")            
            default_gateway = data_json['default_gateway']            
            command = f"sudo ip route replace 0.0.0.0/0 via {default_gateway}"
            status = run_command(command)                 
            New_public_ip = get_local_public_ip()
            if New_public_ip != False:
                data_json['new_public_ip'] = New_public_ip
                Last_public_IP = data_json['old_public_ip']
                if  New_public_ip != Last_public_IP:
                    data_json['old_public_ip'] = New_public_ip
                    logging.info("Public IP changed so tunnel disconnected")
                with open(file_path, "w") as f:
                    json.dump(data_json, f)
                    f.close()                  
                for device in coll_tunnel_ip.find({},{'_id':0}):
                    if device["public_ip"] == Last_public_IP:                        
                        tunnel_ip = device["tunnel_ip"]
                        branch_location = device["branch_location"]
                        subnet = device["subnet"]
                system_uuid = get_system_uuid()                
                coll_tunnel_ip.delete_many({"public_ip": Last_public_IP})
                coll_tunnel_ip.insert_one({"public_ip": New_public_ip,
                                            "tunnel_ip": tunnel_ip,
                                            "branch_location": branch_location,
                                            "subnet": subnet,
                                            "vrf":"vrf1",
                                            "uuid":system_uuid
                                            })
                		 
                collect = [{"new_public_ip": New_public_ip, 
                            "last_public_ip": Last_public_IP,
                            "tunnel_ip": tunnel_ip,
                            "branch_location": branch_location,
                            "subnet": subnet,
                            "uuid":system_uuid
                            }]
                collect_post = {"public_ip": New_public_ip, 
                                "tunnel_ip": tunnel_ip,
                                "branch_location": branch_location,
                                "subnet": subnet,
                                "uuid":system_uuid
                                }                
                # Convert the Python dictionary to a JSON string
                json_data = json.dumps(collect_post)
                # Set the headers to indicate that you are sending JSON data
                headers = {"Content-Type": "application/json"}
                # Make the POST request
                response = requests.post(url, data=json_data, headers=headers)
                # Check the response
                if response.status_code == 200:                    
                    logging.info("It sent updated public IP to HUB")        
                else:                    
                    logging.error(f"POST request failed with status code {response.status_code}")
                post_mail(collect)
                status_new = check_new_tunnel_connection()
                if status_new:
                    logging.info("Reachlink status: Active")
                    Remote_ip_sub = Remote_ip + "/32"
                    command = f"sudo ip route replace {Remote_ip_sub} via {default_gateway}"                   
                    status = run_command(command)
                    command = f"sudo ip route replace 0.0.0.0/0 via {Remote_tunnel_ip}"
                    status = run_command(command)
                    
            else:
                logging.error("Pl check your internet connection")
                
        time.sleep(30)
	
if __name__ == "__main__":
    main()
