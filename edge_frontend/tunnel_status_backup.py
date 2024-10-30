import subprocess
import pymongo
import time
import json
import threading
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
smtp_server = "p3plzcpnl506439.prod.phx3.secureserver.net"  # Your SMTP server address
smtp_port = 587  # SMTP server port (587 for TLS, 465 for SSL)
sender_email = 'reachmanage@cloudetel.com'  # Your email address
sender_password = 'Etel@123!@#'  # Your email password
subject = 'ReachWAN tunnel down'
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["reachedge_info"]
db_backup = client["reachedge_info_backup"]
col_vxlan_details = db["vxlan_details"]
col_vxlan_status_backup = db_backup["vxlan_status"]
data_tunnel_status = []
from concurrent.futures import ThreadPoolExecutor
tunnel_status = []
tunnel_status_lock = threading.Lock()  # Create a lock for thread-safe operations

#In collection of vxlan_details contain src_address, dst_address & dst_loopaddr_addr
#Get the live details of tunnel using command line command show vxlan tunnel 
#Then comparing Both & By pinging the dst_loopback_addr to find the connected status.

def post_mail(collect):
      
    json_data = json.dumps(collect, indent=4)
    receiver_email = "reachmanage@cloudetel.com"  # Recipient's email address
    subject = 'VXLAN tunnel disconnected'
    body = f'Info from edge device.\nThe below mentioned tunel disconnected.\n{json_data}'
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
        print("Email sent successfully!")
    except Exception as e:       
        print(f"An error occurred while sending Email: {str(e)}")
    finally:
        server.quit()  # Close the connection to the server

def vxlan_details():
      try:
            data_vxlan =[]
            out = subprocess.check_output("sudo vppctl show vxlan tunnel", shell=True).decode()         
            if "No vxlan tunnels configured..." in out:
                  return data_vxlan
            else:
                  out1 = out.split("\n")[:-1]      
                  for x in out1:
                        out2 = x.split()
                        colect = {"src_address":out2[4], "dst_address":out2[6], "mcast_index":"4294967295", "encap_vrf_id":0, "vni":13, "decap_index":1}
                        data_vxlan.append(colect)
      except:
            return data_vxlan
      return data_vxlan

def background_tunnel_status(intfc):
    try:
        global tunnel_status
        try:
            dst = intfc["dst_loopback_addr"].split("/")[0]
            command = (f"ping -c 5  {dst}")
            output = subprocess.check_output(command.split()).decode()
            lines = output.strip().split("\n")
            # Extract the round-trip time from the last line of output
            last_line = lines[-1].strip()
            rtt = last_line.split()[3]
            rtt_avg = rtt.split("/")[1]
            jitter = rtt.split("/")[3]   
            status = "connected"  
        except subprocess.CalledProcessError:
            rtt_avg = -1     
            jitter = -1
            status = "Not connected"
            post_mail({  "src_address":intfc["src_address"],
                                    "dst_address":intfc["dst_address"],
                                    "src_loopback_addr":intfc["src_loopback_addr"], 
                                    "dst_loopback_addr": intfc["dst_loopback_addr"],
                                    "rtt": rtt_avg,                   
                                    "status":status, 
                                    "encrypt":"PSK",
                                    "vni":13,
                                "jitter":jitter
                                })
        with tunnel_status_lock: 
            tunnel_status.append({  "src_address":intfc["src_address"],
                                    "dst_address":intfc["dst_address"],
                                    "src_loopback_addr":intfc["src_loopback_addr"], 
                                    "dst_loopback_addr": intfc["dst_loopback_addr"],
                                    "rtt": rtt_avg,                   
                                    "status":status, 
                                    "encrypt":"PSK",
                                    "vni":13,
                                "jitter":jitter
                                })  
            print(tunnel_status)
    except Exception as e:
         print(f"Error while pinging tunnel end point:{e}")            
	
def get_vxlan_status_backup():
        try: 
            global tunnel_status
            tunnel_status = []  # Reinitialize the global variable here           
            tunnel_details = col_vxlan_details.find({},{'_id':0})
            iface_list = vxlan_details()
            with ThreadPoolExecutor(max_workers=5) as executor:  # Adjust max_workers if needed
                futures = []  # K
                for intfc in tunnel_details:
                    for iface in iface_list:
                        if str(iface["dst_address"]) == intfc["dst_address"] and str(iface["src_address"]) == intfc["src_address"]:
                            future = executor.submit(background_tunnel_status, intfc)
                            futures.append(future)
                # Wait for all threads to complete
                for future in futures:
                    print(future)
                    future.result()  # This will block until the background task is complete                                 
        except Exception as e:
            print(f"Error in getting tunnel status:{e}") 
        with open("/etc/reach/reachwan/tunnel_status.json", "w") as f:
            json.dump(tunnel_status, f)
            f.close()
        print("updated the tunnel status")


def main():
    while True:
        get_vxlan_status_backup()
        time.sleep(120)

if __name__ == "__main__":
    main()
