#!/usr/bin/python3
import netifaces
import psutil
import time


def countdown_timer(seconds):
    for remaining in range(seconds, 0, -1):
        minutes, secs = divmod(remaining, 60)
        timer = '{:02d}:{:02d}'.format(minutes, secs)
        print(f"Time left: {timer}", end='\r')
        time.sleep(1)    

def get_interface_details():  
    interface = psutil.net_if_addrs()  
    for intfc_name in interface:
        if intfc_name == "eth0":
            return True        
    print("Initializing ReachLink pl wait. Don't Restart or Power OFF the VM ")
    countdown_timer(60)
    return get_interface_details()

def get_interface_addresses():
    addresses = {}
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        iface_details = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in iface_details:
            ipv4_address = iface_details[netifaces.AF_INET][0]['addr']
        else:
            ipv4_address = None        
        addresses[interface] = {'ipv4': ipv4_address}
    return addresses


def network_info():
    print("\nWelcome to ReachLink!\n")
    print("***********************************************************")    
    get_interface_details()
    interface_addresses = get_interface_addresses()    
    print("ReachLink Local Web Interface is enabled on all interfaces.")
    print("It can be accessed using any of your device IP & port 5005.")
    print("If not registered pl Register your device with ReachLink HUB.")
    print("Access ReachLink User Interface with the following URL:\n") 
    for interface, address_info in interface_addresses.items():
        if interface != "lo" and interface != "tun0":                
            print(f'\t"http://{address_info["ipv4"]}:5005/login/"')              
    print("\nUse below credentials for Login.")  
    print("Username: etel")
    print("Password: reachlink")          
    print("***********************************************************")
    


if __name__ == "__main__":
    network_info()
