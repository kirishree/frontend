import os
import psutil
import yaml
def reach_interface_info():
    try:
        reach_intfc_info = []
        interface = psutil.net_if_addrs()        
        for intfc_name in interface:
            if intfc_name != 'lo':
                colect = {"ubuntu_interface_name":intfc_name}
                addresses = interface[intfc_name]
                for address in addresses: 
                    if address.family == 17:
                        colect.update({
                                        "mac_address":str(address.address)
                                    })         
                reach_intfc_info.append(colect) 
        return reach_intfc_info       
    except Exception as e:
        return False

def get_interface_details():  
    interface = psutil.net_if_addrs()  
    for intfc_name in interface:
        if intfc_name == "eth0":
            return True
    return False
   
def main():
    int_info = reach_interface_info()
    with open("/etc/netplan/00-installer-config.yaml", "r") as f:
        network_config = yaml.safe_load(f)
        f.close()
    no_of_interface = len(int_info)
    if no_of_interface == 3:
        network_config["network"]["ethernets"]["eth0"]['match']['macaddress'] = int_info[0]["mac_address"]
        network_config["network"]["ethernets"]["eth1"]['match']['macaddress'] = int_info[1]["mac_address"]
        network_config["network"]["ethernets"]["eth2"]['match']['macaddress'] = int_info[2]["mac_address"]
    if no_of_interface == 2:
        network_config["network"]["ethernets"]["eth0"]['match']['macaddress'] = int_info[0]["mac_address"]
        network_config["network"]["ethernets"]["eth1"]['match']['macaddress'] = int_info[1]["mac_address"]
    if no_of_interface < 2:
        print("Minimum two interfaces are required to install ReachLink.")
    with open("/etc/netplan/00-installer-config.yaml", "w") as f:
        yaml.dump(network_config, f, default_flow_style=False)
        f.close()
    os.system("sudo netplan apply")
    if get_interface_details():        
        print("ReachLink configured successfully")   
    else:
        print("Error occured while configuring ReachLink")   


if __name__ == "__main__":
    main()
