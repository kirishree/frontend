import ipaddress
try:
   if ipaddress.ip_network("192.168.23.0/24", strict=False) and ipaddress.ip_address("192.168.2.2"):
      print(True)
except Exception as e:
   print(e)
