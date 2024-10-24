import ipaddress
import pytz
from django import forms
from pytz import common_timezones
class ContactForm(forms.Form):
    #status = forms.CharField(max_length=100, label="Status", widget=forms.Textarea(attrs={'rows':1, 'style': 'width: 300px;'}))
    Registered_mail = forms.EmailField(label="Registered Mail ID", widget=forms.EmailInput())
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")

class ChangePassword(forms.Form):
    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput())
    confirm_password = forms.CharField(label='Confirm Password', widget=forms.PasswordInput())
    def clean(self):
        cleaned_data_pass = super().clean()
        new_pass = cleaned_data_pass.get('new_password')
        confirm_pass = cleaned_data_pass.get('confirm_password')
        if new_pass != confirm_pass:
            raise forms.ValidationError("Password & Confirm password should match.")        
        return cleaned_data_pass
    
def is_valid_gateway(wan_addr, wan_gateway, wan_netmask):
    try:
        ip1_obj = ipaddress.ip_address(wan_addr)
        ip2_obj = ipaddress.ip_address(wan_gateway)
        network = ipaddress.ip_network(f"{wan_addr}/{wan_netmask}", strict=False)
        return ip1_obj in network and ip2_obj in network
    except ValueError:
        return False

PROTOCOL_CHOICES= [
    ('static', 'Static'),
    ('DHCP', 'DHCP'),    
    ]

class TimeZoneField(forms.ChoiceField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.choices = [(tz, tz) for tz in common_timezones]
PROTO_CHOICES= [
    ('static', 'Static'),
    ('DHCP', 'DHCP'),    
    ]
class NetworkSettingsForm(forms.Form):
    ip_address = forms.GenericIPAddressField(label='IP Address', protocol='both', required=False)
    netmask = forms.GenericIPAddressField(label='Netmask', protocol='both', required=False)
    gateway = forms.GenericIPAddressField(label='Gateway', protocol='both', required=False)
    primary_dns = forms.GenericIPAddressField(label='Primary DNS', protocol='both', required=False)
    secondary_dns = forms.GenericIPAddressField(label='Secondary DNS', protocol='both', required=False)
    protocol = forms.CharField(label='Protocol', widget=forms.Select(choices=PROTOCOL_CHOICES))
    # You can add more fields as needed for additional settings
    def clean(self):
        cleaned_data = super().clean()
        protocol = cleaned_data.get('protocol')
        if protocol == 'static':
            # If protocol is static, all fields are mandatory
            ip_address = cleaned_data.get('ip_address')
            netmask = cleaned_data.get('netmask')
            gateway = cleaned_data.get('gateway')
            primary_dns = cleaned_data.get('primary_dns')
            secondary_dns = cleaned_data.get('secondary_dns')
            # Check if any of the required fields are empty
            if not all([ip_address, netmask, gateway, primary_dns, secondary_dns]):
                raise forms.ValidationError("All fields are required for static protocol.")
            if not is_valid_gateway(ip_address, gateway, netmask):
                raise forms.ValidationError("Invalid gateway address.")
        elif protocol == 'DHCP':
            # If protocol is dhcp, none of the fields are required
            pass
        else:
            raise forms.ValidationError("Invalid protocol selected.")
        return cleaned_data       
    
class LANSettingsForm(forms.Form):
    ip_address_lan = forms.GenericIPAddressField(label='IP Address', protocol='both', required=True)
    netmask_lan = forms.GenericIPAddressField(label='Netmask', protocol='both', required=True)   

class OptionalAdapterSettingsForm(forms.Form):
    ip_address_opt = forms.GenericIPAddressField(label='IP Address', protocol='both', required=False)
    netmask_opt = forms.GenericIPAddressField(label='Netmask', protocol='both', required=False)
    gateway_opt = forms.GenericIPAddressField(label='Gateway', protocol='both', required=False)
    primary_dns_opt = forms.GenericIPAddressField(label='Primary DNS', protocol='both', required=False)
    secondary_dns_opt = forms.GenericIPAddressField(label='Secondary DNS', protocol='both', required=False)
    protocol_opt = forms.CharField(label='Protocol', widget=forms.Select(choices=PROTO_CHOICES))
    # You can add more fields as needed for additional settings
    def clean(self):
        cleaned_data = super().clean()
        protocol_opt = cleaned_data.get('protocol_opt')
        gateway_opt = cleaned_data.get('gateway_opt')
        if protocol_opt == 'static':
            # If protocol is static, all fields are mandatory
            ip_address_opt = cleaned_data.get('ip_address_opt')
            netmask_opt = cleaned_data.get('netmask_opt')                  
            # Check if any of the required fields are empty
            if not all([ip_address_opt, netmask_opt]):
                raise forms.ValidationError("IP address & Netmask are required for static protocol.")
            if gateway_opt != "":      
                if not is_valid_gateway(ip_address_opt, gateway_opt, netmask_opt):
                    raise forms.ValidationError("Invalid gateway address.")
        elif protocol_opt == 'DHCP':
            # If protocol is dhcp, none of the fields are required
            pass
        else:
            raise forms.ValidationError("Invalid protocol selected.")
        return cleaned_data   
      
class TimeZoneForm(forms.Form):
    current_time_zone = forms.CharField(label='Current Time Zone', widget=forms.TextInput())
    time_zone = TimeZoneField(label='Select Time Zone')

class PingForm(forms.Form):
    ping_host = forms.GenericIPAddressField(label='Ping Host', protocol='both', required=True)



class TraceRouteForm(forms.Form):
    trace_host = forms.GenericIPAddressField(label='Trace Host', protocol='both', required=True)
    
