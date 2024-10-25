#!/bin/bash
original_dir=$(pwd)
echo "Start to install Dependencies"
sudo apt update
sudo apt install -y net-tools python3-dev python3-pip iproute2 netplan.io isc-dhcp-server
pip install pymongo psutil netaddr pyroute2 django python-decouple gunicorn pytz
ufw allow 5000 500 4789/udp 89 53 22 67/udp 179/tcp
working_DIR="/etc/reach"
if [ -d "$working_DIR" ]; then
    echo "Directory $DIR exists."
else:
    echo "Creating Working Directory"
    mkdir -p /etc/reach
    if [ $? -eq 0 ]; then
        echo "Directory $working_DIR created successfully."
    else
        echo "Failed to create directory $working_DIR."
        cd "$original_dir" || exit 
    fi
fi
echo "Copying Reachlink directoy"
cp -r reach/ /etc/reach/
mv /etc/reach/reach.service /etc/systemd/system/
cp -r frontend/linkgui /etc/reach/
cp -r backend/linkbe /etc/reach/
cp dhcp_conf/dhcpd.conf /etc/dhcp/
cp dhcp_conf/interfaces /etc/network/
cp frontend/linkgui.service /etc/systemd/system/
cd /etc/reach/linkgui
python3 manage.py migrate
cp backend/linkbe.service /etc/systemd/system/
cd /etc/reach/linkbe
python3 manage.py migrate

cd "$original_dir"
sudo systemctl daemon-reload
sudo systemctl enable linkgui
sudo systemctl start linkgui
sudo systemctl enable reach
sudo systemctl start reach
echo "Configuring logrotate"
cp logrotate_config/reachlink /etc/logrotate.d/reachlink
chmod 700 /var/log/
logrotate -f /etc/logrotate.d/reachlink
echo "Configuring Grub"
cp -r grub_config/themes /usr/share/grub/
cp grub_config/grub /etc/default/
sudo update-grub
echo "Configuring Plymouth"
cp -r plymouth_config/plymouth /usr/share/
sudo update-initramfs -u
cp init/change_password.sh /etc/init.d/change_password.sh
chmod +x /etc/init.d/change_password.sh
chmod +x /etc/reach/link_info.py
chmod +x /etc/reach/mac_update.py
echo "/etc/init.d/change_password.sh" >> /home/etel/.bashrc
echo "python3 /etc/reach/link_info.py" >> /home/etel/.bashrc
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
echo "Disabling unattended upgrades"
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
systemctl restart unattended-upgrades
echo "Configuring Time Zone"
timedatectl set-timezone Asia/Riyadh
echo "Configuring Netplan"
cp netplan/*.yaml /etc/netplan/
echo "Installing Reachlink service"
cd reachlink
cp reachlink.py /etc/reach/
cp reachlink.service /etc/systemd/system/
echo "Restarting..."
init 6
cd "$original_dir" || exit