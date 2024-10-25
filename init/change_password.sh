#!/bin/bash
FLAG_FILE=/var/tmp/password_changed.flag

if [ -f "$FLAG_FILE" ]; then
   exit 0
fi

echo "Welcome to ReachLink. For security purposes, please change the password."
passwd

if [ $? -eq 0 ]; then
   touch $FLAG_FILE
   echo "Password changed successfully"
else
   echo "Failed to change password. Please restart to change the password."
fi

exit 0 
