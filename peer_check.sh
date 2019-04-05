#!/bin/bash

## This script will run bash commands (on RHEL 7 and Centos 7) according to "Virtual Machine Checklist" and dispaly them in coloer
## each number corresponds to the number on the XLS sheet 

## To use the scrip run in a bash sheel USER@SERVER "bash -s" < script 

## This scrip will run as root
sudo -i

## Number 12 on the sheet - Compute & Storage Allocated (CPU/Memory/Storage)
echo -e " \e[39m"
PROCESSORS=`cat /proc/cpuinfo | grep processor | wc -l`
MEM=`free -h | grep Mem | awk -F " " '{print $2}'`
DISKSPACE=`df -h| grep /dev/mapper/centos-root | awk -F " " '{print $2}'`
echo -e "#12 \e[32m$PROCESSORS CPU | Memory $MEM | Disk Space $DISKSPACE  "
echo -e " \e[39m"

## Number 16 on the sheet - Virtualization Tools Installed (VMWare Tools)
VM_TOOLS=`rpm -qa | grep open-vm-tools`
if [ -z "$VM_TOOLS" ]; then
       echo -e "#16 \e[31m########################### Vm Tools - NOT Installed!!!  #################################"
echo -e " \e[39m"
else echo -e "#16 \e[32mVm Tools - Installed"       
echo -e " \e[39m"
fi

## Number 17 on the sheet - Virtual Machine Host/Domain Name Configured
HOSTNAME=`hostname`
echo " "
echo -e "#17 \e[32mHostname: $HOSTNAME"
echo -e " \e[39m"
echo " "

## Number 18  on the sheet - Virtual Machine IP Address(es) Configured
## WILL DISPLAY ONLY THE MAIN IP ADDRESS !!
IPADDR=`/usr/sbin/ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}'`
echo -e "#18 \e[32mLocal IP Address: $IPADDR"
PUBLIC_IP=`curl http://icanhazip.com 2> /dev/null`
echo -e "    \e[32mPublic IP Address $PUBLIC_IP"
echo -e " \e[39m"
echo " "

## Number 19 - Local Firewall Configured & #24 - Firewall Rules configured to allow Customer Admin (RDP, SSH, etc)
FIREWALL_SERVICES=`firewall-cmd --list-services`
FIREWALL_PORTS=`firewall-cmd --list-ports`
FIREWALL_RICH_RULES=`firewall-cmd --list-rich-rules`
echo -e "#19,#24 \e[32mFirewalld Rules: $FIREWALL_SERVICES $FIREWALL_PORTS $FIREWALL_RICH_RULES"
echo -e " \e[39m"

## Number 20 - display timezone
TIMEZONE=`timedatectl | grep "Time zone"`
echo -e "#20 \e[32m$TIMEZONE"
echo -e " \e[39m"

##Number 21 - Time Server/NTP Setting/Virtual Machine timesync Configured
NTPD=`systemctl status ntpd | grep Active | awk -F " " '{print $3}' | grep running 2> /dev/null`
CHRONYD=`systemctl status chronyd | grep Active | awk -F " " '{print $3}' | grep running 2> /dev/null`
## check if ntpd is running if not check if chronyd is running## check if ntpd is running if not check if chronyd is running
if [ -z "$NTPD" ] && [ -z "$CHRONYD" ]; then
       echo -e "#21 \e[31mTimesync Configured NOT Running !!!"
echo -e "\e[39m"
else echo -e "#21 \e[32mTimesync Configured and Running"
echo -e "\e[39m"
fi

##Number 22 - Customer user account Account Created & #30 - Local Secura account created
echo -e "#22,#30,#42 \e[32mUsers Accounts:"
awk -F ":" '{print $1,$3}'  /etc/passwd | grep 100* | awk '{print $1}'
echo -e "\e[39m"

#Number 23 - Customer user account added to Administrators/Sudoers/etc, #31 -Local Secura account added to Administrators/sudoers/etc, #42 - Add svc_cwa Automate account as local admin
echo -e "#23,#31 \e[32mGroup $(getent group wheel)"
echo -e "\e[39m"

#Number 40 - Web Protect - ESET
ESET=`pgrep esets`
if [ -z "$ESET" ]; then
       echo -e "#40 \e[31m########################## Eset Is NOT Running!!! ###############################################"
echo -e " \e[39m"
else echo -e "#40 \e[32mEset Is Running"
echo -e " \e[39m"
fi

#Number 41 - Install the Automate Agent
LTECHAGENT=`systemctl status ntpd | grep Active | awk -F " " '{print $3}' | grep running 2> /dev/null`
if [ -z "$LTECHAGENT" ]; then
       echo -e "#41 \e[31mltechagent NOT Running !!!"
echo -e "\e[39m"
else echo -e "#41 \e[32mltechagent Is Running"
echo -e "\e[39m"
fi
