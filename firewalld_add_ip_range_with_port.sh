#!/bin/bash

while read IP
do
	        #echo $IP
		                /usr/bin/firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address=$IP port port="555" protocol=tcp accept"
			done < $1
