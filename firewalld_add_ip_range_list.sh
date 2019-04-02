#!/bin/bash

while read IP
do
	                #echo $IP
			                               echo  firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address=$IP accept"
							                        done < $1
