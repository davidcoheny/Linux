#!/bin/bash                                                                                                           
count=`cat /var/log/httpd/error_log | grep -c "found"`                                                                
                                                                                                                      
if [ $count -ge 9 ]                                                                                                   
then                                                                                                                  
 for i in $(cat /var/log/httpd/error_log | grep "found" | awk -F " " '{print $11}' | awk -F ":" '{print $1}' | uniq)  
 do                                                                                                                   
         firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address="$i" drop"                       
#        echo "Drop IP $i" >> /tmp/drop.log                                                                           
 done                                                                                                                 
                                                                                                                      
 firewall-cmd --reload                                                                                                
                                                                                                                      
 echo "" > /var/log/httpd/error_log                                                                                   
fi                                                                                                                    
