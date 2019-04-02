<?php
$ips = array(
        "82.80.26.205",
        "82.166.147.240",
        "1.2.3.4",
        "31.168.157.171",
        "5.100.248.236", // itzik
        "192.116.49.35", // itzik
        );
if(!in_array($_SERVER['REMOTE_ADDR'],$ips))
die();
