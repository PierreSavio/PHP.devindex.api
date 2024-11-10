<?php
function dn_server_02(){
    $host = "localhost";
    $user = "root";
    $password = "";
    $database = "dn_server_02";

    $connection2 = mysqli_connect($host, $user, $password, $database);
    if (!$connection2) {
        return false;
    } else {
        mysqli_set_charset($connection2, "utf8");
        return $connection2;
    }
}
