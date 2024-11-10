<?php
function dn_server_01(){
    $host = "localhost";
    $user = "root";
    $password = "";
    $database = "dn_service.api";

    $connection = mysqli_connect($host, $user, $password, $database);
    if (!$connection) {
        $message = ['status' => 'connectionFailed', 'message' => 'Cannot connect to Network', 'error' => mysqli_connect_error()];
        return $message;
    } else {
        mysqli_set_charset($connection, "utf8");
        return $connection;
    }
}

function dn_server_02(){
    $host = "localhost";
    $user = "root";
    $password = "";
    $database = "dn_server_02";

    $connection2 = mysqli_connect($host, $user, $password, $database);
    if (!$connection2) {
        $message = ['status' => 'connectionFailed', 'message' => 'Cannot connect to Network', 'error' => mysqli_connect_error()];
        return $message;
    } else {
        mysqli_set_charset($connection2, "utf8");
        return $connection2;
    }
}