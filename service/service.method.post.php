<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

include_once 'network.php';

define('JWT_SECRET_KEY', 'merchant.kalengkangart.my.id_34fj495HsDK348djdDJI4556');

function service_login($email, $password)
{
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }

    try {
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE email_query = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();

        if ($row) {
            if (HASHsha512($password) === $row['password_query']) {
                if($row['account_status'] == 'Deactive'){
                    $account_status = 'Deactive';
                    return $account_status;
                } else {
                    $payload = [
                        'iss' => "http://api.devindex.com",
                        'aud' => "http://api.devindex.com",
                        'iat' => time(),
                        'exp' => time() + 3600,
                        'auth_uid' => $row['auth_uid'],
                        'role' => $row['role_query']
                    ];
                    $jwt = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');
                    return $jwt;
                }
            } else {
                $account_status = 'passwordInvalid';
                return $account_status;
            }
        } else {
            $account_status = 'failedLogin';
            return $account_status;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_addAkun($token, $name, $no_hp, $email, $password, $role){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $token_auth_uid = $decoded->auth_uid;
        $token_role = $decoded->role;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ? AND role_query = ?");
        $stmt->bind_param("ss", $token_auth_uid, $token_role);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        if($row){
            if($row['role_query'] == 'Developer'){
                try{
                    $random_number = rand(10000000, 99999999);
                    $active_status = 'Deactive';

                    $auth_uid = hash('sha512', $random_number . HASHsha512($email) . HASHsha512($password) . HASHsha512($no_hp));
                    $auth_token_query = hash('sha512', $auth_uid . $email . $password . $no_hp);
                    $stmt = $connection->prepare("INSERT INTO auth_key (auth_uid, name_query, email_query, nomor_hp, password_query, auth_token_query, role_query, account_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

                    $hash_password = HASHsha512($password);
                    $stmt->bind_param("ssssssss", $auth_uid, $name, $email, $no_hp, $hash_password, $auth_token_query, $role, $active_status);

                    if ($stmt->execute()) {
                        return true;
                    } else {
                        throw new Exception("Database error: " . $stmt->error);
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
                }
            } else {
                http_response_code(401);
                echo json_encode(['message' => 'Unauthorized']);
                return false;
            }
        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Unauthorized']);
            return false;
        }

    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}
function HASHsha512($input)
{
    return hash('sha512', $input);
}

function service_getUser($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM merchant_user");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $rows = [];
            while ($row2 = $result2->fetch_assoc()) {
                $rows[] = $row2;
            }
            if (!empty($rows)) {
                http_response_code(200);
                echo json_encode($rows);
            } else {
                http_response_code(404);
                echo json_encode(['message' => 'Users not found']);
            }
        } else {
            http_response_code(404);
            echo json_encode(['message' => 'User not found']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_getDataTransaksi($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;
        
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM h738j3jkr38j2374490mf7_user_transaction_history");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $rows = [];
            while ($row2 = $result2->fetch_assoc()) {
                $rows[] = $row2;
            }
            if (!empty($rows)) {
                http_response_code(200);
                echo json_encode($rows);
            } else {
                http_response_code(404);
                echo json_encode(['message' => 'Transaksi not found']);
            }
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_getTotalData($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;
        
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM h738j3jkr38j2374490mf7_user_transaction_history");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $gross_amount = 0;
            $count = 0;
            while ($row2 = $result2->fetch_assoc()) {
                $count += 1;
                $gross_amount += $row2['gross_amount'];
            }
            http_response_code(200);
            echo json_encode(['total_amount' => $gross_amount, 'total_count' => $count]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_getRecentTransaction($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM h738j3jkr38j2374490mf7_user_transaction_history ORDER BY transaction_time DESC LIMIT 5");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $rows = [];
            while ($row2 = $result2->fetch_assoc()) {
                $rows[] = $row2;
            }
            http_response_code(200);
            echo json_encode($rows);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_getDataChart($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM h738j3jkr38j2374490mf7_user_transaction_history WHERE transaction_time BETWEEN DATE_SUB(CURDATE(), INTERVAL 7 DAY) AND CURDATE() ORDER BY transaction_time DESC");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $rows = [];
            while ($row2 = $result2->fetch_assoc()) {
                $rows[] = ['transaction_time' => $row2['transaction_time'], 'gross_amount' => $row2['gross_amount']];
            }
            http_response_code(200);
            echo json_encode($rows);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_transactionHistory($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row) {
            $connection2 = dn_server_02();
            if (is_array($connection2) && isset($connection2['status'])) {
                return $connection2;
            }
            $stmt2 = $connection2->prepare("SELECT * FROM h738j3jkr38j2374490mf7_user_transaction_history");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $rows = [];
            while ($row2 = $result2->fetch_assoc()) {
                $rows[] = $row2;
            }
            http_response_code(200);
            echo json_encode($rows);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

//Memulai function dengan mengembalikan nilai return;
function service_infoAkun($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;
        $role = $decoded->role;
        
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ? AND role_query = ?");
        $stmt->bind_param("ss", $auth_uid, $role);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();

        if($row){
            if($row['role_query'] == 'Developer'){
                $select_all = $connection->prepare("SELECT * FROM auth_key");
                $select_all->execute();
                $result_all = $select_all->get_result();

                $all_users = [];
                while ($row_all = $result_all->fetch_assoc()) {
                    $all_users[] = [
                        'id_akun' => $row_all['auth_uid'],
                        'nama' => $row_all['name_query'],
                        'no_hp' => $row_all['nomor_hp'],
                        'email' => $row_all['email_query'],
                        'role' => $row_all['role_query'],
                        'active_status' => $row_all['account_status']
                    ];
                }

                $compress_JWT = JWT::encode($all_users, JWT_SECRET_KEY, 'HS256');
                return $compress_JWT;
            }
        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Unauthorized']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_viewAkun($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if($row){
            $nama = $row['name_query'];
            $email = $row['email_query'];
            $no_hp = $row['nomor_hp'];
            $password = $row['password_query'];
            $role = $row['role_query'];
            $auth_token_query = $row['auth_token_query'];

            $compress_JWT = JWT::encode(['nama' => $nama, 'email' => $email, 'no_hp' => $no_hp, 'password' => $password, 'role' => $role, 'auth_token_query' => $auth_token_query], JWT_SECRET_KEY, 'HS384');
            return $compress_JWT;
        } else {
            http_response_code(404);
            echo json_encode(['message' => 'User not found']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_activeAccount($token, $id_akun){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;

        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();

        if($row){
            if($row['role_query'] == 'Developer'){
                $then_select = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
                $then_select->bind_param("s", $id_akun);
                $then_select->execute();
                $result_then_select = $then_select->get_result();
                $row_then_select = $result_then_select->fetch_assoc();
                if($row_then_select && $row_then_select['account_status'] == 'Deactive'){
                    $user_token = $row_then_select['auth_token_query'];
                    $update_status = $connection->prepare("UPDATE auth_key SET account_status = 'Active' WHERE auth_uid = ? AND auth_token_query = ?");
                    $update_status->bind_param("ss", $id_akun, $user_token);
                    $update_status->execute();

                    $message = 'success_setStatus';
                    return $message;
                } else if($row_then_select && $row_then_select['account_status'] == 'Active'){
                    $user_token = $row_then_select['auth_token_query'];
                    $update_status = $connection->prepare("UPDATE auth_key SET account_status = 'Deactive' WHERE auth_uid = ? AND auth_token_query = ?");
                    $update_status->bind_param("ss", $id_akun, $user_token);
                    $update_status->execute();

                    $message = 'success_setStatus';
                    return $message;
                } else {
                    $message = 'Akun tidak ditemukan';
                    return $message;
                }
            } else {
                $message = 'Unauthorized, Not have previlige';
                return $message;
            }
        } else {
            $message = 'Akun tidak ditemukan';
            return $message;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_addProject($token, $nama_project, $skalabilitas_project, $target_selesai){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try{
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if($row){
            if($row['role_query'] == 'Developer' || $row['role_query'] == 'Admin'){
                //Create unique id project
                $unique = uniqid();
                $number = rand(10000000, 99999999);
                $project_id = hash('sha256', $unique . $number);

                $default_image = 'default/defaultproject.jpg';

                $stmt2 = $connection->prepare("INSERT INTO dn_project (project_id, project_name, project_scale, project_date, project_image) VALUES (?, ?, ?, ?, ?)");
                $stmt2->bind_param("sssss", $project_id, $nama_project, $skalabilitas_project, $target_selesai, $default_image);
                if($stmt2->execute()){
                    $statusCode = 200;
                    return $statusCode;
                } else {
                    $statusCode = 500;
                    return $statusCode;
                }
            } else {
                $statusCode = 401;
                return $statusCode;
            }
        } else {
            $message = 'Akun tidak ditemukan';
            return $message;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

function service_getProject($token){
    $connection = dn_server_01();
    if (is_array($connection) && isset($connection['status'])) {
        return $connection;
    }
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        $auth_uid = $decoded->auth_uid;
        $stmt = $connection->prepare("SELECT * FROM auth_key WHERE auth_uid = ?");
        $stmt->bind_param("s", $auth_uid);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if($row){
            $stmt2 = $connection->prepare("SELECT * FROM dn_project");
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            $getAllProject = [];
            while ($row2 = $result2->fetch_assoc()) {
                $getAllProject[] = [
                    'project_id' => $row2['project_id'],
                    'project_name' => $row2['project_name'],
                    'project_scale' => $row2['project_scale'],
                    'project_date' => $row2['project_date'],
                    'project_image' => $row2['project_image']   
                ];
            }
            return $getAllProject;
            
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['message' => 'Internal server error', 'error' => $e->getMessage()]);
    }
}

