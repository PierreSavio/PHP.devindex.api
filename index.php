<?php
//index.php as route for angular api
// to serve angular to ngrok, type "ngrok http --host-header=rewrite 4200"

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: *");

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    return null;
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (isset($data['action'])) {
        switch ($data['action']) {

            case 'login':
                require 'service/service.method.post.php';
                $login = service_login($data['email'], $data['password']);
                if($login !== 'Deactive'){
                    http_response_code(200);
                    echo json_encode(['status' => 'successLogin', 'code' => 200604, 'token' => $login]);
                } else if($login == 'Deactive'){
                    http_response_code(401);
                    echo json_encode(['status' => 'accountDeactive', 'code' => 401321, 'message' => 'Akun anda tidak aktif!']);
                } else if($login == 'passwordInvalid'){
                    http_response_code(401);
                    echo json_encode(['status' => 'passwordInvalid', 'code' => 401001, 'message' => 'Password tidak sesuai!']);
                } else if($login == 'failedLogin'){
                    http_response_code(404);
                    echo json_encode(['status' => 'failedLogin', 'code' => 404002, 'message' => 'User tidak ditemukan!']);
                } else if($login == 'internalServerError'){
                    http_response_code(500);
                    echo json_encode(['status' => 'internalServerError', 'code' => 500000, 'message' => 'Terjadi kesalahan di server!']);
                }
                break;

            case 'getData':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_getUser($headers['Authorization']);
                break;
            case 'getTotalData':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_getTotalData($headers['Authorization']);
                break;
            case 'dataTransaksi':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_getDataTransaksi($headers['Authorization']);
                break;
            case 'getRecentTransaction':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_getRecentTransaction($headers['Authorization']);
                break;
            case 'getDataChart':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_getDataChart($headers['Authorization']);
                break;
            case 'transactionHistory':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                service_transactionHistory($headers['Authorization']);
                break;

            //Breakpoint dengan nilai return;
            case 'addAkun':
                require 'service/service.method.post.php';
                $headers = getallheaders();
                $nama = $data['data']['nama'];
                $no_hp = $data['data']['no_hp'];
                $email = $data['data']['email'];
                $password = $data['data']['password'];
                $role = $data['data']['role'];
                
                $response = service_addAkun($headers['Authorization'], $nama, $no_hp, $email, $password, $role);
                if($response){
                    http_response_code(200);
                    echo json_encode(['message' => 'successAddAkun', 'data' => $response]);
                }
                break;

            case 'infoAkun':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                $info_akun = service_infoAkun($headers['Authorization']);
                if($info_akun){
                    http_response_code(200);
                    echo json_encode($info_akun);
                } else {
                    http_response_code(401);
                    echo json_encode(['message' => 'Unauthorized']);
                }
                break;
            case 'viewAkun':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                $view_akun = service_viewAkun($headers['Authorization']);
                if($view_akun){
                    http_response_code(200);
                    echo json_encode($view_akun);
                }
                break;

            case 'activeAccount':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                $return_value = service_activeAccount($headers['Authorization'], $data['id_akun']);
                if($return_value){
                    http_response_code(200);
                    echo json_encode(['message' => $return_value]);
                } else {
                    http_response_code(401);
                    echo json_encode(['message' => $return_value]);
                }
                break;

            case 'addProject':
                $headers = getallheaders();
                $nama_project = $data['data']['nama_project'];
                $skalabilitas_project = $data['data']['skalabilitas_project'];
                $target_selesai = $data['data']['target_selesai'];

                require 'service/service.method.post.php';
                $return_value = service_addProject($headers['Authorization'], $nama_project, $skalabilitas_project, $target_selesai);
                if($return_value == 200){
                    http_response_code(200);
                    echo json_encode([
                        'status' => 'success_addProject', 
                        'message' => 'Add project success', 
                        'code' => 200, 
                        'letIN' => 'approve'
                    ]);
                } else if($return_value == 401){
                    http_response_code(401);
                    echo json_encode([
                        'status' => 'Unauthorized, Not have previlige', 
                        'message' => 'Unauthorized, Not have previlige', 
                        'code' => 401, 
                        'letIN' => 'rejected'
                    ]);
                } else if($return_value == 404){
                    http_response_code(404);
                    echo json_encode([
                        'status' => 'Akun tidak ditemukan', 
                        'message' => 'Akun tidak ditemukan', 
                        'code' => 404, 
                        'letIN' => 'notFound'
                    ]);
                } else if($return_value == 500){
                    http_response_code(500);
                    echo json_encode([
                        'status' => 'Internal server error', 
                        'message' => 'Internal server error', 
                        'code' => 500, 
                        'letIN' => 'error'
                    ]);
                }
                break;
            
            case 'getProject':
                $headers = getallheaders();
                require 'service/service.method.post.php';
                $return_value = service_getProject($headers['Authorization']);
                if($return_value){
                    http_response_code(200);
                    echo json_encode($return_value);
                }
                break;
            //breakpoint
            default:
                http_response_code(400);
                echo json_encode(['message' => 'Invalid action']);
                break;
        }
    } else {
        http_response_code(400);
        echo json_encode(['message' => 'Action not specified']);
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
} else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
} else if ($_SERVER['REQUEST_METHOD'] === 'PATCH') {
} else {
    echo json_encode(['message' => 'Invalid request method']);
}

?>