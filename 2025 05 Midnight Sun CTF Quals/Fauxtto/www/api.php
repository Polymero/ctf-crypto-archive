<?php
define('FLAG', 'midnight{*****CENSORED*****}');
define('KEY', "****CENSORED****");

if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    header('HTTP/1.1 405 Method Not Allowed');
    exit;
}

header('Content-Type: application/json');

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if ($data['request'] == 'ticket') {
    $winning_number = generate_6_random_digits();
    
                        $winning_number .= generate_6_random_digits() . generate_6_random_digits() . generate_6_random_digits() . generate_6_random_digits() . generate_6_random_digits();  // hehehehehe
    
    $winning_hash = md5($winning_number);
    
    $response = [
        'winning_number' => secure_serialize($winning_hash),
        'ticket_no' => substr(md5($winning_hash), 0, 8)
    ];
    
    exit(json_encode($response));
} elseif ($data['request'] == 'check') {
    $guess = $data['guess'];
    $ticket_no = $data['ticket_no'];
    $winning_hash = secure_unserialize($data['winning_number']);
    
    if (empty($ticket_no) || empty($winning_hash)) {
        exit(json_encode(['error' => "Invalid request"]));
    }
    
    if (!preg_match('/^[0-9a-f]{8}$/', $ticket_no)) {
        exit(json_encode(['error' => "Invalid ticket number"]));
    }
    
    if (!preg_match('/^[0-9a-f]{32}$/', $winning_hash)) {
        exit(json_encode(['error' => "Corrupted ticket detected"]));
    }
    
    if ($ticket_no != substr(md5($winning_hash), 0, 8)) {
        exit(json_encode(['error' => "Forged ticket detected"]));
    }
    
    if (!preg_match('/^[0-9]{6}$/', $guess)) {
        exit(json_encode(['error' => "Invalid guess. Please enter a 6-digit number"]));
    }
    
    if (md5($guess) === $winning_hash) {
        exit(json_encode(['success' => "Congratulations! You've got the winning number. Here's your prize: " . FLAG]));
    } else {
        exit(json_encode(['error' => "Sorry, that's not the winning number. Try again!"]));
    }
} else {
    header('HTTP/1.1 400 Bad Request');
    exit;
}


function secure_serialize($data) {
    $data = gzencode($data);
    $iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    $data = openssl_encrypt($data, 'AES-128-CTR', KEY, OPENSSL_RAW_DATA, $iv);
    $data = bin2hex($data);
    return $data;
}

function secure_unserialize($data) {
    $data = hex2bin($data);
    $iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    $data = openssl_decrypt($data, 'AES-128-CTR', KEY, OPENSSL_RAW_DATA, $iv);
    $data = gzdecode($data);
    return $data;
}

function generate_6_random_digits() {
    return sprintf('%06d', random_int(0, 999999));
}
