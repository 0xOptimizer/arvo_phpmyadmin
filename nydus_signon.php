<?php
session_name('NydusSignonSession');
session_start();

$token = $_GET['token'] ?? '';

if (empty($token)) {
    http_response_code(400);
    exit('Missing token.');
}

$credentials_file = '/tmp/nydus_pma_' . preg_replace('/[^a-f0-9]/', '', $token) . '.json';

if (!file_exists($credentials_file)) {
    http_response_code(403);
    exit('Invalid or expired token.');
}

$age = time() - filemtime($credentials_file);
if ($age > 30) {
    unlink($credentials_file);
    http_response_code(403);
    exit('Token expired.');
}

$data = json_decode(file_get_contents($credentials_file), true);
unlink($credentials_file);

if (!isset($data['username'], $data['password'])) {
    http_response_code(400);
    exit('Malformed credentials file.');
}

$_SESSION['PMA_single_signon_user']     = $data['username'];
$_SESSION['PMA_single_signon_password'] = $data['password'];
$_SESSION['PMA_single_signon_host']     = '127.0.0.1';
$_SESSION['PMA_single_signon_done']     = true;

session_write_close();

$server = isset($_GET['server']) ? (int)$_GET['server'] : 2;
header('Location: https://pma.arvo.team/index.php?server=' . $server);
exit;