<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Secure External REST API Endpoint
 * CORS Enabled, Dual-Key Authentication (API Key + Secret Key)
 */

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-KEY, X-API-SECRET, X-Requested-With');
header('Content-Type: application/json; charset=UTF-8');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/smtp_mailer.php';

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Method Not Allowed. Only POST requests are accepted.'
    ]);
    exit;
}

$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$bookingBaseUrl = rtrim($adminSettings['booking_base_url'] ?? '', '=') . '=';

// Parse Input (JSON body or Form-data)
$rawBody = file_get_contents('php://input');
$jsonInput = json_decode($rawBody, true) ?? [];

// 1. Extract API Key & Secret Key
// Check HTTP Headers first, fallback to JSON body / POST parameters
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? ($jsonInput['api_key'] ?? ($_POST['api_key'] ?? ''));
$apiSecret = $_SERVER['HTTP_X_API_SECRET'] ?? ($jsonInput['secret_key'] ?? ($_POST['secret_key'] ?? ''));

$apiKey = trim($apiKey);
$apiSecret = trim($apiSecret);

if (empty($apiKey) || empty($apiSecret)) {
    http_response_code(401);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Unauthorized. Missing API Key or Secret Key. Provide headers X-API-KEY and X-API-SECRET or JSON fields api_key and secret_key.'
    ]);
    exit;
}

// 2. Validate Dual-Key Credentials against `api_keys` table
$stmtKey = $pdo->prepare("SELECT * FROM `api_keys` WHERE `api_key` = ? LIMIT 1");
$stmtKey->execute([$apiKey]);
$keyRow = $stmtKey->fetch();

if (!$keyRow || $keyRow['status'] !== 'active' || !hash_equals($keyRow['secret_key'], $apiSecret)) {
    http_response_code(401);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Unauthorized. Invalid, expired, or revoked API credentials.'
    ]);
    exit;
}

// Update API Key usage statistics
$stmtUpdateStats = $pdo->prepare("UPDATE `api_keys` SET `total_requests` = `total_requests` + 1, `last_used_at` = NOW() WHERE `id` = ?");
$stmtUpdateStats->execute([$keyRow['id']]);

// 3. Extract and Validate Target Domain, User Email, and Optional Lead Info
$rawDomain = $jsonInput['domain'] ?? ($_POST['domain'] ?? '');
$rawEmail  = $jsonInput['email'] ?? ($_POST['email'] ?? '');
$rawName   = $jsonInput['name'] ?? ($_POST['name'] ?? '');
$rawPhone  = $jsonInput['phone'] ?? ($_POST['phone'] ?? '');

$domain = cleanDomain($rawDomain);
$email  = trim($rawEmail);
$userName  = !empty(trim($rawName)) ? trim($rawName) : null;
$userPhone = !empty(trim($rawPhone)) ? trim($rawPhone) : null;

if (empty($domain)) {
    http_response_code(422);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Unprocessable Entity. A valid domain name is required (e.g. example.com).'
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(422);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Unprocessable Entity. A valid user email address is required.'
    ]);
    exit;
}

// 4. Instant WHOIS Check
$isAvailable = isDomainAvailable($domain);
$newStatus = $isAvailable ? 'available' : 'registered';
$notified = $isAvailable ? 1 : 0;
$sourceApp = $keyRow['app_name'] ?? 'API Client';

// Duplicate check
$stmtCheck = $pdo->prepare("SELECT id, status, user_name, user_phone FROM `watched_domains` WHERE `domain_name` = ? AND `user_email` = ? LIMIT 1");
$stmtCheck->execute([$domain, $email]);
$existing = $stmtCheck->fetch();

if ($existing) {
    $finalName = $userName ?? $existing['user_name'];
    $finalPhone = $userPhone ?? $existing['user_phone'];

    $stmtUp = $pdo->prepare("
        UPDATE `watched_domains`
        SET `status` = ?,
            `last_checked` = NOW(),
            `notified_available` = ?,
            `user_name` = ?,
            `user_phone` = ?,
            `source_app` = ?
        WHERE `id` = ?
    ");
    $stmtUp->execute([$newStatus, $notified, $finalName, $finalPhone, $sourceApp, $existing['id']]);
    $domainId = $existing['id'];
} else {
    $stmtIns = $pdo->prepare("
        INSERT INTO `watched_domains` (`domain_name`, `user_email`, `user_name`, `user_phone`, `added_by`, `source_app`, `status`, `last_checked`, `notified_available`, `created_at`)
        VALUES (?, ?, ?, ?, 'api', ?, ?, NOW(), ?, NOW())
    ");
    $stmtIns->execute([$domain, $email, $userName, $userPhone, $sourceApp, $newStatus, $notified]);
    $domainId = (int)$pdo->lastInsertId();
}

// 5. Dispatch Instant Dual Email Notifications
$mailer = new BanglarSmtpMailer(getSmtpSettings($pdo), $adminSettings);
$directBookingUrl = $bookingBaseUrl . urlencode($domain);

if ($isAvailable) {
    // Send to User
    $mailer->sendUserAvailableAlert($domain, $email, $userName);
    // Send to Admin
    $mailer->sendAdminLeadAlert($domain, $email, "REST API ({$sourceApp})", 'available', $userName, $userPhone);

    http_response_code(200);
    echo json_encode([
        'status'          => 'success',
        'domain_id'       => $domainId,
        'domain'          => $domain,
        'user_name'       => $userName,
        'user_phone'      => $userPhone,
        'domain_status'   => 'available',
        'booking_url'     => $directBookingUrl,
        'message'         => "Domain is available right now! Instant availability emails and registration links dispatched to {$email}.",
        'source_app'      => $sourceApp,
        'checked_at'      => date('Y-m-d H:i:s T')
    ]);
    exit;
} else {
    // Send Watchlist Confirmation Alert to User
    $mailer->sendWatchlistConfirmation($domain, $email, $userName);

    // Send Admin Watchlist Alert
    $mailer->sendAdminLeadAlert($domain, $email, "REST API ({$sourceApp})", 'registered', $userName, $userPhone);

    http_response_code(200);
    echo json_encode([
        'status'          => 'success',
        'domain_id'       => $domainId,
        'domain'          => $domain,
        'user_name'       => $userName,
        'user_phone'      => $userPhone,
        'domain_status'   => 'registered',
        'message'         => "Domain is currently registered. Successfully enrolled into Banglar Server 24/7 automated drop watch queue.",
        'source_app'      => $sourceApp,
        'checked_at'      => date('Y-m-d H:i:s T')
    ]);
    exit;
}
