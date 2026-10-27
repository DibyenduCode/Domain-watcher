<?php
/**
 * Banglar Server - Domain Availability Watcher & REST API System
 * Core Configuration & WHOIS Engine
 * Compatible with PHP 8.0+
 */

// Prevent multiple inclusions
if (defined('BS_CONFIG_LOADED')) {
    return;
}
define('BS_CONFIG_LOADED', true);

// Set strict error reporting for logging, but suppress display in production if needed
error_reporting(E_ALL & ~E_NOTICE);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Set default timezone
date_default_timezone_set('Asia/Dhaka');

// Start safe session if not already active
function startSessionSafe(): void {
    if (session_status() === PHP_SESSION_NONE) {
        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
                    || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
                    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

        // Enforce secure cookie attributes (HttpOnly, SameSite, Secure if HTTPS)
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isSecure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        ini_set('session.cookie_httponly', '1');
        ini_set('session.use_only_cookies', '1');
        session_start();
    }
}

// -------------------------------------------------------------
// Database Credentials (Configure for your cPanel / Localhost)
// NOTE FOR CPANEL: Set DB_NAME and DB_USER with your cPanel prefix
// e.g. define('DB_NAME', 'cpaneluser_dwatcher');
//      define('DB_USER', 'cpaneluser_dbuser');
//      define('DB_PASS', 'YourStrongPassword123');
// -------------------------------------------------------------
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_NAME', getenv('DB_NAME') ?: 'dwatcher_db');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : '');
define('DB_CHARSET', 'utf8mb4');

/**
 * Get singleton PDO instance
 */
function getDbConnection(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // If API or AJAX, return JSON error
            if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || (isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'json')) || str_contains($_SERVER['REQUEST_URI'] ?? '', 'api.php')) {
                header('Content-Type: application/json; charset=UTF-8', true, 500);
                echo json_encode([
                    'status'  => 'error',
                    'message' => 'Database connection failure. Please verify database configuration in config.php.'
                ]);
                exit;
            }
            die("Database Connection Error: " . htmlspecialchars($e->getMessage()));
        }
    }
    return $pdo;
}

/**
 * Fetch Admin Settings from database
 */
function getAdminSettings(?PDO $pdo = null): array {
    $pdo = $pdo ?? getDbConnection();
    try {
        $stmt = $pdo->query("SELECT * FROM `admins` ORDER BY `id` ASC LIMIT 1");
        $row = $stmt->fetch();
        if ($row) {
            return $row;
        }
    } catch (Exception $e) {
        // Fallback default
    }
    return [
        'id'                  => 1,
        'username'            => 'admin',
        'admin_email'         => 'admin@banglarserver.com',
        'daily_report_emails' => null,
        'logo_url'            => 'assets/logo.png',
        'booking_base_url'    => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query=',
        'daily_report_time'   => '09:00:00',
        'cron_token'          => 'bs_cron_7f8a3c9b2e1d'
    ];
}

/**
 * Extract all unique valid recipient email addresses for admin daily report
 */
function getAdminReportEmails(?array $adminSettings = null, ?PDO $pdo = null): array {
    if ($adminSettings === null) {
        $adminSettings = getAdminSettings($pdo);
    }
    $rawList = [];
    if (!empty($adminSettings['admin_email'])) {
        $rawList[] = $adminSettings['admin_email'];
    }
    if (!empty($adminSettings['daily_report_emails'])) {
        $rawList[] = $adminSettings['daily_report_emails'];
    }

    $emails = [];
    foreach ($rawList as $raw) {
        $parts = preg_split('/[\r\n,;\s]+/', (string)$raw);
        foreach ($parts as $p) {
            $cleaned = trim($p);
            if (!empty($cleaned) && filter_var($cleaned, FILTER_VALIDATE_EMAIL)) {
                $emails[] = strtolower($cleaned);
            }
        }
    }
    return array_values(array_unique($emails));
}

/**
 * Fetch SMTP Settings from database
 */
function getSmtpSettings(?PDO $pdo = null): array {
    $pdo = $pdo ?? getDbConnection();
    try {
        $stmt = $pdo->query("SELECT * FROM `smtp_settings` ORDER BY `id` ASC LIMIT 1");
        $row = $stmt->fetch();
        if ($row) {
            return $row;
        }
    } catch (Exception $e) {
        // Fallback
    }
    return [
        'id'          => 1,
        'smtp_host'   => 'smtp.mailtrap.io',
        'smtp_port'   => 587,
        'smtp_user'   => '',
        'smtp_pass'   => '',
        'smtp_secure' => 'tls',
        'from_email'  => 'support@banglarserver.com',
        'from_name'   => 'Banglar Server Watcher'
    ];
}

/**
 * Fetch all email templates from database, keyed by template_key
 */
function getEmailTemplates(?PDO $pdo = null): array {
    $pdo = $pdo ?? getDbConnection();
    $templates = [];
    try {
        $stmt = $pdo->query("SELECT * FROM `email_templates` ORDER BY `id` ASC");
        if ($stmt) {
            while ($row = $stmt->fetch()) {
                $templates[$row['template_key']] = $row;
            }
        }
    } catch (Exception $e) {
        // Fallback below
    }

    $defaultTemplates = [
        'domain_added' => [
            'template_key'  => 'domain_added',
            'template_name' => 'Domain Added to Watchlist (Enrollment Confirmation)',
            'subject'       => 'Domain {domain} Successfully Added to Banglar Server Watchlist',
            'headline'      => 'Watchlist Activated for {domain}',
            'body_html'     => '<p style="color: #cbd5e1; font-size: 15px;">Thank you for choosing <strong>Banglar Server Domain Watcher</strong>. We have successfully enrolled your target domain into our 24/7 automated monitoring system.</p><p style="color: #cbd5e1; font-size: 15px;">Our engine monitors registry WHOIS servers continuously. The moment <strong><span style="color: #10b981;">{domain}</span></strong> expires and drops into availability, we will dispatch an instant notification to <strong>{email}</strong> so you can claim it immediately!</p>',
            'button_text'   => 'Search on Banglar Server',
            'button_url'    => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}',
            'is_enabled'    => 1
        ],
        'domain_available' => [
            'template_key'  => 'domain_available',
            'template_name' => 'Domain Available / Drop Alert Notification',
            'subject'       => '🔥 URGENT: {domain} is Available to Register Right Now!',
            'headline'      => 'Congratulations! {domain} is Available',
            'body_html'     => '<p style="color: #cbd5e1; font-size: 15px;">Great news! We just verified domain <strong><span style="color: #10b981;">{domain}</span></strong> via registry lookup, and it is <strong>100% available for immediate purchase</strong>.</p><p style="color: #cbd5e1; font-size: 15px;">Domain names are registered on a first-come, first-served basis. Secure it right now through Banglar Server before someone else claims it!</p>',
            'button_text'   => 'Claim & Book Domain Now',
            'button_url'    => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}',
            'is_enabled'    => 1
        ],
        'admin_daily_report' => [
            'template_key'  => 'admin_daily_report',
            'template_name' => 'Admin Daily Watcher Summary Report (দৈনিক ডোমেন রিপোর্ট)',
            'subject'       => '📊 Banglar Server Daily Watcher Report: {newly_available} Newly Available Domains ({date_short})',
            'headline'      => 'Daily Domain Watcher Executive Summary',
            'body_html'     => '<p style="color: #cbd5e1; font-size: 15px;">Here is your scheduled daily executive summary of all monitored domains. Our automated WHOIS engine checked all watchlist targets.</p><p style="color: #cbd5e1; font-size: 15px;">Today we detected <strong><span style="color: #10b981;">{newly_available} newly available</span></strong> domain(s) ready for registration. Check the breakdown and full domain database below.</p>',
            'button_text'   => 'Open Admin Watchlist',
            'button_url'    => 'admin.php',
            'is_enabled'    => 1
        ]
    ];

    return array_merge($defaultTemplates, $templates);
}

/**
 * Fetch a specific email template by key
 */
function getEmailTemplate(string $key, ?PDO $pdo = null): array {
    $all = getEmailTemplates($pdo);
    return $all[$key] ?? [
        'template_key'  => $key,
        'template_name' => ucfirst(str_replace('_', ' ', $key)),
        'subject'       => 'Notification regarding {domain}',
        'headline'      => '{domain} Status Alert',
        'body_html'     => '<p>Status update for domain {domain}.</p>',
        'button_text'   => 'Search on Banglar Server',
        'button_url'    => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}',
        'is_enabled'    => 1
    ];
}

/**
 * Sanitize domain name input
 * Strips http://, https://, www., paths, query strings, port numbers, whitespace.
 * Validates domain structure.
 */
function cleanDomain(string $input): string {
    $domain = trim($input);
    $domain = strtolower($domain);

    // Remove protocol
    $domain = preg_replace('#^https?://#i', '', $domain);
    $domain = preg_replace('#^ftp://#i', '', $domain);

    // Remove leading www.
    $domain = preg_replace('#^www\.#i', '', $domain);

    // Remove paths, queries, fragments, ports
    $domain = preg_replace('~[:/?#].*$~', '', $domain);

    // Strip trailing slashes or dots
    $domain = trim($domain, "/. \t\n\r\0\x0B");

    // Strict domain format validation
    // Allows standard international domains: letters, digits, hyphens, and dots
    if (!preg_match('/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i', $domain)) {
        return '';
    }

    return $domain;
}

/**
 * Core WHOIS Availability Engine
 * Uses direct socket connection (fsockopen on Port 43) with 10s timeout
 * Evaluates exact negative responses per TLD and includes DNS fallback.
 * 
 * Returns true if AVAILABLE, false if REGISTERED / TAKEN.
 */
function isDomainAvailable(string $domain): bool {
    $clean = cleanDomain($domain);
    if (empty($clean)) {
        return false;
    }

    // Extract TLD / Extension (including multi-part TLDs like co.in, com.bd)
    $parts = explode('.', $clean);
    if (count($parts) < 2) {
        return false;
    }

    $tld = end($parts);
    $secondLevel = '';
    if (count($parts) >= 3) {
        $secondLevel = $parts[count($parts) - 2] . '.' . $tld;
    }

    // TLD WHOIS server mapping and availability match patterns
    $whoisServers = [
        'com' => [
            'server'   => 'whois.verisign-grs.com',
            'patterns' => ['No match for', 'NOT FOUND']
        ],
        'net' => [
            'server'   => 'whois.verisign-grs.com',
            'patterns' => ['No match for', 'NOT FOUND']
        ],
        'org' => [
            'server'   => 'whois.publicinterestregistry.org',
            'patterns' => ['NOT FOUND', 'Domain not found', 'No match']
        ],
        'in' => [
            'server'   => 'whois.registry.in',
            'patterns' => ['NOT FOUND']
        ],
        'co.in' => [
            'server'   => 'whois.registry.in',
            'patterns' => ['NOT FOUND']
        ],
        'net.in' => [
            'server'   => 'whois.registry.in',
            'patterns' => ['NOT FOUND']
        ],
        'org.in' => [
            'server'   => 'whois.registry.in',
            'patterns' => ['NOT FOUND']
        ],
        'xyz' => [
            'server'   => 'whois.nic.xyz',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'info' => [
            'server'   => 'whois.afilias.net',
            'patterns' => ['NOT FOUND']
        ],
        'biz' => [
            'server'   => 'whois.biz',
            'patterns' => ['Not found', 'No Data Found']
        ],
        'io' => [
            'server'   => 'whois.nic.io',
            'patterns' => ['NOT FOUND', 'Domain not found', 'is available', 'Domain Not Found']
        ],
        'shop' => [
            'server'   => 'whois.nic.shop',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found', 'No match']
        ],
        'online' => [
            'server'   => 'whois.nic.online',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'tech' => [
            'server'   => 'whois.nic.tech',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'me' => [
            'server'   => 'whois.nic.me',
            'patterns' => ['NOT FOUND']
        ],
        'co' => [
            'server'   => 'whois.nic.co',
            'patterns' => ['No Data Found', 'Not found']
        ],
        'app' => [
            'server'   => 'whois.nic.google',
            'patterns' => ['Domain not found', 'NOT FOUND']
        ],
        'dev' => [
            'server'   => 'whois.nic.google',
            'patterns' => ['Domain not found', 'NOT FOUND']
        ],
        'cloud' => [
            'server'   => 'whois.nic.cloud',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'site' => [
            'server'   => 'whois.nic.site',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'club' => [
            'server'   => 'whois.nic.club',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ],
        'agency' => [
            'server'   => 'whois.donuts.co',
            'patterns' => ['Domain not found', 'NOT FOUND']
        ],
        'digital' => [
            'server'   => 'whois.donuts.co',
            'patterns' => ['Domain not found', 'NOT FOUND']
        ],
        'live' => [
            'server'   => 'whois.nic.live',
            'patterns' => ['DOMAIN NOT FOUND', 'Domain not found']
        ]
    ];

    // Check multi-level TLD first (e.g., co.in), then single TLD (e.g., com)
    $serverInfo = null;
    if ($secondLevel !== '' && isset($whoisServers[$secondLevel])) {
        $serverInfo = $whoisServers[$secondLevel];
    } elseif (isset($whoisServers[$tld])) {
        $serverInfo = $whoisServers[$tld];
    }

    $whoisQuerySuccess = false;
    $whoisSaysAvailable = false;

    if ($serverInfo !== null) {
        $server = $serverInfo['server'];
        $patterns = $serverInfo['patterns'];

        $errno = 0;
        $errstr = '';
        $timeout = 10; // 10 seconds timeout requirement

        $socket = @fsockopen($server, 43, $errno, $errstr, $timeout);
        if ($socket) {
            stream_set_timeout($socket, $timeout);
            // Query domain name
            fwrite($socket, $clean . "\r\n");

            $response = '';
            while (!feof($socket)) {
                $response .= fgets($socket, 512);
            }
            fclose($socket);

            if (strlen($response) > 0) {
                $whoisQuerySuccess = true;
                foreach ($patterns as $pattern) {
                    if (stripos($response, $pattern) !== false) {
                        $whoisSaysAvailable = true;
                        break;
                    }
                }
            }
        }
    }

    if ($whoisQuerySuccess) {
        return $whoisSaysAvailable;
    }

    // DNS Fallback: If WHOIS port 43 is blocked/firewalled or TLD not listed in table
    // If NS, A, or MX records exist, domain is unequivocally registered.
    $hasDns = @checkdnsrr($clean, 'NS') ||
              @checkdnsrr($clean, 'A')  ||
              @checkdnsrr($clean, 'MX') ||
              @checkdnsrr($clean, 'SOA');

    // If records exist => registered (not available). If none exist => available.
    return !$hasDns;
}

/**
 * Generate CSRF Token for Admin forms
 */
function getCsrfToken(): string {
    startSessionSafe();
    if (empty($_SESSION['bs_csrf_token'])) {
        $_SESSION['bs_csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['bs_csrf_token'];
}

/**
 * Verify CSRF Token
 */
function verifyCsrfToken(?string $token): bool {
    startSessionSafe();
    if (empty($_SESSION['bs_csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['bs_csrf_token'], $token);
}

/**
 * Check if Admin is currently logged in
 */
function isAdminLoggedIn(): bool {
    startSessionSafe();
    return !empty($_SESSION['bs_admin_id']) && !empty($_SESSION['bs_admin_user']);
}

/**
 * Require Admin authentication, redirect to login if not authenticated
 */
function requireAdminAuth(): void {
    if (!isAdminLoggedIn()) {
        header("Location: admin.php?action=login");
        exit;
    }
}

/**
 * HTML Output Escaper
 */
function e(?string $string): string {
    return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
}
