<?php
/**
 * Banglar Server - Domain Availability Watcher & REST API System
 * Standalone Socket SMTP Client & HTML Email Template Engine
 * 100% Dependency-free, Core PHP 8.x
 */

require_once __DIR__ . '/config.php';

class BanglarSmtpMailer {
    private array $smtpSettings;
    private array $adminSettings;
    private array $debugLog = [];

    public function __construct(?array $smtpSettings = null, ?array $adminSettings = null) {
        $this->smtpSettings = $smtpSettings ?? getSmtpSettings();
        $this->adminSettings = $adminSettings ?? getAdminSettings();
    }

    public function getLogs(): array {
        return $this->debugLog;
    }

    private function log(string $msg): void {
        $this->debugLog[] = "[" . date('H:i:s') . "] " . $msg;
    }

    /**
     * Send email using Native Socket SMTP with fallback to mail()
     * 
     * @param string $to Recipient email address
     * @param string $subject Subject line
     * @param string $htmlBody HTML email content
     * @param string|null $toName Optional recipient name
     * @return array ['success' => bool, 'message' => string, 'log' => string]
     */
    public function send(string $to, string $subject, string $htmlBody, ?string $toName = null): array {
        $host   = trim($this->smtpSettings['smtp_host'] ?? '');
        $port   = (int)($this->smtpSettings['smtp_port'] ?? 587);
        $user   = trim($this->smtpSettings['smtp_user'] ?? '');
        $pass   = trim($this->smtpSettings['smtp_pass'] ?? '');
        $secure = strtolower($this->smtpSettings['smtp_secure'] ?? 'tls');
        $fromEmail = trim($this->smtpSettings['from_email'] ?? 'support@banglarserver.com');
        $fromName  = trim($this->smtpSettings['from_name'] ?? 'Banglar Server');

        // Clean headers and parameters
        $to = trim($to);
        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Invalid recipient email address: ' . htmlspecialchars($to), 'log' => ''];
        }

        // If no SMTP host is configured or user is testing fallback
        if (empty($host)) {
            $this->log("No SMTP Host configured. Attempting native PHP mail() fallback...");
            $headers  = "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
            $headers .= "Content-Transfer-Encoding: base64\r\n";
            $headers .= "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <{$fromEmail}>\r\n";
            $encodedSubject = "=?UTF-8?B?" . base64_encode($subject) . "?=";
            $encodedBody = chunk_split(base64_encode($htmlBody));

            $mailSent = @mail($to, $encodedSubject, $encodedBody, $headers);
            return [
                'success' => $mailSent,
                'message' => $mailSent ? 'Sent via PHP mail() fallback' : 'Failed to send via PHP mail() fallback',
                'log'     => implode("\n", $this->debugLog)
            ];
        }

        // Native Socket SMTP execution
        $timeout = 15;
        $context = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true
            ]
        ]);

        $connectHost = ($secure === 'ssl') ? 'ssl://' . $host : $host;
        $this->log("Connecting to {$connectHost}:{$port} (Timeout: {$timeout}s)...");

        $socket = @stream_socket_client(
            "{$connectHost}:{$port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            $this->log("Socket connection failed: {$errstr} ({$errno})");
            return [
                'success' => false,
                'message' => "Socket connection failed to {$host}:{$port} - {$errstr}",
                'log'     => implode("\n", $this->debugLog)
            ];
        }

        stream_set_timeout($socket, $timeout);
        $greeting = $this->readResponse($socket);
        $this->log("Server: " . trim($greeting));

        // EHLO
        $clientHost = $_SERVER['SERVER_NAME'] ?? 'localhost';
        $this->sendCommand($socket, "EHLO {$clientHost}");
        $ehloResp = $this->readResponse($socket);
        $this->log("EHLO Response: " . trim($ehloResp));

        // STARTTLS if configured
        if ($secure === 'tls') {
            $this->log("Sending STARTTLS...");
            $this->sendCommand($socket, "STARTTLS");
            $tlsResp = $this->readResponse($socket);
            $this->log("STARTTLS Response: " . trim($tlsResp));

            if (!str_starts_with(trim($tlsResp), '220')) {
                fclose($socket);
                return [
                    'success' => false,
                    'message' => 'STARTTLS negotiation failed: ' . trim($tlsResp),
                    'log'     => implode("\n", $this->debugLog)
                ];
            }

            $cryptoMethod = STREAM_CRYPTO_METHOD_TLS_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            }
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }

            $cryptoSuccess = @stream_socket_enable_crypto($socket, true, $cryptoMethod);
            if (!$cryptoSuccess) {
                fclose($socket);
                return [
                    'success' => false,
                    'message' => 'TLS encryption handshake failed.',
                    'log'     => implode("\n", $this->debugLog)
                ];
            }
            $this->log("TLS Encryption enabled. Re-issuing EHLO...");
            $this->sendCommand($socket, "EHLO {$clientHost}");
            $ehlo2 = $this->readResponse($socket);
            $this->log("EHLO 2: " . trim($ehlo2));
        }

        // Authenticate if credentials provided
        if (!empty($user) && !empty($pass)) {
            $this->log("Authenticating with AUTH LOGIN...");
            $this->sendCommand($socket, "AUTH LOGIN");
            $authResp = $this->readResponse($socket);
            $this->log("AUTH LOGIN Response: " . trim($authResp));

            $this->sendCommand($socket, base64_encode($user));
            $userResp = $this->readResponse($socket);

            $this->sendCommand($socket, base64_encode($pass));
            $passResp = $this->readResponse($socket);
            $this->log("Auth verify response: " . trim($passResp));

            if (!str_starts_with(trim($passResp), '235')) {
                $this->sendCommand($socket, "QUIT");
                fclose($socket);
                return [
                    'success' => false,
                    'message' => 'SMTP Authentication failed: ' . trim($passResp),
                    'log'     => implode("\n", $this->debugLog)
                ];
            }
        }

        // MAIL FROM
        $this->sendCommand($socket, "MAIL FROM:<{$fromEmail}>");
        $mailFromResp = $this->readResponse($socket);
        if (!str_starts_with(trim($mailFromResp), '250')) {
            $this->sendCommand($socket, "QUIT");
            fclose($socket);
            return [
                'success' => false,
                'message' => 'MAIL FROM rejected: ' . trim($mailFromResp),
                'log'     => implode("\n", $this->debugLog)
            ];
        }

        // RCPT TO
        $this->sendCommand($socket, "RCPT TO:<{$to}>");
        $rcptResp = $this->readResponse($socket);
        if (!str_starts_with(trim($rcptResp), '250')) {
            $this->sendCommand($socket, "QUIT");
            fclose($socket);
            return [
                'success' => false,
                'message' => 'RCPT TO rejected: ' . trim($rcptResp),
                'log'     => implode("\n", $this->debugLog)
            ];
        }

        // DATA
        $this->sendCommand($socket, "DATA");
        $dataResp = $this->readResponse($socket);
        if (!str_starts_with(trim($dataResp), '354')) {
            $this->sendCommand($socket, "QUIT");
            fclose($socket);
            return [
                'success' => false,
                'message' => 'DATA command rejected: ' . trim($dataResp),
                'log'     => implode("\n", $this->debugLog)
            ];
        }

        // Build UTF-8 MIME headers
        $encodedSubject = "=?UTF-8?B?" . base64_encode($subject) . "?=";
        $encodedFromName = "=?UTF-8?B?" . base64_encode($fromName) . "?=";
        $encodedToName = $toName ? "=?UTF-8?B?" . base64_encode($toName) . "?= <{$to}>" : "<{$to}>";

        $headers = [];
        $headers[] = "Date: " . date('r');
        $headers[] = "From: {$encodedFromName} <{$fromEmail}>";
        $headers[] = "To: {$encodedToName}";
        $headers[] = "Subject: {$encodedSubject}";
        $headers[] = "Message-ID: <" . md5(uniqid(microtime(), true)) . "@{$host}>";
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-Type: text/html; charset=UTF-8";
        $headers[] = "Content-Transfer-Encoding: base64";
        $headers[] = "X-Mailer: BanglarServer-NativeMailer/2.0";

        $fullPayload = implode("\r\n", $headers) . "\r\n\r\n" . chunk_split(base64_encode($htmlBody)) . "\r\n.\r\n";
        
        $this->log("Sending email payload (" . strlen($fullPayload) . " bytes)...");
        fwrite($socket, $fullPayload);

        $sendResp = $this->readResponse($socket);
        $this->log("Payload response: " . trim($sendResp));

        $this->sendCommand($socket, "QUIT");
        $this->readResponse($socket);
        fclose($socket);

        $isSuccess = str_starts_with(trim($sendResp), '250');
        return [
            'success' => $isSuccess,
            'message' => $isSuccess ? 'Email sent successfully via SMTP' : 'Email transmission failed: ' . trim($sendResp),
            'log'     => implode("\n", $this->debugLog)
        ];
    }

    private function sendCommand($socket, string $cmd): void {
        fwrite($socket, $cmd . "\r\n");
    }

    private function readResponse($socket): string {
        $response = "";
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            // SMTP multiline response lines have '-' as fourth char, last line has space ' '
            if (strlen($line) >= 4 && substr($line, 3, 1) === ' ') {
                break;
            }
        }
        return $response;
    }

    // -------------------------------------------------------------
    // MASTER RESPONSIVE HTML EMAIL TEMPLATE WRAPPER
    // -------------------------------------------------------------
    public function wrapInTemplate(string $title, string $preheader, string $contentHtml): string {
        $logoUrl = $this->adminSettings['logo_url'] ?? 'assets/logo.png';
        
        // Convert relative logo URL to absolute if host available
        if (!preg_match('#^https?://#i', $logoUrl) && isset($_SERVER['HTTP_HOST'])) {
            $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
            $baseDir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
            $logoUrl = $protocol . $_SERVER['HTTP_HOST'] . $baseDir . '/' . ltrim($logoUrl, '/');
        }

        $year = date('Y');

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{$title}</title>
  <style>
    body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
    table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
    img { -ms-interpolation-mode: bicubic; border: 0; outline: none; text-decoration: none; }
    body { margin: 0; padding: 0; width: 100% !important; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0; }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
  <!-- Preheader text for inbox preview -->
  <span style="display:none;font-size:1px;color:#0b1120;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
    {$preheader}
  </span>

  <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0b1120; padding: 25px 15px;">
    <tr>
      <td align="center">
        <!-- Main Email Container (600px) -->
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #0f172a; border-radius: 14px; border: 1px solid #1e293b; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
          
          <!-- Brand Header -->
          <tr>
            <td style="padding: 24px 30px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-bottom: 2px solid #1F75FE; text-align: center;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td align="center">
                    <img src="{$logoUrl}" alt="Banglar Server" style="max-height: 48px; max-width: 260px; display: block; margin: 0 auto;" />
                    <div style="margin-top: 8px; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: #1F75FE;">
                      BANGLAR SERVER &bull; DOMAIN INTELLIGENCE
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Email Body Content -->
          <tr>
            <td style="padding: 32px 30px; color: #cbd5e1; font-size: 15px; line-height: 1.6;">
              {$contentHtml}
            </td>
          </tr>

          <!-- Footer Area -->
          <tr>
            <td style="padding: 24px 30px; background-color: #090d16; border-top: 1px solid #1e293b; text-align: center; color: #64748b; font-size: 12px; line-height: 1.6;">
              <p style="margin: 0 0 8px 0; color: #94a3b8; font-weight: 600;">
                Banglar Server &bull; Cloud Infrastructure &amp; Domain Watcher Engine
              </p>
              <p style="margin: 0 0 10px 0;">
                You are receiving this automated alert because a domain was submitted to the Banglar Server Watchlist.
              </p>
              <p style="margin: 0; font-size: 11px; color: #475569;">
                &copy; {$year} Banglar Server. All rights reserved. &bull; <a href="https://banglarserver.com" style="color: #1F75FE; text-decoration: none;">banglarserver.com</a>
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;
    }

    // -------------------------------------------------------------
    // -------------------------------------------------------------
    // Helper to replace standard template placeholders
    // -------------------------------------------------------------
    public function renderTemplateText(string $text, array $vars): string {
        $keys = array_map(function($k) { return '{' . $k . '}'; }, array_keys($vars));
        return str_replace($keys, array_values($vars), $text);
    }

    // -------------------------------------------------------------
    // 0. User Confirmation: Domain Added to Watchlist (Template: domain_added)
    // -------------------------------------------------------------
    public function sendWatchlistConfirmation(string $domain, string $userEmail, ?string $userName = null): array {
        $bookingBase = rtrim($this->adminSettings['booking_base_url'] ?? '', '=') . '=';
        $bookingUrl = $bookingBase . urlencode($domain);

        $tpl = getEmailTemplate('domain_added');
        if (isset($tpl['is_enabled']) && !$tpl['is_enabled']) {
            return ['success' => true, 'message' => 'Watchlist enrollment email template is disabled.', 'log' => ''];
        }

        $greeting = !empty($userName) ? "Hello " . htmlspecialchars($userName) . "," : "Hello,";
        $displayName = !empty($userName) ? $userName : 'Valued Customer';

        $vars = [
            'domain'      => $domain,
            'email'       => $userEmail,
            'name'        => $displayName,
            'date'        => date('Y-m-d H:i:s T'),
            'booking_url' => $bookingUrl
        ];

        $title = $this->renderTemplateText($tpl['subject'] ?? 'Domain {domain} Successfully Added to Banglar Server Watchlist', $vars);
        $preheader = "Your domain {$domain} has been added to the Banglar Server 24/7 automated drop watcher queue.";
        $headline = $this->renderTemplateText($tpl['headline'] ?? 'Watchlist Activated for {domain}', $vars);
        $bodyHtml = $this->renderTemplateText($tpl['body_html'] ?? '', $vars);
        $btnText = $this->renderTemplateText($tpl['button_text'] ?? 'Search on Banglar Server', $vars);
        $targetButtonUrl = !empty($tpl['button_url']) ? $this->renderTemplateText($tpl['button_url'], $vars) : $bookingUrl;

        $content = <<<HTML
<div style="text-align: center; margin-bottom: 24px;">
  <div style="display: inline-block; padding: 6px 14px; background-color: rgba(56, 189, 248, 0.15); border: 1px solid #38bdf8; border-radius: 9999px; color: #38bdf8; font-size: 12px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;">
    &bull; 24/7 Drop Monitoring Active
  </div>
  <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 16px 0 8px 0; letter-spacing: -0.5px;">
    {$headline}
  </h1>
  <p style="color: #94a3b8; font-size: 14px; margin: 0;">
    আপনার কাঙ্খিত ডোমেইনটি নজরদারির জন্য সফলভাবে তালিকাভুক্ত করা হয়েছে।
  </p>
</div>

<p style="color: #e2e8f0; font-size: 16px; font-weight: 600;">
  {$greeting}
</p>

{$bodyHtml}

<!-- Domain Detail Box -->
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 20px 0; overflow: hidden;">
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Target Domain:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 14px;">{$domain}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Current Registry Status:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155;">
      <span style="background-color: #f59e0b; color: #451a03; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase;">REGISTERED &bull; MONITORED</span>
    </td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; color: #94a3b8; font-size: 13px;">Enrolled On:</td>
    <td style="padding: 12px 18px; color: #e2e8f0; font-size: 13px;">{$vars['date']}</td>
  </tr>
</table>

<!-- Prominent Call To Action -->
<div style="text-align: center; margin: 32px 0 24px 0;">
  <a href="{$targetButtonUrl}" target="_blank" style="display: inline-block; background-color: #1F75FE; color: #ffffff; font-size: 15px; font-weight: 700; text-decoration: none; padding: 14px 34px; border-radius: 8px; box-shadow: 0 10px 15px -3px rgba(31, 117, 254, 0.4); letter-spacing: 0.3px;">
    {$btnText}
  </a>
</div>

<p style="font-size: 13px; color: #94a3b8; border-top: 1px solid #1e293b; padding-top: 16px; margin-top: 24px;">
  Thank you for choosing <strong>Banglar Server</strong>. Our automated system will alert you the moment this domain expires.
</p>
HTML;

        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);
        return $this->send($userEmail, $title, $fullHtml, $userName);
    }

    // -------------------------------------------------------------
    // 1. User Alert: Domain is Available Right Now (Template: domain_available)
    // -------------------------------------------------------------
    public function sendUserAvailableAlert(string $domain, string $userEmail, ?string $userName = null): array {
        $bookingBase = rtrim($this->adminSettings['booking_base_url'] ?? '', '=') . '=';
        $bookingUrl = $bookingBase . urlencode($domain);

        $tpl = getEmailTemplate('domain_available');
        if (isset($tpl['is_enabled']) && !$tpl['is_enabled']) {
            return ['success' => true, 'message' => 'Available domain notification email template is disabled.', 'log' => ''];
        }

        $greeting = !empty($userName) ? "Hello " . htmlspecialchars($userName) . "," : "Hello,";
        $displayName = !empty($userName) ? $userName : 'Valued Customer';

        $vars = [
            'domain'      => $domain,
            'email'       => $userEmail,
            'name'        => $displayName,
            'date'        => date('Y-m-d H:i:s T'),
            'booking_url' => $bookingUrl
        ];

        $title = $this->renderTemplateText($tpl['subject'] ?? '🔥 URGENT: {domain} is Available to Register Right Now!', $vars);
        $preheader = "Your watched domain {$domain} is available right now! Book it instantly on Banglar Server before someone else takes it.";
        $headline = $this->renderTemplateText($tpl['headline'] ?? 'Congratulations! {domain} is Available', $vars);
        $bodyHtml = $this->renderTemplateText($tpl['body_html'] ?? '', $vars);
        $btnText = $this->renderTemplateText($tpl['button_text'] ?? 'Claim & Book Domain Now', $vars);
        $targetButtonUrl = !empty($tpl['button_url']) ? $this->renderTemplateText($tpl['button_url'], $vars) : $bookingUrl;

        $content = <<<HTML
<div style="text-align: center; margin-bottom: 24px;">
  <div style="display: inline-block; padding: 6px 14px; background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 9999px; color: #10b981; font-size: 12px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;">
    &check; Domain Available Right Now
  </div>
  <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 16px 0 8px 0; letter-spacing: -0.5px;">
    {$headline}
  </h1>
  <p style="color: #94a3b8; font-size: 14px; margin: 0;">
    আপনার কাঙ্খিত ডোমেইনটি বর্তমানে উন্মুক্ত এবং রেজিস্ট্রেশনের জন্য প্রস্তুত!
  </p>
</div>

<p style="color: #e2e8f0; font-size: 16px; font-weight: 600;">
  {$greeting}
</p>

{$bodyHtml}

<!-- Domain Detail Box -->
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 20px 0; overflow: hidden;">
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Domain Name:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 14px;">{$domain}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Status:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155;">
      <span style="background-color: #10b981; color: #042f2e; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase;">AVAILABLE</span>
    </td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; color: #94a3b8; font-size: 13px;">Checked At:</td>
    <td style="padding: 12px 18px; color: #e2e8f0; font-size: 13px;">{$vars['date']}</td>
  </tr>
</table>

<!-- Prominent Call To Action -->
<div style="text-align: center; margin: 32px 0 24px 0;">
  <a href="{$targetButtonUrl}" target="_blank" style="display: inline-block; background-color: #10b981; color: #042f2e; font-size: 15px; font-weight: 700; text-decoration: none; padding: 14px 34px; border-radius: 8px; box-shadow: 0 10px 15px -3px rgba(16, 185, 129, 0.4); letter-spacing: 0.3px;">
    {$btnText}
  </a>
  <p style="margin-top: 10px; font-size: 12px; color: #64748b;">
    Instant automated WHMCS cart redirection. Register before another party claims it!
  </p>
</div>

<p style="font-size: 13px; color: #94a3b8; border-top: 1px solid #1e293b; padding-top: 16px; margin-top: 24px;">
  Thank you for choosing <strong>Banglar Server</strong>. If you need any assistance with DNS or web hosting setup, our technical support team is here 24/7.
</p>
HTML;

        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);
        return $this->send($userEmail, $title, $fullHtml, $userName);
    }

    // -------------------------------------------------------------
    // 2. Admin Lead Alert: Instant Notification of New Lead
    // -------------------------------------------------------------
    public function sendAdminLeadAlert(string $domain, string $userEmail, string $source, string $status, ?string $userName = null, ?string $userPhone = null): array {
        $adminEmail = $this->adminSettings['admin_email'] ?? 'admin@banglarserver.com';
        $bookingBase = rtrim($this->adminSettings['booking_base_url'] ?? '', '=') . '=';
        $bookingUrl = $bookingBase . urlencode($domain);

        $isAvail = ($status === 'available');
        $statusBadge = $isAvail
            ? '<span style="background-color: #10b981; color: #042f2e; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px;">AVAILABLE (HOT LEAD)</span>'
            : '<span style="background-color: #f59e0b; color: #451a03; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px;">REGISTERED (MONITORING)</span>';

        $title = $isAvail 
            ? "[HOT LEAD] User searched available domain: {$domain}" 
            : "[NEW WATCHLIST LEAD] User monitoring domain: {$domain}";

        $cleanPhone = $userPhone ? preg_replace('/[^\d+]/', '', $userPhone) : '';
        $waNum = ltrim($cleanPhone, '+');
        $waLink = "https://wa.me/{$waNum}";

        $nameRow = !empty($userName) ? <<<ROW
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Full Name:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 14px;">{$userName}</td>
  </tr>
ROW : '';

        $phoneRow = !empty($userPhone) ? <<<ROW
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Phone / WhatsApp:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #34d399; font-weight: 700; font-size: 14px;">
      <a href="tel:{$cleanPhone}" style="color: #34d399; text-decoration: none;">{$userPhone}</a>
      <a href="{$waLink}" target="_blank" style="display: inline-block; margin-left: 8px; background-color: #25D366; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-decoration: none; font-weight: bold;">WhatsApp &rarr;</a>
    </td>
  </tr>
ROW : '';

        $preheader = "New lead captured: " . ($userName ? "{$userName} " : "") . "({$userEmail}, {$userPhone}) is interested in {$domain} via {$source}.";

        $content = <<<HTML
<div style="margin-bottom: 20px;">
  <span style="font-size: 11px; font-weight: 700; color: #1F75FE; text-transform: uppercase; letter-spacing: 1px;">
    &bull; Admin Lead Notification
  </span>
  <h2 style="color: #ffffff; font-size: 20px; font-weight: 800; margin: 8px 0;">
    New Lead Captured: {$domain}
  </h2>
  <p style="color: #94a3b8; font-size: 14px; margin: 0;">
    A visitor just entered their contact details on your Banglar Server Domain Watcher platform.
  </p>
</div>

<!-- Lead Detail Table -->
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 20px 0; overflow: hidden;">
  {$nameRow}
  {$phoneRow}
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">User Email:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #38bdf8; font-weight: 700; font-size: 14px;">
      <a href="mailto:{$userEmail}" style="color: #38bdf8; text-decoration: none;">{$userEmail}</a>
    </td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Domain Name:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 14px;">{$domain}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">WHOIS Status:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155;">{$statusBadge}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Submission Source:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #cbd5e1; font-weight: 600; font-size: 13px;">{$source}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; color: #94a3b8; font-size: 13px;">Captured Timestamp:</td>
    <td style="padding: 12px 18px; color: #e2e8f0; font-size: 13px;">%DATE%</td>
  </tr>
</table>

<div style="text-align: center; margin: 28px 0 16px 0;">
  <a href="{$bookingUrl}" target="_blank" style="display: inline-block; background-color: #1F75FE; color: #ffffff; font-size: 14px; font-weight: 700; text-decoration: none; padding: 12px 26px; border-radius: 6px; box-shadow: 0 8px 12px -2px rgba(31, 117, 254, 0.4);">
    View Domain on Banglar Server
  </a>
HTML;

        $content = str_replace('%DATE%', date('Y-m-d H:i:s T'), $content);
        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);

        return $this->send($adminEmail, $title, $fullHtml);
    }

    // -------------------------------------------------------------
    // 3. Drop Alert: Domain Just Became Available (Drop Catching)
    // -------------------------------------------------------------
    public function sendDropAlert(string $domain, string $recipientEmail, bool $isAdmin = false, ?string $userName = null, ?string $userPhone = null, ?string $leadEmail = null): array {
        $bookingBase = rtrim($this->adminSettings['booking_base_url'] ?? '', '=') . '=';
        $bookingUrl = $bookingBase . urlencode($domain);

        $greeting = (!empty($userName) && !$isAdmin) ? "Hello " . htmlspecialchars($userName) . "," : "Hello,";

        $title = "🔥 URGENT DROP ALERT: {$domain} is Now Available to Register!";
        $preheader = "Drop Alert! The previously registered domain {$domain} has just expired and dropped. Register it immediately!";

        $leadBox = '';
        if ($isAdmin && (!empty($userName) || !empty($userPhone) || !empty($leadEmail))) {
            $nameCell = !empty($userName) ? "<tr><td style='padding: 10px 16px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;'>Lead Name:</td><td style='padding: 10px 16px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 13px;'>" . htmlspecialchars($userName) . "</td></tr>" : "";
            $emailCell = !empty($leadEmail) ? "<tr><td style='padding: 10px 16px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;'>Lead Email:</td><td style='padding: 10px 16px; border-bottom: 1px solid #334155; color: #38bdf8; font-weight: 700; font-size: 13px;'><a href='mailto:" . htmlspecialchars($leadEmail) . "' style='color: #38bdf8; text-decoration: none;'>" . htmlspecialchars($leadEmail) . "</a></td></tr>" : "";
            
            $phoneCell = '';
            if (!empty($userPhone)) {
                $cleanDigits = preg_replace('/[^0-9]/', '', $userPhone);
                $waLink = !empty($cleanDigits) ? " &bull; <a href='https://wa.me/{$cleanDigits}' target='_blank' style='color: #10b981; font-weight: 700; text-decoration: none;'>WhatsApp &rarr;</a>" : "";
                $phoneCell = "<tr><td style='padding: 10px 16px; color: #94a3b8; font-size: 13px;'>Lead Phone:</td><td style='padding: 10px 16px; color: #ffffff; font-weight: 700; font-size: 13px;'><a href='tel:" . htmlspecialchars($userPhone) . "' style='color: #ffffff; text-decoration: none;'>" . htmlspecialchars($userPhone) . "</a>{$waLink}</td></tr>";
            }

            $leadBox = <<<LEADHTML
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 18px 0; overflow: hidden;">
  <tr>
    <td colspan="2" style="padding: 10px 16px; background-color: #0f172a; border-bottom: 1px solid #334155; color: #38bdf8; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
      Lead Contact Details
    </td>
  </tr>
  {$nameCell}
  {$emailCell}
  {$phoneCell}
</table>
LEADHTML;
        }

        $roleNote = $isAdmin 
            ? "<p style='color: #38bdf8;'><strong>Admin Notice:</strong> A monitored domain on your watchlist just dropped. Contact the lead or register it now.</p>"
            : "<p style='color: #10b981;'><strong>Exclusive Drop Alert:</strong> {$greeting} The domain you asked us to monitor has finally dropped and is open for public registration!</p>";

        $content = <<<HTML
<div style="text-align: center; margin-bottom: 24px;">
  <div style="display: inline-block; padding: 6px 14px; background-color: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; border-radius: 9999px; color: #f87171; font-size: 12px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;">
    🔥 Instant Drop Detected
  </div>
  <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 16px 0 8px 0;">
    {$domain} Just Dropped!
  </h1>
  {$roleNote}
</div>

{$leadBox}

<p style="color: #cbd5e1; font-size: 15px;">
  Our 24/7 automated cron engine checked this domain and discovered that the registry status changed from <strong>REGISTERED</strong> to <strong>AVAILABLE</strong>!
</p>

<!-- Domain Box -->
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 20px 0; overflow: hidden;">
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">Target Domain:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #ffffff; font-weight: 700; font-size: 14px;">{$domain}</td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">New Status:</td>
    <td style="padding: 12px 18px; border-bottom: 1px solid #334155;">
      <span style="background-color: #10b981; color: #042f2e; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px;">AVAILABLE NOW</span>
    </td>
  </tr>
  <tr>
    <td style="padding: 12px 18px; color: #94a3b8; font-size: 13px;">Drop Time:</td>
    <td style="padding: 12px 18px; color: #e2e8f0; font-size: 13px;">%DATE%</td>
  </tr>
</table>

<!-- CTA Button -->
<div style="text-align: center; margin: 32px 0 24px 0;">
  <a href="{$bookingUrl}" target="_blank" style="display: inline-block; background-color: #10b981; color: #042f2e; font-size: 16px; font-weight: 800; text-decoration: none; padding: 14px 34px; border-radius: 8px; box-shadow: 0 10px 15px -3px rgba(16, 185, 129, 0.4); text-transform: uppercase;">
    &rarr; Claim &amp; Book {$domain} Now
  </a>
</div>
HTML;

        $content = str_replace('%DATE%', date('Y-m-d H:i:s T'), $content);
        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);

        return $this->send($recipientEmail, $title, $fullHtml, $userName);
    }

    // -------------------------------------------------------------
    // 4. Daily Full Admin Report with 4 KPI boxes and full table (Template: admin_daily_report)
    // -------------------------------------------------------------
    public function sendDailyReportEmail(array $stats, array $domains, string|array $adminEmails): array {
        $tpl = getEmailTemplate('admin_daily_report');
        if (isset($tpl['is_enabled']) && !$tpl['is_enabled']) {
            return ['success' => true, 'message' => 'Daily admin report email template is disabled.', 'log' => ''];
        }

        // Build Table Rows
        $tableRows = '';
        if (empty($domains)) {
            $tableRows = '<tr><td colspan="5" style="padding: 16px; text-align: center; color: #94a3b8;">No domains currently on the watchlist.</td></tr>';
        } else {
            foreach ($domains as $row) {
                $isAvail = ($row['status'] === 'available');
                $statusBadge = $isAvail 
                    ? '<span style="background-color: #10b981; color: #042f2e; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">AVAILABLE</span>'
                    : '<span style="background-color: #f59e0b; color: #451a03; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">REGISTERED</span>';

                $bookingBase = rtrim($this->adminSettings['booking_base_url'] ?? '', '=') . '=';
                $bookLink = $isAvail 
                    ? "<a href='{$bookingBase}" . urlencode($row['domain_name']) . "' target='_blank' style='color: #10b981; text-decoration: none; font-weight: 600;'>Book &rarr;</a>"
                    : "<span style='color: #64748b;'>Watching</span>";

                $lastChecked = !empty($row['last_checked']) ? date('M d, H:i', strtotime($row['last_checked'])) : 'Just now';
                $sourceLabel = htmlspecialchars($row['source_app'] ?? $row['added_by']);
                $domainName = htmlspecialchars($row['domain_name']);
                $userEmail = htmlspecialchars($row['user_email']);

                $tableRows .= <<<ROW
<tr style="border-bottom: 1px solid #1e293b;">
  <td style="padding: 10px 12px; color: #ffffff; font-weight: 600; font-size: 13px;">{$domainName}</td>
  <td style="padding: 10px 12px; color: #94a3b8; font-size: 12px;">{$sourceLabel}</td>
  <td style="padding: 10px 12px; color: #38bdf8; font-size: 12px;">{$userEmail}</td>
  <td style="padding: 10px 12px; text-align: center;">{$statusBadge}</td>
  <td style="padding: 10px 12px; font-size: 12px; text-align: right;">{$bookLink}</td>
</tr>
ROW;
            }
        }

        $vars = [
            'total_monitored'   => (string)($stats['total'] ?? 0),
            'newly_available'   => (string)($stats['newly_available'] ?? 0),
            'total_available'   => (string)($stats['available'] ?? 0),
            'still_registered'  => (string)($stats['registered'] ?? 0),
            'date'              => date('Y-m-d H:i:s T'),
            'date_short'        => date('Y-m-d')
        ];

        $title = $this->renderTemplateText($tpl['subject'] ?? '📊 Banglar Server Daily Watcher Report: {newly_available} Newly Available Domains ({date_short})', $vars);
        $preheader = "Daily Summary: {$stats['total']} total monitored domains, {$stats['newly_available']} newly available today.";
        $headline = $this->renderTemplateText($tpl['headline'] ?? 'Daily Domain Watcher Executive Summary', $vars);
        $bodyHtml = $this->renderTemplateText($tpl['body_html'] ?? '', $vars);
        $btnText = $this->renderTemplateText($tpl['button_text'] ?? 'Open Admin Watchlist', $vars);
        $targetButtonUrl = !empty($tpl['button_url']) ? $this->renderTemplateText($tpl['button_url'], $vars) : 'admin.php';

        $content = <<<HTML
<div style="margin-bottom: 24px;">
  <span style="font-size: 11px; font-weight: 700; color: #1F75FE; text-transform: uppercase; letter-spacing: 1px;">
    &bull; Automated Scheduled Report
  </span>
  <h2 style="color: #ffffff; font-size: 22px; font-weight: 800; margin: 8px 0;">
    {$headline}
  </h2>
  <p style="color: #94a3b8; font-size: 14px; margin: 0;">
    Scheduled automated daily check completed at {$vars['date']}.
  </p>
</div>

{$bodyHtml}

<!-- 4 KPI Summary Cards (2x2 Grid via table for email client compatibility) -->
<table border="0" cellpadding="0" cellspacing="6" width="100%" style="margin: 20px 0 24px 0;">
  <tr>
    <td width="50%" style="background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px;">
      <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase;">Total Monitored</div>
      <div style="font-size: 24px; font-weight: 800; color: #ffffff; margin-top: 4px;">{$stats['total']}</div>
    </td>
    <td width="50%" style="background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px;">
      <div style="font-size: 11px; font-weight: 700; color: #1F75FE; text-transform: uppercase;">Newly Available Today</div>
      <div style="font-size: 24px; font-weight: 800; color: #1F75FE; margin-top: 4px;">{$stats['newly_available']}</div>
    </td>
  </tr>
  <tr>
    <td width="50%" style="background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px;">
      <div style="font-size: 11px; font-weight: 700; color: #10b981; text-transform: uppercase;">Total Available</div>
      <div style="font-size: 24px; font-weight: 800; color: #10b981; margin-top: 4px;">{$stats['available']}</div>
    </td>
    <td width="50%" style="background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px;">
      <div style="font-size: 11px; font-weight: 700; color: #f59e0b; text-transform: uppercase;">Still Registered</div>
      <div style="font-size: 24px; font-weight: 800; color: #f59e0b; margin-top: 4px;">{$stats['registered']}</div>
    </td>
  </tr>
</table>

<!-- Full Monitored Domains Table -->
<h3 style="color: #ffffff; font-size: 16px; font-weight: 700; margin: 24px 0 12px 0;">
  Watched Domains Database
</h3>
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #111827; border-radius: 8px; border: 1px solid #1f2937; overflow: hidden; margin-bottom: 24px;">
  <thead>
    <tr style="background-color: #1e293b; border-bottom: 1px solid #334155;">
      <th style="padding: 10px 12px; text-align: left; color: #94a3b8; font-size: 11px; text-transform: uppercase;">Domain</th>
      <th style="padding: 10px 12px; text-align: left; color: #94a3b8; font-size: 11px; text-transform: uppercase;">Source</th>
      <th style="padding: 10px 12px; text-align: left; color: #94a3b8; font-size: 11px; text-transform: uppercase;">User Email</th>
      <th style="padding: 10px 12px; text-align: center; color: #94a3b8; font-size: 11px; text-transform: uppercase;">Status</th>
      <th style="padding: 10px 12px; text-align: right; color: #94a3b8; font-size: 11px; text-transform: uppercase;">Action</th>
    </tr>
  </thead>
  <tbody>
    {$tableRows}
  </tbody>
</table>

<!-- Action Button -->
<div style="text-align: center; margin: 28px 0 16px 0;">
  <a href="{$targetButtonUrl}" target="_blank" style="display: inline-block; background-color: #1F75FE; color: #ffffff; font-size: 15px; font-weight: 700; text-decoration: none; padding: 14px 34px; border-radius: 8px; box-shadow: 0 10px 15px -3px rgba(31, 117, 254, 0.4);">
    {$btnText}
  </a>
</div>
HTML;

        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);

        // Parse one or multiple admin recipient emails
        $recipientList = [];
        if (is_array($adminEmails)) {
            $rawList = $adminEmails;
        } else {
            $rawList = preg_split('/[\r\n,;\s]+/', (string)$adminEmails);
        }

        foreach ($rawList as $em) {
            $cleaned = trim($em);
            if (!empty($cleaned) && filter_var($cleaned, FILTER_VALIDATE_EMAIL)) {
                $recipientList[] = strtolower($cleaned);
            }
        }
        $recipientList = array_values(array_unique($recipientList));

        if (empty($recipientList)) {
            return ['success' => false, 'message' => 'No valid admin recipient email addresses provided.', 'log' => ''];
        }

        $successCount = 0;
        $failedEmails = [];
        $logs = [];

        foreach ($recipientList as $targetEmail) {
            $res = $this->send($targetEmail, $title, $fullHtml, 'Administrator');
            if ($res['success']) {
                $successCount++;
            } else {
                $failedEmails[] = $targetEmail;
            }
            $logs[] = "[{$targetEmail}] " . ($res['success'] ? 'SENT' : 'FAILED: ' . $res['message']);
        }

        $allOk = ($successCount > 0);
        $summary = "Dispatched to {$successCount} of " . count($recipientList) . " recipient(s) (" . implode(', ', $recipientList) . ")";
        if (!empty($failedEmails)) {
            $summary .= " | Failed for: " . implode(', ', $failedEmails);
        }

        return [
            'success'    => $allOk,
            'message'    => $summary,
            'log'        => implode("\n", $logs),
            'count'      => $successCount,
            'recipients' => $recipientList
        ];
    }

    // -------------------------------------------------------------
    // 5. Test SMTP Email
    // -------------------------------------------------------------
    public function sendTestEmail(string $recipientEmail): array {
        $title = "Test Verification Email - Banglar Server SMTP Engine";
        $preheader = "Your SMTP configuration on Banglar Server is active and operational.";

        $content = <<<HTML
<div style="text-align: center; margin-bottom: 20px;">
  <div style="display: inline-block; padding: 6px 14px; background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 9999px; color: #10b981; font-size: 12px; font-weight: 700; text-transform: uppercase;">
    &check; SMTP Connection Verified
  </div>
  <h2 style="color: #ffffff; font-size: 22px; font-weight: 800; margin: 16px 0 8px 0;">
    Socket SMTP Connection Successful!
  </h2>
  <p style="color: #94a3b8; font-size: 14px; margin: 0;">
    This is a live test email dispatched via Banglar Server standalone socket mailer.
  </p>
</div>

<p style="color: #cbd5e1; font-size: 15px;">
  Congratulations! If you can see this email formatted with dark mode accents, emerald badges, and logo, your SMTP host, port, credentials, and UTF-8 encoding are correctly set up.
</p>

<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; margin: 20px 0;">
  <tr>
    <td style="padding: 10px 16px; color: #94a3b8; font-size: 13px; border-bottom: 1px solid #334155;">Test Timestamp:</td>
    <td style="padding: 10px 16px; color: #ffffff; font-weight: 600; font-size: 13px; border-bottom: 1px solid #334155;">%DATE%</td>
  </tr>
  <tr>
    <td style="padding: 10px 16px; color: #94a3b8; font-size: 13px;">Recipient:</td>
    <td style="padding: 10px 16px; color: #10b981; font-weight: 600; font-size: 13px;">{$recipientEmail}</td>
  </tr>
</table>
HTML;

        $content = str_replace('%DATE%', date('Y-m-d H:i:s T'), $content);
        $fullHtml = $this->wrapInTemplate($title, $preheader, $content);

        return $this->send($recipientEmail, $title, $fullHtml);
    }
}
