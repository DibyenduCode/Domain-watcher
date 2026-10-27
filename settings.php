<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Admin Profile, Branding, Schedule & SMTP Configuration
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/smtp_mailer.php';
requireAdminAuth();

$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$smtpSettings  = getSmtpSettings($pdo);
$logoUrl = !empty($adminSettings['logo_url']) ? $adminSettings['logo_url'] : 'assets/logo.png';

$flashMessage = $_SESSION['bs_flash_message'] ?? null;
unset($_SESSION['bs_flash_message']);

$testEmailLog = null;
$testEmailStatus = null;

// Determine absolute cron URL
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$baseDir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
$cronUrl = $protocol . $host . $baseDir . '/cron.php?token=' . urlencode($adminSettings['cron_token']);
$serverScriptPath = __DIR__ . DIRECTORY_SEPARATOR . 'cron.php';

// -------------------------------------------------------------
// POST Handlers (Protected with CSRF verification)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid or expired CSRF token). Please refresh and try again.'];
        header("Location: settings.php?tab=" . urlencode($activeTab));
        exit;
    }
}

// 1. Update Profile & Security
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $username = trim($_POST['username'] ?? '');
    $adminEmail = trim($_POST['admin_email'] ?? '');
    $rawDailyEmails = trim($_POST['daily_report_emails'] ?? '');
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    // Validate and clean additional daily report emails
    $cleanedDailyEmails = [];
    if (!empty($rawDailyEmails)) {
        $parts = preg_split('/[\r\n,;\s]+/', $rawDailyEmails);
        foreach ($parts as $p) {
            $p = trim($p);
            if (!empty($p)) {
                if (!filter_var($p, FILTER_VALIDATE_EMAIL)) {
                    $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => "Invalid email address format in daily report list: {$p}"];
                    header("Location: settings.php?tab=profile");
                    exit;
                }
                $cleanedDailyEmails[] = strtolower($p);
            }
        }
    }
    $finalDailyEmails = !empty($cleanedDailyEmails) ? implode(', ', array_unique($cleanedDailyEmails)) : null;

    if (empty($username) || empty($adminEmail)) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Username and Admin Email cannot be empty.'];
    } elseif (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Please provide a valid primary Admin Email address.'];
    } else {
        if (!empty($newPassword)) {
            if ($newPassword !== $confirmPassword) {
                $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'New passwords do not match.'];
            } else {
                $hash = password_hash($newPassword, PASSWORD_BCRYPT);
                $stmt = $pdo->prepare("UPDATE `admins` SET `username` = ?, `admin_email` = ?, `daily_report_emails` = ?, `password_hash` = ? WHERE `id` = ?");
                $stmt->execute([$username, $adminEmail, $finalDailyEmails, $hash, $adminSettings['id']]);
                $_SESSION['bs_admin_user'] = $username;
                $_SESSION['bs_admin_email'] = $adminEmail;
                $_SESSION['bs_flash_message'] = ['type' => 'success', 'text' => 'Profile and daily report recipient emails updated successfully!'];
            }
        } else {
            $stmt = $pdo->prepare("UPDATE `admins` SET `username` = ?, `admin_email` = ?, `daily_report_emails` = ? WHERE `id` = ?");
            $stmt->execute([$username, $adminEmail, $finalDailyEmails, $adminSettings['id']]);
            $_SESSION['bs_admin_user'] = $username;
            $_SESSION['bs_admin_email'] = $adminEmail;
            $_SESSION['bs_flash_message'] = ['type' => 'success', 'text' => 'Profile and daily report recipient emails updated successfully!'];
        }
    }
    header("Location: settings.php?tab=profile");
    exit;
}

// 2. Update Branding & Schedule Settings
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_branding_schedule'])) {
    $logoInput = trim($_POST['logo_url'] ?? 'assets/logo.png');
    $bookingUrlInput = trim($_POST['booking_base_url'] ?? '');
    $dailyTimeInput = trim($_POST['daily_report_time'] ?? '09:00:00');
    $rawDailyEmails = trim($_POST['daily_report_emails'] ?? '');
    $regenerateToken = isset($_POST['regenerate_cron_token']);

    $cronToken = $adminSettings['cron_token'];
    if ($regenerateToken) {
        $cronToken = 'bs_cron_' . bin2hex(random_bytes(12));
    }

    $cleanedDailyEmails = [];
    if (!empty($rawDailyEmails)) {
        $parts = preg_split('/[\r\n,;\s]+/', $rawDailyEmails);
        foreach ($parts as $p) {
            $p = trim($p);
            if (!empty($p)) {
                if (!filter_var($p, FILTER_VALIDATE_EMAIL)) {
                    $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => "Invalid email address format in daily report list: {$p}"];
                    header("Location: settings.php?tab=branding");
                    exit;
                }
                $cleanedDailyEmails[] = strtolower($p);
            }
        }
    }
    $finalDailyEmails = !empty($cleanedDailyEmails) ? implode(', ', array_unique($cleanedDailyEmails)) : null;

    $stmt = $pdo->prepare("
        UPDATE `admins` 
        SET `logo_url` = ?,
            `booking_base_url` = ?,
            `daily_report_time` = ?,
            `daily_report_emails` = ?,
            `cron_token` = ?
        WHERE `id` = ?
    ");
    $stmt->execute([$logoInput, $bookingUrlInput, $dailyTimeInput, $finalDailyEmails, $cronToken, $adminSettings['id']]);

    $_SESSION['bs_flash_message'] = ['type' => 'success', 'text' => 'Branding, Schedule, and Daily Report recipients updated successfully!'];
    header("Location: settings.php?tab=branding");
    exit;
}

// 3. Update SMTP Settings
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_smtp'])) {
    $host   = trim($_POST['smtp_host'] ?? '');
    $port   = (int)($_POST['smtp_port'] ?? 587);
    $user   = trim($_POST['smtp_user'] ?? '');
    $pass   = $_POST['smtp_pass'] ?? '';
    $secure = trim($_POST['smtp_secure'] ?? 'tls');
    $fromEmail = trim($_POST['from_email'] ?? '');
    $fromName  = trim($_POST['from_name'] ?? 'Banglar Server');

    // If password left blank, preserve existing
    if ($pass === '') {
        $pass = $smtpSettings['smtp_pass'] ?? '';
    }

    $stmt = $pdo->prepare("
        UPDATE `smtp_settings`
        SET `smtp_host` = ?,
            `smtp_port` = ?,
            `smtp_user` = ?,
            `smtp_pass` = ?,
            `smtp_secure` = ?,
            `from_email` = ?,
            `from_name` = ?
        WHERE `id` = ?
    ");
    $stmt->execute([$host, $port, $user, $pass, $secure, $fromEmail, $fromName, $smtpSettings['id']]);

    $_SESSION['bs_flash_message'] = ['type' => 'success', 'text' => 'SMTP Configuration saved successfully!'];
    header("Location: settings.php?tab=smtp");
    exit;
}

// 4. Send Test Email
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_test_email'])) {
    $testRecipient = trim($_POST['test_recipient'] ?? $adminSettings['admin_email']);
    
    // Refresh settings from DB
    $currentSmtp = getSmtpSettings($pdo);
    $currentAdmin = getAdminSettings($pdo);

    $mailer = new BanglarSmtpMailer($currentSmtp, $currentAdmin);
    $result = $mailer->sendTestEmail($testRecipient);

    $testEmailStatus = $result['success'];
    $testEmailLog = $result;
}

// 5. Save Email Template
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_email_template'])) {
    $tplKey = trim($_POST['template_key'] ?? '');
    $subject = trim($_POST['subject'] ?? '');
    $headline = trim($_POST['headline'] ?? '');
    $buttonText = trim($_POST['button_text'] ?? 'Search on Banglar Server');
    $buttonUrl = trim($_POST['button_url'] ?? 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}');
    $bodyHtml = trim($_POST['body_html'] ?? '');
    $isEnabled = isset($_POST['is_enabled']) ? 1 : 0;

    if (in_array($tplKey, ['domain_added', 'domain_available', 'admin_daily_report']) && !empty($subject)) {
        $stmt = $pdo->prepare("
            UPDATE `email_templates`
            SET `subject` = ?,
                `headline` = ?,
                `button_text` = ?,
                `button_url` = ?,
                `body_html` = ?,
                `is_enabled` = ?
            WHERE `template_key` = ?
        ");
        $stmt->execute([$subject, $headline, $buttonText, $buttonUrl, $bodyHtml, $isEnabled, $tplKey]);

        $_SESSION['bs_flash_message'] = [
            'type' => 'success',
            'text' => 'Email template updated successfully!'
        ];
    } else {
        $_SESSION['bs_flash_message'] = [
            'type' => 'error',
            'text' => 'Please provide at least a Subject line and Headline.'
        ];
    }
    header("Location: settings.php?tab=templates&tpl=" . urlencode($tplKey));
    exit;
}

// 6. Test Send Email Template to Admin
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_email_template'])) {
    $tplKey = trim($_POST['template_key'] ?? 'domain_available');
    $adminEmail = $adminSettings['admin_email'];
    $mailer = new BanglarSmtpMailer(getSmtpSettings($pdo), getAdminSettings($pdo));

    if ($tplKey === 'domain_added') {
        $result = $mailer->sendWatchlistConfirmation('mytestbrand.com', $adminEmail, 'Admin Preview');
    } elseif ($tplKey === 'domain_available') {
        $result = $mailer->sendUserAvailableAlert('mytestbrand.com', $adminEmail, 'Admin Preview');
    } else {
        $sampleStats = ['total' => 12, 'newly_available' => 3, 'available' => 5, 'registered' => 7];
        $sampleDomains = [
            ['domain_name' => 'supercoolbrand.com', 'source_app' => 'Public Watcher', 'user_email' => 'client1@gmail.com', 'status' => 'available', 'last_checked' => date('Y-m-d H:i:s')],
            ['domain_name' => 'banglarstartup.net', 'source_app' => 'API Key #1', 'user_email' => 'ceo@banglarstartup.net', 'status' => 'available', 'last_checked' => date('Y-m-d H:i:s')],
            ['domain_name' => 'dhakahosting.org', 'source_app' => 'Admin Manual', 'user_email' => 'admin@banglarserver.com', 'status' => 'registered', 'last_checked' => date('Y-m-d H:i:s')]
        ];
        $result = $mailer->sendDailyReportEmail($sampleStats, $sampleDomains, $adminEmail);
    }

    $testEmailStatus = $result['success'];
    $testEmailLog = $result;
}

// 7. Reset Email Template to Default
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_email_template'])) {
    $tplKey = trim($_POST['template_key'] ?? '');
    $defaults = [
        'domain_added' => [
            'subject'     => 'Domain {domain} Successfully Added to Banglar Server Watchlist',
            'headline'    => 'Watchlist Activated for {domain}',
            'body_html'   => '<p style="color: #cbd5e1; font-size: 15px;">Thank you for choosing <strong>Banglar Server Domain Watcher</strong>. We have successfully enrolled your target domain into our 24/7 automated monitoring system.</p><p style="color: #cbd5e1; font-size: 15px;">Our engine monitors registry WHOIS servers continuously. The moment <strong><span style="color: #10b981;">{domain}</span></strong> expires and drops into availability, we will dispatch an instant notification to <strong>{email}</strong> so you can claim it immediately!</p>',
            'button_text' => 'View on Banglar Server',
            'button_url'  => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}'
        ],
        'domain_available' => [
            'subject'     => '🔥 URGENT: {domain} is Available to Register Right Now!',
            'headline'    => 'Congratulations! {domain} is Available',
            'body_html'   => '<p style="color: #cbd5e1; font-size: 15px;">Great news! We just verified domain <strong><span style="color: #10b981;">{domain}</span></strong> via registry lookup, and it is <strong>100% available for immediate purchase</strong>.</p><p style="color: #cbd5e1; font-size: 15px;">Domain names are registered on a first-come, first-served basis. Secure it right now through Banglar Server before someone else claims it!</p>',
            'button_text' => 'Claim & Book Domain Now',
            'button_url'  => 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}'
        ],
        'admin_daily_report' => [
            'subject'     => '📊 Banglar Server Daily Watcher Report: {newly_available} Newly Available Domains ({date_short})',
            'headline'    => 'Daily Domain Watcher Executive Summary',
            'body_html'   => '<p style="color: #cbd5e1; font-size: 15px;">Here is your scheduled daily executive summary of all monitored domains. Our automated WHOIS engine checked all watchlist targets.</p><p style="color: #cbd5e1; font-size: 15px;">Today we detected <strong><span style="color: #10b981;">{newly_available} newly available</span></strong> domain(s) ready for registration. Check the breakdown and full domain database below.</p>',
            'button_text' => 'Open Admin Watchlist',
            'button_url'  => 'admin.php'
        ]
    ];

    if (isset($defaults[$tplKey])) {
        $d = $defaults[$tplKey];
        $stmt = $pdo->prepare("
            UPDATE `email_templates`
            SET `subject` = ?,
                `headline` = ?,
                `button_text` = ?,
                `button_url` = ?,
                `body_html` = ?,
                `is_enabled` = 1
            WHERE `template_key` = ?
        ");
        $stmt->execute([$d['subject'], $d['headline'], $d['button_text'], $d['button_url'], $d['body_html'], $tplKey]);

        $_SESSION['bs_flash_message'] = [
            'type' => 'success',
            'text' => 'Email template reset to default Banglar Server copy.'
        ];
    }
    header("Location: settings.php?tab=templates&tpl=" . urlencode($tplKey));
    exit;
}

$activeTab = $_GET['tab'] ?? 'profile';
$allTemplates = getEmailTemplates($pdo);
$selectedTplKey = $_GET['tpl'] ?? 'domain_added';
if (!isset($allTemplates[$selectedTplKey])) {
    $selectedTplKey = 'domain_added';
}
$currentTpl = $allTemplates[$selectedTplKey];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Settings &amp; SMTP - Banglar Server Admin</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#eff6ff',
              100: '#dbeafe',
              200: '#bfdbfe',
              300: '#93c5fd',
              400: '#5296fe',
              500: '#1F75FE',
              600: '#1664e8',
              700: '#1350bc',
              800: '#103f96',
              900: '#0e3478',
              950: '#081c44'
            }
          }
        }
      }
    }
  </script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
    code, pre { font-family: 'JetBrains Mono', monospace; }
    header, header a, header span, header button, header nav {
      white-space: nowrap !important;
    }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-blue-600 selection:text-white">

  <!-- Admin Navigation Bar -->
  <header class="border-b border-slate-800 bg-slate-900 sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between gap-3 lg:gap-6 flex-nowrap">
      
      <!-- Brand Logo -->
      <div class="flex items-center gap-3 shrink-0">
        <a href="admin.php" class="flex items-center gap-3 shrink-0">
          <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-9 sm:h-11 w-auto object-contain drop-shadow-sm shrink-0" onerror="this.onerror=null; this.src='assets/logo.png';" />
        </a>
        <span class="hidden sm:inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase tracking-wider shrink-0" style="white-space: nowrap !important;">
          System Settings
        </span>
      </div>

      <!-- Navigation Tabs -->
      <nav class="hidden md:flex items-center gap-1 lg:gap-2 shrink-0">
        <a href="admin.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-list-check text-blue-400"></i> <span>Watchlist</span>
        </a>
        <a href="api_manager.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-key text-amber-400"></i> <span>REST API Keys</span>
        </a>
        <a href="settings.php?tab=templates" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium <?= $activeTab === 'templates' ? 'bg-slate-800 text-purple-400 border border-slate-700' : 'text-slate-300 hover:text-white hover:bg-slate-800' ?> shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-envelope-open-text text-purple-400"></i> <span>Email Templates</span>
        </a>
        <a href="settings.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-semibold <?= $activeTab !== 'templates' ? 'bg-slate-800 text-blue-400 border border-blue-500/30' : 'text-slate-300 hover:text-white hover:bg-slate-800' ?> shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-sliders text-teal-400"></i> <span>Settings &amp; SMTP</span>
        </a>
      </nav>

      <!-- Action items -->
      <div class="flex items-center gap-2 sm:gap-3 shrink-0">
        <a href="cron.php?manual=1" target="_blank" class="inline-flex items-center gap-2 px-3 lg:px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 shrink-0" style="white-space: nowrap !important;">
          <i class="fa-solid fa-bolt"></i>
          <span class="hidden 2xl:inline">Run Check &amp; Send Report</span>
          <span class="inline 2xl:hidden">Run Check</span>
        </a>
        <a href="admin.php?action=logout" class="p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors shrink-0" title="Log Out">
          <i class="fa-solid fa-right-from-bracket text-base"></i>
        </a>
      </div>

    </div>

    <!-- Mobile Nav Bar -->
    <div class="md:hidden flex items-center justify-around border-t border-slate-800 py-2.5 px-4 bg-slate-900/90 text-xs">
      <a href="admin.php" class="text-slate-400 hover:text-white flex items-center gap-1">
        <i class="fa-solid fa-list-check"></i> Watchlist
      </a>
      <a href="api_manager.php" class="text-slate-400 hover:text-white flex items-center gap-1">
        <i class="fa-solid fa-key"></i> API Keys
      </a>
      <a href="settings.php?tab=templates" class="<?= $activeTab === 'templates' ? 'text-purple-400 font-bold' : 'text-slate-400 hover:text-white' ?> flex items-center gap-1">
        <i class="fa-solid fa-envelope-open-text"></i> Templates
      </a>
      <a href="settings.php" class="<?= $activeTab !== 'templates' ? 'text-blue-400 font-bold' : 'text-slate-400 hover:text-white' ?> flex items-center gap-1">
        <i class="fa-solid fa-sliders"></i> Settings
      </a>
      <a href="index.php" target="_blank" class="text-slate-400 hover:text-white flex items-center gap-1">
        <i class="fa-solid fa-arrow-up-right-from-square"></i> Public
      </a>
    </div>
  </header>

  <!-- Main Content -->
  <main class="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 space-y-8">
    
    <!-- Flash Alert -->
    <?php if ($flashMessage): ?>
      <div class="p-4 rounded-xl <?= $flashMessage['type'] === 'success' ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-200' : 'bg-rose-950/60 border-rose-500/40 text-rose-200' ?> border text-sm flex items-center justify-between">
        <div class="flex items-center gap-3">
          <i class="fa-solid <?= $flashMessage['type'] === 'success' ? 'fa-circle-check text-emerald-400' : 'fa-circle-exclamation text-rose-400' ?> text-lg"></i>
          <span><?= e($flashMessage['text']) ?></span>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white">&times;</button>
      </div>
    <?php endif; ?>

    <!-- Test Email Result Banner (if triggered) -->
    <?php if ($testEmailLog): ?>
      <div class="p-6 rounded-2xl <?= $testEmailStatus ? 'bg-emerald-950/60 border-emerald-500/50' : 'bg-rose-950/60 border-rose-500/50' ?> border shadow-2xl space-y-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl <?= $testEmailStatus ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400' ?> flex items-center justify-center text-xl">
              <i class="fa-solid <?= $testEmailStatus ? 'fa-check-double' : 'fa-triangle-exclamation' ?>"></i>
            </div>
            <div>
              <h3 class="font-bold text-white text-base">
                <?= $testEmailStatus ? 'SMTP Test Email Successfully Sent!' : 'SMTP Test Email Failed to Deliver' ?>
              </h3>
              <p class="text-xs text-slate-300"><?= e($testEmailLog['message']) ?></p>
            </div>
          </div>
          <span class="px-3 py-1 rounded-full text-xs font-bold <?= $testEmailStatus ? 'bg-emerald-500 text-slate-950' : 'bg-rose-500 text-white' ?> uppercase">
            <?= $testEmailStatus ? 'SUCCESS' : 'FAILED' ?>
          </span>
        </div>

        <?php if (!empty($testEmailLog['log'])): ?>
          <details class="text-xs pt-2">
            <summary class="cursor-pointer text-slate-400 hover:text-white font-semibold">View Socket SMTP Connection Trace Log</summary>
            <pre class="mt-2 bg-slate-950/90 border border-slate-800 p-4 rounded-xl text-slate-300 font-mono overflow-x-auto text-[11px] leading-relaxed"><?= e($testEmailLog['log']) ?></pre>
          </details>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <!-- Settings Tabs Navigation -->
    <div class="flex border-b border-slate-800 gap-2 sm:gap-6 text-sm font-semibold overflow-x-auto">
      <a href="settings.php?tab=profile" class="pb-3 border-b-2 flex items-center gap-2 <?= $activeTab === 'profile' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200' ?>">
        <i class="fa-solid fa-user-shield"></i> Admin Profile &amp; Security
      </a>
      <a href="settings.php?tab=branding" class="pb-3 border-b-2 flex items-center gap-2 <?= $activeTab === 'branding' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200' ?>">
        <i class="fa-solid fa-palette"></i> Branding &amp; Schedule
      </a>
      <a href="settings.php?tab=templates" class="pb-3 border-b-2 flex items-center gap-2 <?= $activeTab === 'templates' ? 'border-purple-400 text-purple-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200' ?>">
        <i class="fa-solid fa-envelope-open-text text-purple-400"></i> Email Templates
      </a>
      <a href="settings.php?tab=smtp" class="pb-3 border-b-2 flex items-center gap-2 <?= $activeTab === 'smtp' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200' ?>">
        <i class="fa-solid fa-envelope-circle-check"></i> SMTP Mailer &amp; Diagnostics
      </a>
    </div>

    <!-- TAB 1: Profile & Security -->
    <?php if ($activeTab === 'profile'): ?>
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 max-w-2xl">
        <h2 class="text-xl font-bold text-white mb-2">Admin Profile &amp; Security</h2>
        <p class="text-xs text-slate-400 mb-6">Manage login credentials and notification recipient email address.</p>

        <form action="settings.php?tab=profile" method="POST" class="space-y-5">
          <input type="hidden" name="update_profile" value="1">
          <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">

          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Username</label>
            <input type="text" name="username" value="<?= e($adminSettings['username']) ?>" required
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
          </div>

          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
              Primary Admin Notification Email ID
            </label>
            <input type="email" name="admin_email" value="<?= e($adminSettings['admin_email']) ?>" required
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
            <p class="mt-1.5 text-xs text-slate-400">Receives instant hot lead alerts, drop alerts, and daily full reports.</p>
          </div>

          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center justify-between">
              <span class="flex items-center gap-1.5">
                <i class="fa-solid fa-users text-blue-400"></i> Additional Daily Report Recipients (Multiple Admin Emails)
              </span>
              <span class="text-[11px] font-normal text-slate-400">Comma or newline separated</span>
            </label>
            <textarea name="daily_report_emails" rows="3" placeholder="admin2@banglarserver.com, ops@banglarserver.com, director@banglarserver.com"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono leading-relaxed"><?= e($adminSettings['daily_report_emails'] ?? '') ?></textarea>
            <p class="mt-1.5 text-xs text-slate-400">
              <i class="fa-solid fa-circle-info text-blue-400 mr-1"></i> Enter multiple emails to receive the scheduled daily report. Every listed admin will receive the full executive domain report.
            </p>
          </div>

          <div class="pt-4 border-t border-slate-800">
            <h3 class="text-sm font-bold text-white mb-3">Change Password (leave blank to keep current)</h3>
            
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">New Password</label>
                <input type="password" name="new_password" autocomplete="new-password"
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
              </div>
              <div>
                <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Confirm New Password</label>
                <input type="password" name="confirm_password" autocomplete="new-password"
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
              </div>
            </div>
          </div>

          <div class="pt-4 flex justify-end">
            <button type="submit" class="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
              Save Profile Changes
            </button>
          </div>
        </form>
      </div>
    <?php endif; ?>

    <!-- TAB 2: Branding & Schedule Settings -->
    <?php if ($activeTab === 'branding'): ?>
      <div class="space-y-8">
        
        <!-- Branding Form -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8">
          <h2 class="text-xl font-bold text-white mb-2">Branding &amp; Automated Schedule</h2>
          <p class="text-xs text-slate-400 mb-6">Configure custom logo placement, WHMCS cart redirect URL, and daily check execution time.</p>

          <form action="settings.php?tab=branding" method="POST" class="space-y-6">
            <input type="hidden" name="update_branding_schedule" value="1">
            <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              <!-- Logo URL & Live Visibility Test Bench -->
              <div class="md:col-span-2 bg-slate-950/70 border border-slate-800 rounded-2xl p-5 space-y-4">
                <div>
                  <label class="block text-xs font-bold text-slate-200 uppercase tracking-wider mb-2 flex items-center justify-between">
                    <span class="flex items-center gap-1.5">
                      <i class="fa-solid fa-image text-blue-400"></i> Dynamic Brand Logo URL &amp; File
                    </span>
                    <span class="text-[11px] font-normal text-blue-400">Public Navbar &bull; Admin Portal &bull; HTML Emails</span>
                  </label>
                  <input type="text" id="logoUrlInput" name="logo_url" value="<?= e($adminSettings['logo_url']) ?>" required
                    class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
                  <p class="mt-1.5 text-xs text-slate-400">Default: <code class="text-blue-400 font-semibold">assets/logo.png</code>. Enter local relative path (e.g. assets/logo.png) or full external HTTPS URL.</p>
                </div>

                <!-- Live Brand Logo Visibility Test Bench -->
                <div class="pt-3 border-t border-slate-800">
                  <div class="flex items-center justify-between mb-3">
                    <span class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                      <i class="fa-solid fa-eye text-blue-400"></i> Logo Visual Visibility &amp; Contrast Check
                    </span>
                    <span class="text-[11px] text-slate-400">Renders live on both dark and light contexts</span>
                  </div>

                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <!-- Dark Background Context (Navbar / Portal) -->
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 text-center">
                      <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Dark Theme Context (Navbar &amp; Portal)</div>
                      <div class="h-16 flex items-center justify-center bg-slate-950 rounded-lg p-2 border border-slate-800">
                        <img id="liveLogoDark" src="<?= e($logoUrl) ?>" alt="Banglar Server" class="max-h-12 w-auto object-contain drop-shadow-sm" onerror="this.src='assets/logo.png';" />
                      </div>
                      <div class="text-[10px] text-emerald-400 font-semibold mt-2 flex items-center justify-center gap-1">
                        <i class="fa-solid fa-circle-check"></i> High Contrast on Dark Backgrounds
                      </div>
                    </div>

                    <!-- Light Background Context (Standard Inboxes) -->
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 text-center">
                      <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Light Email Context (Standard Canvas)</div>
                      <div class="h-16 flex items-center justify-center bg-white rounded-lg p-2 border border-slate-300">
                        <img id="liveLogoLight" src="<?= e($logoUrl) ?>" alt="Banglar Server" class="max-h-12 w-auto object-contain" onerror="this.src='assets/logo_original.png';" />
                      </div>
                      <div class="text-[10px] text-slate-400 font-semibold mt-2 flex items-center justify-center gap-1">
                        <i class="fa-solid fa-info-circle text-blue-400"></i> Light Mode Compatibility
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Booking Base URL -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Booking Base URL (WHMCS / Cart Link)
                </label>
                <input type="url" name="booking_base_url" value="<?= e($adminSettings['booking_base_url']) ?>" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
                <p class="mt-1.5 text-xs text-slate-400">The domain name will be automatically appended (e.g., <code class="text-blue-400">?query=example.com</code>).</p>
              </div>

              <!-- Daily Report Time -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Daily Check &amp; Full Report Time
                </label>
                <input type="time" step="1" name="daily_report_time" value="<?= e($adminSettings['daily_report_time']) ?>" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
                <p class="mt-1.5 text-xs text-slate-400">Scheduled time (24-hour format) when daily checks run and summary email is sent.</p>
              </div>

              <!-- Multiple Daily Report Recipients -->
              <div class="md:col-span-2">
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center justify-between">
                  <span class="flex items-center gap-1.5">
                    <i class="fa-solid fa-envelopes-bulk text-blue-400"></i> Multiple Daily Report Recipients (Admin Emails)
                  </span>
                  <span class="text-[11px] font-normal text-slate-400">Comma, space, or newline separated</span>
                </label>
                <textarea name="daily_report_emails" rows="2" placeholder="ops@banglarserver.com, ceo@banglarserver.com, management@banglarserver.com"
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono leading-relaxed"><?= e($adminSettings['daily_report_emails'] ?? '') ?></textarea>
                <p class="mt-1.5 text-xs text-slate-400">
                  <i class="fa-solid fa-circle-info text-blue-400 mr-1"></i> Enter multiple email addresses. The daily automated full report will be delivered to each listed admin recipient alongside the primary admin (<strong class="text-white"><?= e($adminSettings['admin_email']) ?></strong>).
                </p>
              </div>

              <!-- Secret Cron Token -->
              <div class="md:col-span-2">
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Secret Cron Security Token
                </label>
                <div class="flex items-center gap-3">
                  <input type="text" readonly value="<?= e($adminSettings['cron_token']) ?>"
                    class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-slate-400 font-mono text-sm cursor-not-allowed">
                  <label class="inline-flex items-center gap-1.5 text-xs text-amber-400 shrink-0 cursor-pointer">
                    <input type="checkbox" name="regenerate_cron_token" value="1" class="rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-blue-500">
                    Regenerate
                  </label>
                </div>
                <p class="mt-1.5 text-xs text-slate-400">Protects your cron URL from unauthorized public execution.</p>
              </div>

            </div>

            <div class="pt-4 flex justify-end">
              <button type="submit" class="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
                Save Branding &amp; Schedule
              </button>
            </div>
          </form>
        </div>

        <!-- Cron Instructions Box -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center text-lg">
              <i class="fa-solid fa-clock-rotate-left"></i>
            </div>
            <div>
              <h3 class="text-base font-bold text-white">Automated Cron Job Setup Guide</h3>
              <p class="text-xs text-slate-400">Configure your cPanel, CyberPanel, aaPanel, or server crontab to execute every 10–15 minutes.</p>
            </div>
          </div>

          <div class="space-y-3 pt-2">
            <div>
              <span class="text-xs font-bold text-slate-300 uppercase tracking-wider">cPanel / CyberPanel / HTTP Cron Command</span>
              <div class="mt-1.5 flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-xl p-3">
                <code class="text-xs text-blue-400 font-mono flex-grow select-all break-all">
                  curl -s "<?= e($cronUrl) ?>" &gt;/dev/null 2&gt;&amp;1
                </code>
                <button onclick="navigator.clipboard.writeText('curl -s &quot;<?= e($cronUrl) ?>&quot; &gt;/dev/null 2&gt;&amp;1'); alert('Cron command copied!');" class="text-slate-400 hover:text-white px-2 py-1 text-xs">
                  <i class="fa-solid fa-copy"></i>
                </button>
              </div>
            </div>

            <div>
              <span class="text-xs font-bold text-slate-300 uppercase tracking-wider">Direct Server CLI Command</span>
              <div class="mt-1.5 flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-xl p-3">
                <code class="text-xs text-blue-400 font-mono flex-grow select-all break-all">
                  php <?= e($serverScriptPath) ?> token=<?= e($adminSettings['cron_token']) ?>
                </code>
                <button onclick="navigator.clipboard.writeText('php <?= addslashes($serverScriptPath) ?> token=<?= e($adminSettings['cron_token']) ?>'); alert('CLI command copied!');" class="text-slate-400 hover:text-white px-2 py-1 text-xs">
                  <i class="fa-solid fa-copy"></i>
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>
    <?php endif; ?>

    <!-- TAB 3: SMTP Settings & Live Test -->
    <?php if ($activeTab === 'smtp'): ?>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        <!-- SMTP Form (2 cols) -->
        <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8">
          <h2 class="text-xl font-bold text-white mb-2">Native Socket SMTP Configuration</h2>
          <p class="text-xs text-slate-400 mb-6">Zero external libraries. Connects directly using PHP sockets supporting SSL (465) and TLS (587 with STARTTLS).</p>

          <form action="settings.php?tab=smtp" method="POST" class="space-y-5">
            <input type="hidden" name="update_smtp" value="1">
            <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              
              <!-- SMTP Host -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">SMTP Host</label>
                <input type="text" name="smtp_host" value="<?= e($smtpSettings['smtp_host']) ?>" placeholder="smtp.mailtrap.io or smtp.gmail.com" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
              </div>

              <!-- SMTP Port -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">SMTP Port</label>
                <input type="number" name="smtp_port" value="<?= (int)$smtpSettings['smtp_port'] ?>" placeholder="587" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
              </div>

              <!-- Encryption -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Encryption Protocol</label>
                <select name="smtp_secure" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
                  <option value="tls" <?= ($smtpSettings['smtp_secure'] ?? '') === 'tls' ? 'selected' : '' ?>>TLS / STARTTLS (Port 587 - Recommended)</option>
                  <option value="ssl" <?= ($smtpSettings['smtp_secure'] ?? '') === 'ssl' ? 'selected' : '' ?>>SSL (Port 465)</option>
                  <option value="none" <?= ($smtpSettings['smtp_secure'] ?? '') === 'none' ? 'selected' : '' ?>>None / Plain (Port 25)</option>
                </select>
              </div>

              <!-- From Name -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">From Display Name</label>
                <input type="text" name="from_name" value="<?= e($smtpSettings['from_name']) ?>" placeholder="Banglar Server" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
              </div>

              <!-- From Email -->
              <div class="sm:col-span-2">
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">From Email Address</label>
                <input type="email" name="from_email" value="<?= e($smtpSettings['from_email']) ?>" placeholder="support@banglarserver.com" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
              </div>

              <!-- Username -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">SMTP Username</label>
                <input type="text" name="smtp_user" value="<?= e($smtpSettings['smtp_user']) ?>" autocomplete="off"
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
              </div>

              <!-- Password -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">SMTP Password</label>
                <input type="password" name="smtp_pass" placeholder="••••••••••••" autocomplete="new-password"
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
                <p class="mt-1 text-[11px] text-slate-400">Leave blank to keep current stored password.</p>
              </div>

            </div>

            <div class="pt-4 flex justify-end">
              <button type="submit" class="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
                Save SMTP Settings
              </button>
            </div>
          </form>
        </div>

        <!-- Live Test Email Box (1 col) -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
          <div>
            <div class="w-12 h-12 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center text-xl mb-4">
              <i class="fa-solid fa-paper-plane"></i>
            </div>
            <h3 class="text-lg font-bold text-white mb-2">Send Test HTML Email</h3>
            <p class="text-xs text-slate-400 leading-relaxed mb-6">
              Test your socket SMTP connection and inspect the live connection handshake log instantly.
            </p>

            <form action="settings.php?tab=smtp" method="POST" class="space-y-4">
              <input type="hidden" name="send_test_email" value="1">
              <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Recipient Email</label>
                <input type="email" name="test_recipient" value="<?= e($adminSettings['admin_email']) ?>" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
              </div>

              <button type="submit" class="w-full py-3.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
                <i class="fa-solid fa-bolt mr-1"></i> Send Test HTML Email
              </button>
            </form>
          </div>

          <div class="pt-6 border-t border-slate-800 text-[11px] text-slate-400 mt-6">
            <i class="fa-solid fa-info-circle text-blue-400 mr-1"></i>
            If your SMTP server credentials are left blank, the system automatically falls back to native PHP <code>mail()</code>.
          </div>
        </div>

      </div>
    <?php elseif ($activeTab === 'templates'): ?>
      <!-- TAB 4: Email Templates Manager -->
      <div class="space-y-6">
        
        <!-- Header & Template Selector Banner -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-xl">
          <div>
            <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30 uppercase tracking-wider mb-2">
              <i class="fa-solid fa-envelope-open-text"></i> Email Templates Customizer
            </div>
            <h2 class="text-2xl font-black text-white tracking-tight">Automated Email Templates</h2>
            <p class="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Customize the automated emails dispatched to customers and leads when domains are added to the watchlist or become available to register.
            </p>
          </div>

          <!-- Template Switcher Tabs -->
          <div class="flex flex-col sm:flex-row gap-2 shrink-0">
            <a href="settings.php?tab=templates&tpl=domain_added" 
               class="px-4 py-3 rounded-xl border text-xs font-bold flex items-center gap-2.5 transition-all <?= $selectedTplKey === 'domain_added' ? 'bg-purple-600 text-white border-purple-500 shadow-lg shadow-purple-600/30' : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700' ?>">
              <i class="fa-solid fa-clock-rotate-left"></i>
              <div class="text-left">
                <div>1. Domain Added to Watchlist</div>
                <div class="text-[10px] font-normal <?= $selectedTplKey === 'domain_added' ? 'text-purple-200' : 'text-slate-500' ?>">Client Confirmation</div>
              </div>
            </a>

            <a href="settings.php?tab=templates&tpl=domain_available" 
               class="px-4 py-3 rounded-xl border text-xs font-bold flex items-center gap-2.5 transition-all <?= $selectedTplKey === 'domain_available' ? 'bg-purple-600 text-white border-purple-500 shadow-lg shadow-purple-600/30' : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700' ?>">
              <i class="fa-solid fa-fire text-amber-400"></i>
              <div class="text-left">
                <div>2. When Available / Drop Alert</div>
                <div class="text-[10px] font-normal <?= $selectedTplKey === 'domain_available' ? 'text-purple-200' : 'text-slate-500' ?>">Client Drop Alert</div>
              </div>
            </a>

            <a href="settings.php?tab=templates&tpl=admin_daily_report" 
               class="px-4 py-3 rounded-xl border text-xs font-bold flex items-center gap-2.5 transition-all <?= $selectedTplKey === 'admin_daily_report' ? 'bg-purple-600 text-white border-purple-500 shadow-lg shadow-purple-600/30' : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700' ?>">
              <i class="fa-solid fa-chart-pie text-emerald-400"></i>
              <div class="text-left">
                <div>3. Admin Daily Report</div>
                <div class="text-[10px] font-normal <?= $selectedTplKey === 'admin_daily_report' ? 'text-purple-200' : 'text-slate-500' ?>">দৈনিক সার্বিক ডোমেন রিপোর্ট</div>
              </div>
            </a>
          </div>
        </div>

        <!-- Editor & Live Preview Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          <!-- Column 1: Editor Form (7 cols) -->
          <div class="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
            
            <div class="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 class="text-base font-bold text-white flex items-center gap-2">
                  <i class="fa-solid fa-pen-nib text-purple-400"></i>
                  <?= e($currentTpl['template_name']) ?>
                </h3>
                <span class="text-[11px] text-slate-400">Key: <code class="text-purple-400 font-mono"><?= e($selectedTplKey) ?></code></span>
              </div>

              <div class="flex items-center gap-2">
                <form action="settings.php?tab=templates&tpl=<?= e($selectedTplKey) ?>" method="POST" onsubmit="return confirm('Reset this template back to official Banglar Server default copy?');">
                  <input type="hidden" name="reset_email_template" value="1">
                  <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
                  <input type="hidden" name="template_key" value="<?= e($selectedTplKey) ?>">
                  <button type="submit" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white text-xs font-medium border border-slate-700 transition-colors" title="Reset to Defaults">
                    <i class="fa-solid fa-rotate-left mr-1"></i> Reset
                  </button>
                </form>
              </div>
            </div>

            <!-- Main Edit Form -->
            <form id="templateEditForm" action="settings.php?tab=templates&tpl=<?= e($selectedTplKey) ?>" method="POST" class="space-y-5">
              <input type="hidden" name="save_email_template" value="1">
              <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
              <input type="hidden" name="template_key" value="<?= e($selectedTplKey) ?>">

              <!-- Status Toggle -->
              <div class="flex items-center justify-between p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div class="flex items-center gap-2.5">
                  <i class="fa-solid fa-circle-check <?= $currentTpl['is_enabled'] ? 'text-emerald-400' : 'text-slate-600' ?>"></i>
                  <div>
                    <label for="is_enabled" class="text-xs font-bold text-white cursor-pointer">Template Status</label>
                    <p class="text-[11px] text-slate-400">When enabled, this email is automatically dispatched by the engine.</p>
                  </div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" id="is_enabled" name="is_enabled" value="1" <?= $currentTpl['is_enabled'] ? 'checked' : '' ?> class="sr-only peer">
                  <div class="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
                </label>
              </div>

              <!-- Subject Line -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Email Subject Line
                </label>
                <input type="text" id="input_subject" name="subject" value="<?= e($currentTpl['subject']) ?>" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 text-sm">
                <p class="text-[11px] text-slate-500 mt-1">Inbox subject header seen by client.</p>
              </div>

              <!-- Headline / Card Title -->
              <div>
                <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Email Banner Headline (Inside Email Body)
                </label>
                <input type="text" id="input_headline" name="headline" value="<?= e($currentTpl['headline']) ?>" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 text-sm">
              </div>

              <!-- Call to Action Button Text & Target URL -->
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Action Button Label (Text)
                  </label>
                  <input type="text" id="input_button_text" name="button_text" value="<?= e($currentTpl['button_text']) ?>" required
                    class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 text-sm">
                  <p class="text-[11px] text-slate-500 mt-1">e.g. Claim &amp; Book Domain Now</p>
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Button Target Link (URL)
                  </label>
                  <input type="text" id="input_button_url" name="button_url" value="<?= e($currentTpl['button_url'] ?? 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}') ?>" required
                    class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 text-xs font-mono">
                  <p class="text-[11px] text-slate-500 mt-1">Direct search URL with <code class="text-emerald-400 font-mono">{domain}</code></p>
                </div>
              </div>

              <!-- Body HTML Textarea -->
              <div>
                <div class="flex items-center justify-between mb-2">
                  <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Message Body (HTML Supported)
                  </label>
                  <span class="text-[11px] text-purple-400 font-mono">HTML + Dynamic Placeholders</span>
                </div>
                <textarea id="input_body_html" name="body_html" rows="8" required
                  class="w-full bg-slate-950 border border-slate-700 rounded-xl p-4 text-slate-200 font-mono text-xs focus:outline-none focus:border-purple-500 leading-relaxed"><?= e($currentTpl['body_html']) ?></textarea>
              </div>

              <!-- Clickable Dynamic Variables Guide -->
              <div class="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span class="text-xs font-bold text-slate-300 block">
                  <i class="fa-solid fa-wand-magic-sparkles text-purple-400 mr-1"></i> Click to Insert Placeholder Variable:
                </span>
                <div class="flex flex-wrap gap-1.5 text-xs">
                  <?php if ($selectedTplKey === 'admin_daily_report'): ?>
                    <button type="button" onclick="insertVariable('{newly_available}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Count of domains that dropped today">
                      {newly_available}
                    </button>
                    <button type="button" onclick="insertVariable('{total_monitored}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Total active watchlist count">
                      {total_monitored}
                    </button>
                    <button type="button" onclick="insertVariable('{total_available}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Total currently available count">
                      {total_available}
                    </button>
                    <button type="button" onclick="insertVariable('{still_registered}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Still registered count">
                      {still_registered}
                    </button>
                    <button type="button" onclick="insertVariable('{date_short}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="YYYY-MM-DD Date">
                      {date_short}
                    </button>
                    <button type="button" onclick="insertVariable('{date}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Full timestamp">
                      {date}
                    </button>
                  <?php else: ?>
                    <button type="button" onclick="insertVariable('{domain}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Target domain name">
                      {domain}
                    </button>
                    <button type="button" onclick="insertVariable('{name}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Lead's Full Name">
                      {name}
                    </button>
                    <button type="button" onclick="insertVariable('{email}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Lead's Email Address">
                      {email}
                    </button>
                    <button type="button" onclick="insertVariable('{booking_url}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Direct WHMCS cart registration URL">
                      {booking_url}
                    </button>
                    <button type="button" onclick="insertVariable('{date}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-purple-950 text-slate-300 hover:text-purple-300 border border-slate-700 font-mono text-[11px] transition-colors cursor-pointer" title="Current timestamp">
                      {date}
                    </button>
                  <?php endif; ?>
                </div>
              </div>

              <!-- Form Submit Bar -->
              <div class="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
                <button type="submit" class="w-full sm:w-auto px-7 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-purple-600/30 cursor-pointer">
                  <i class="fa-solid fa-floppy-disk mr-1.5"></i> Save Template Changes
                </button>
              </div>
            </form>

            <!-- Test Send Section -->
            <div class="pt-6 border-t border-slate-800">
              <form action="settings.php?tab=templates&tpl=<?= e($selectedTplKey) ?>" method="POST" class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <input type="hidden" name="test_email_template" value="1">
                <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
                <input type="hidden" name="template_key" value="<?= e($selectedTplKey) ?>">
                <div>
                  <span class="text-xs font-bold text-white block">Test Delivery</span>
                  <span class="text-[11px] text-slate-400">Send an instant test email of this template to <code class="text-blue-400 font-semibold"><?= e($adminSettings['admin_email']) ?></code></span>
                </div>
                <button type="submit" class="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-blue-300 border border-blue-500/30 font-bold text-xs uppercase tracking-wider transition-all cursor-pointer">
                  <i class="fa-solid fa-paper-plane mr-1"></i> Send Test to Admin Email
                </button>
              </form>
            </div>

          </div>

          <!-- Column 2: Live Simulated Email Client Preview (5 cols) -->
          <div class="lg:col-span-5 sticky top-28 space-y-4">
            
            <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
              
              <!-- Simulated Email Client Window Chrome -->
              <div class="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block"></span>
                  <span class="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block"></span>
                  <span class="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
                  <span class="text-[11px] font-bold text-slate-400 ml-2">Inbox Preview</span>
                </div>
                <span class="text-[10px] text-slate-500 font-mono">600px Container</span>
              </div>

              <!-- Message Headers Bar -->
              <div class="p-4 bg-slate-950/50 border-b border-slate-800 space-y-1 text-xs">
                <div class="flex items-center justify-between">
                  <span class="text-slate-400 font-semibold">Subject:</span>
                  <span id="preview_subject" class="font-bold text-white truncate max-w-[280px]">
                    <?= e($currentTpl['subject']) ?>
                  </span>
                </div>
                <div class="flex items-center justify-between text-[11px] text-slate-400">
                  <span>From: <span class="text-slate-300">Banglar Server &lt;support@banglarserver.com&gt;</span></span>
                  <span>To: <span class="text-sky-400"><?= $selectedTplKey === 'admin_daily_report' ? e($adminSettings['admin_email']) : 'lead@client.com' ?></span></span>
                </div>
              </div>

              <!-- Simulated Email Body Container (#0b1120 canvas) -->
              <div class="p-4 sm:p-6 bg-[#0b1120] text-slate-200 text-xs">
                
                <!-- Main Email Card (#0f172a) -->
                <div class="max-w-[540px] mx-auto bg-[#0f172a] rounded-xl border border-slate-800 overflow-hidden shadow-xl">
                  
                  <!-- Email Header Banner -->
                  <div class="p-5 text-center bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border-b-2 border-blue-600">
                    <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-8 w-auto mx-auto object-contain mb-2 drop-shadow-sm" onerror="this.onerror=null; this.src='assets/logo.png';" />
                    <div class="text-[10px] font-bold tracking-widest text-blue-400 uppercase">
                      BANGLAR SERVER &bull; DOMAIN INTELLIGENCE
                    </div>
                  </div>

                  <!-- Email Content Container -->
                  <div class="p-5 space-y-4">
                    
                    <!-- Dynamic Top Status Badge -->
                    <div class="text-center pt-2">
                      <?php if ($selectedTplKey === 'domain_added'): ?>
                        <div class="inline-block px-3 py-1 bg-blue-500/15 border border-blue-500 rounded-full text-blue-300 text-[10px] font-bold tracking-wider uppercase">
                          &bull; 24/7 Drop Monitoring Active
                        </div>
                      <?php elseif ($selectedTplKey === 'domain_available'): ?>
                        <div class="inline-block px-3 py-1 bg-emerald-500/15 border border-emerald-500 rounded-full text-emerald-400 text-[10px] font-bold tracking-wider uppercase">
                          &check; Domain Available Right Now
                        </div>
                      <?php else: ?>
                        <div class="inline-block px-3 py-1 bg-purple-500/15 border border-purple-500 rounded-full text-purple-300 text-[10px] font-bold tracking-wider uppercase">
                          &bull; Automated Scheduled Daily Report
                        </div>
                      <?php endif; ?>

                      <!-- Dynamic Headline -->
                      <h2 id="preview_headline" class="text-base sm:text-lg font-extrabold text-white mt-3">
                        <?= e($currentTpl['headline']) ?>
                      </h2>
                      <p class="text-[11px] text-slate-400 mt-1">
                        <?php if ($selectedTplKey === 'domain_added'): ?>
                          আপনার কাঙ্খিত ডোমেইনটি নজরদারির জন্য সফলভাবে তালিকাভুক্ত করা হয়েছে।
                        <?php elseif ($selectedTplKey === 'domain_available'): ?>
                          আপনার কাঙ্খিত ডোমেইনটি বর্তমানে উন্মুক্ত এবং রেজিস্ট্রেশনের জন্য প্রস্তুত!
                        <?php else: ?>
                          Scheduled automated daily check completed at <?= date('Y-m-d H:i:s T') ?>.
                        <?php endif; ?>
                      </p>
                    </div>

                    <!-- Greeting -->
                    <p class="text-white font-semibold text-xs">
                      <?= $selectedTplKey === 'admin_daily_report' ? 'Hello Banglar Server Admin,' : 'Hello Tanvir Ahmed,' ?>
                    </p>

                    <!-- Live Message Body Content -->
                    <div id="preview_body" class="text-slate-300 text-xs leading-relaxed space-y-2">
                      <?= $currentTpl['body_html'] ?>
                    </div>

                    <?php if ($selectedTplKey === 'admin_daily_report'): ?>
                      <!-- 4 KPI Summary Cards -->
                      <div class="grid grid-cols-2 gap-2 text-[11px]">
                        <div class="bg-slate-900 border border-slate-800 rounded-lg p-3">
                          <div class="text-[10px] text-slate-400 uppercase font-bold tracking-wide">Total Monitored</div>
                          <div class="text-lg font-black text-white mt-0.5">12</div>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 rounded-lg p-3">
                          <div class="text-[10px] text-emerald-400 uppercase font-bold tracking-wide">Newly Available Today</div>
                          <div class="text-lg font-black text-emerald-400 mt-0.5">3</div>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 rounded-lg p-3">
                          <div class="text-[10px] text-emerald-300 uppercase font-bold tracking-wide">Total Available</div>
                          <div class="text-lg font-black text-emerald-300 mt-0.5">5</div>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 rounded-lg p-3">
                          <div class="text-[10px] text-amber-400 uppercase font-bold tracking-wide">Still Registered</div>
                          <div class="text-lg font-black text-amber-400 mt-0.5">7</div>
                        </div>
                      </div>

                      <!-- Watched Domains Mini Preview Table -->
                      <div class="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-[10px]">
                        <div class="px-3 py-2 bg-slate-900 font-bold text-slate-300 flex justify-between items-center border-b border-slate-800">
                          <span>Watched Domains Database</span>
                          <span class="text-emerald-400 font-mono text-[9px]">3 Newly Available</span>
                        </div>
                        <div class="divide-y divide-slate-850 font-mono">
                          <div class="px-3 py-2 flex justify-between items-center">
                            <span class="text-white font-bold">supercoolbrand.com</span>
                            <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[9px] font-sans font-bold">AVAILABLE</span>
                          </div>
                          <div class="px-3 py-2 flex justify-between items-center">
                            <span class="text-white font-bold">banglarstartup.net</span>
                            <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[9px] font-sans font-bold">AVAILABLE</span>
                          </div>
                          <div class="px-3 py-2 flex justify-between items-center">
                            <span class="text-slate-400">dhakahosting.org</span>
                            <span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 text-[9px] font-sans font-bold">REGISTERED</span>
                          </div>
                        </div>
                      </div>

                      <!-- Live Call-to-action Button -->
                      <div class="text-center pt-3 pb-2">
                        <a href="admin.php" target="_blank" rel="noopener noreferrer" id="preview_button" class="inline-block px-7 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-600/30 transition-all">
                          <?= e($currentTpl['button_text']) ?>
                        </a>
                        <p class="text-[10px] text-slate-400 mt-2 flex items-center justify-center gap-1">
                          <i class="fa-solid fa-arrow-up-right-from-square text-[9px] text-blue-400"></i> Opens Admin Watchlist in new tab
                        </p>
                      </div>

                    <?php else: ?>

                      <!-- Sample Domain Details Card -->
                      <div class="bg-slate-900/90 rounded-xl border border-slate-800 divide-y divide-slate-800 text-[11px] shadow-sm">
                        <div class="px-4 py-3 flex justify-between items-center">
                          <span class="text-slate-400 font-medium">Target Domain:</span>
                          <span class="text-white font-mono font-bold text-xs">example-preview.com</span>
                        </div>
                        <div class="px-4 py-3 flex justify-between items-center">
                          <span class="text-slate-400 font-medium">Status:</span>
                          <span class="px-2.5 py-0.5 rounded text-[10px] font-bold tracking-wide <?= $selectedTplKey === 'domain_added' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400' ?>">
                            <?= $selectedTplKey === 'domain_added' ? 'REGISTERED &bull; MONITORED' : 'AVAILABLE NOW' ?>
                          </span>
                        </div>
                        <div class="px-4 py-3 flex justify-between items-center">
                          <span class="text-slate-400 font-medium">Timestamp:</span>
                          <span class="text-slate-300 font-mono text-[10px]"><?= date('Y-m-d H:i:s T') ?></span>
                        </div>
                      </div>

                      <!-- Live Call-to-action Button (Clickable to Banglar Server Domain Search) -->
                      <div class="text-center pt-3 pb-2">
                        <a href="https://dash.banglarserver.com/cart.php?a=add&domain=register&query=example-preview.com" target="_blank" rel="noopener noreferrer" id="preview_button" class="inline-block px-7 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-lg shadow-blue-600/30 transition-all">
                          <?= e($currentTpl['button_text']) ?>
                        </a>
                        <p class="text-[10px] text-slate-400 mt-2 flex items-center justify-center gap-1">
                          <i class="fa-solid fa-arrow-up-right-from-square text-[9px] text-blue-400"></i> Opens Banglar Server search in new tab
                        </p>
                      </div>

                    <?php endif; ?>

                    <p class="text-[10px] text-slate-500 border-t border-slate-800 pt-3 text-center">
                      Thank you for choosing <strong>Banglar Server</strong>. Technical support available 24/7.
                    </p>

                  </div>

                  <!-- Footer -->
                  <div class="p-4 bg-slate-950/80 border-t border-slate-800 text-center text-[10px] text-slate-500 space-y-1">
                    <p class="font-semibold text-slate-400">Banglar Server Cloud &bull; Domain Watcher Engine</p>
                    <p>&copy; <?= date('Y') ?> Banglar Server. All rights reserved.</p>
                  </div>

                </div>

              </div>

            </div>

          </div>

        </div>

      </div>

      <!-- Live Interactive Real-Time Preview JavaScript -->
      <script>
        const inputSubj = document.getElementById('input_subject');
        const inputHead = document.getElementById('input_headline');
        const inputBtn  = document.getElementById('input_button_text');
        const inputUrl  = document.getElementById('input_button_url');
        const inputBody = document.getElementById('input_body_html');

        const prevSubj = document.getElementById('preview_subject');
        const prevHead = document.getElementById('preview_headline');
        const prevBtn  = document.getElementById('preview_button');
        const prevBody = document.getElementById('preview_body');

        function replaceSampleVars(str) {
          if (!str) return '';
          return str
            .replace(/{domain}/g, '<span class="text-emerald-400 font-mono font-bold">example-preview.com</span>')
            .replace(/{name}/g, 'Tanvir Ahmed')
            .replace(/{email}/g, 'client@preview.com')
            .replace(/{booking_url}/g, 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query=example-preview.com')
            .replace(/{newly_available}/g, '<span class="text-emerald-400 font-bold">3 newly available</span>')
            .replace(/{total_monitored}/g, '<span class="text-white font-bold">12</span>')
            .replace(/{total_available}/g, '<span class="text-emerald-300 font-bold">5</span>')
            .replace(/{still_registered}/g, '<span class="text-amber-400 font-bold">7</span>')
            .replace(/{date_short}/g, '<?= date('Y-m-d') ?>')
            .replace(/{date}/g, '<?= date('Y-m-d H:i:s T') ?>');
        }

        function updatePreview() {
          if (inputSubj && prevSubj) {
            prevSubj.textContent = inputSubj.value
              .replace(/{domain}/g, 'example-preview.com')
              .replace(/{newly_available}/g, '3')
              .replace(/{date_short}/g, '<?= date('Y-m-d') ?>');
          }
          if (inputHead && prevHead) {
            prevHead.textContent = inputHead.value
              .replace(/{domain}/g, 'example-preview.com')
              .replace(/{newly_available}/g, '3');
          }
          if (inputBtn && prevBtn) {
            prevBtn.textContent = inputBtn.value;
          }
          if (inputUrl && prevBtn) {
            let finalUrl = (inputUrl.value || '').trim() || 'admin.php';
            finalUrl = finalUrl.replace(/{domain}/g, 'example-preview.com')
                               .replace(/{booking_url}/g, 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query=example-preview.com');
            prevBtn.href = finalUrl;
          }
          if (inputBody && prevBody) {
            prevBody.innerHTML = replaceSampleVars(inputBody.value);
          }
        }

        if (inputSubj) inputSubj.addEventListener('input', updatePreview);
        if (inputHead) inputHead.addEventListener('input', updatePreview);
        if (inputBtn)  inputBtn.addEventListener('input', updatePreview);
        if (inputUrl)  inputUrl.addEventListener('input', updatePreview);
        if (inputBody) inputBody.addEventListener('input', updatePreview);

        function insertVariable(token) {
          const textarea = document.getElementById('input_body_html');
          if (!textarea) return;

          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          const text = textarea.value;

          textarea.value = text.substring(0, start) + token + text.substring(end);
          textarea.focus();
          textarea.selectionStart = textarea.selectionEnd = start + token.length;
          updatePreview();
        }

        // Initialize preview on page load
        updatePreview();
      </script>

    <?php endif; ?>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
    Banglar Server Settings Engine &bull; System Time: <?= date('Y-m-d H:i:s T') ?> &bull; &copy; <?= date('Y') ?> Banglar Server
  </footer>

  <!-- Live Logo Test Bench Sync Script -->
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      const logoInputEl = document.getElementById('logoUrlInput');
      if (logoInputEl) {
        logoInputEl.addEventListener('input', () => {
          const val = logoInputEl.value.trim() || 'assets/logo.png';
          const darkEl = document.getElementById('liveLogoDark');
          const lightEl = document.getElementById('liveLogoLight');
          if (darkEl) darkEl.src = val;
          if (lightEl) lightEl.src = val;
        });
      }
    });
  </script>

</body>
</html>
