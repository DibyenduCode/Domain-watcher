<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Scheduled Daily Check & Guaranteed Full HTML Report Engine
 * Dual-Mode Execution: Web GET (Token / Admin Manual) & CLI
 */

// Set execution limits for large domain lists
set_time_limit(600);
ignore_user_abort(true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/smtp_mailer.php';

$isCli = (php_sapi_name() === 'cli');
$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$smtpSettings  = getSmtpSettings($pdo);

// Parse input parameters (from CLI arguments or GET)
$token = '';
$isManual = false;
$isForce = false;

if ($isCli) {
    global $argv;
    foreach ($argv as $arg) {
        if (str_starts_with($arg, 'token=')) {
            $token = substr($arg, 6);
        }
        if ($arg === 'manual=1' || $arg === '--manual') {
            $isManual = true;
        }
        if ($arg === 'force=1' || $arg === '--force') {
            $isForce = true;
        }
    }
} else {
    $token = $_GET['token'] ?? '';
    $isManual = isset($_GET['manual']) && $_GET['manual'] == '1';
    $isForce = isset($_GET['force']) && $_GET['force'] == '1';
}

// -------------------------------------------------------------
// Security & Authentication Gate
// -------------------------------------------------------------
$authorized = false;

if ($isCli) {
    // CLI execution on server is authorized
    $authorized = true;
} elseif ($isManual && isAdminLoggedIn()) {
    // Logged in admin manual trigger
    $authorized = true;
} elseif (!empty($token) && hash_equals($adminSettings['cron_token'], $token)) {
    // Valid secret cron token
    $authorized = true;
}

if (!$authorized) {
    http_response_code(403);
    if ($isCli) {
        echo "Error: Unauthorized cron execution. Invalid token.\n";
    } else {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'status'  => 'error',
            'message' => 'Forbidden. Invalid or missing cron_token. Access denied.'
        ]);
    }
    exit;
}

// -------------------------------------------------------------
// Schedule Time & Duplicate Report Prevention Check
// -------------------------------------------------------------
$currentTime = date('H:i:s');
$currentDate = date('Y-m-d');
$scheduledTime = $adminSettings['daily_report_time'] ?? '09:00:00';
$lastReportDate = $adminSettings['last_report_date'] ?? null;

// If triggered via routine cron (not manual and not forced)
$shouldSendDailyReport = false;

if ($isManual || $isForce) {
    $shouldSendDailyReport = true;
} else {
    // Check if current time has reached or passed scheduled time AND not already sent today
    if ($currentTime >= $scheduledTime && $lastReportDate !== $currentDate) {
        $shouldSendDailyReport = true;
    }
}

// -------------------------------------------------------------
// Domain Availability Check Execution Loop
// -------------------------------------------------------------
$stmtDomains = $pdo->query("SELECT * FROM `watched_domains` ORDER BY `id` ASC");
$allDomains = $stmtDomains->fetchAll();

$mailer = new BanglarSmtpMailer($smtpSettings, $adminSettings);

$totalChecked = 0;
$newlyAvailableCount = 0;
$executionLogs = [];

foreach ($allDomains as $row) {
    $domainId = (int)$row['id'];
    $domainName = cleanDomain($row['domain_name']);
    if (empty($domainName)) continue;

    $userEmail = trim($row['user_email']);
    $prevStatus = $row['status'];
    $prevNotified = (int)$row['notified_available'];

    // Run direct socket WHOIS lookup
    $isAvailable = isDomainAvailable($domainName);
    $currentStatus = $isAvailable ? 'available' : 'registered';
    $notified = $prevNotified;

    // Detect Instant Drop (previously registered -> now available)
    if ($isAvailable && ($prevStatus === 'registered' || $prevNotified == 0)) {
        // Send Instant Drop Alert to User
        if (!empty($userEmail)) {
            $mailer->sendDropAlert($domainName, $userEmail, false, $row['user_name'] ?? null);
        }
        // Send Instant Drop Alert to Admin
        $mailer->sendDropAlert($domainName, $adminSettings['admin_email'], true, $row['user_name'] ?? null, $row['user_phone'] ?? null, $userEmail);

        $notified = 1;
        $newlyAvailableCount++;
        $executionLogs[] = "DROP DETECTED: {$domainName} is now AVAILABLE. Drop alerts sent to {$userEmail} and {$adminSettings['admin_email']}.";
    }

    // Update database record
    $stmtUp = $pdo->prepare("
        UPDATE `watched_domains`
        SET `status` = ?,
            `last_checked` = NOW(),
            `notified_available` = ?
        WHERE `id` = ?
    ");
    $stmtUp->execute([$currentStatus, $notified, $domainId]);
    $totalChecked++;

    // 1-second pause to prevent WHOIS rate limiting as specified in requirements
    usleep(1000000);
}

// Fetch refreshed list and counts for report
$stmtFresh = $pdo->query("SELECT * FROM `watched_domains` ORDER BY `id` ASC");
$refreshedDomains = $stmtFresh->fetchAll();

$totalCount = count($refreshedDomains);
$availableCount = 0;
$registeredCount = 0;

foreach ($refreshedDomains as $d) {
    if ($d['status'] === 'available') {
        $availableCount++;
    } else {
        $registeredCount++;
    }
}

$stats = [
    'total'            => $totalCount,
    'newly_available'  => $newlyAvailableCount,
    'available'        => $availableCount,
    'registered'       => $registeredCount
];

$reportSent = false;
$reportMsg = '';

// Send Guaranteed Full Admin Report if scheduled or manual
$adminReportRecipients = getAdminReportEmails($adminSettings, $pdo);
$recipientsDisplay = implode(', ', $adminReportRecipients);

if ($shouldSendDailyReport) {
    $sendReport = $mailer->sendDailyReportEmail($stats, $refreshedDomains, $adminReportRecipients);
    $reportSent = $sendReport['success'];
    $reportMsg = $sendReport['message'];

    // Update last_report_date in admins table to prevent duplicate reports today
    $stmtDate = $pdo->prepare("UPDATE `admins` SET `last_report_date` = CURDATE() WHERE `id` = ?");
    $stmtDate->execute([$adminSettings['id']]);
}

// -------------------------------------------------------------
// Output Formatting (Browser HTML for Admin Manual vs CLI/JSON)
// -------------------------------------------------------------
if (!$isCli && $isManual) {
    // Beautiful Dark-Mode Summary Page for Admin
    $logoUrl = !empty($adminSettings['logo_url']) ? $adminSettings['logo_url'] : 'assets/logo.png';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daily Check &amp; Report Completed - Banglar Server</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#eef6ff',
              100: '#d9eaff',
              200: '#bcd9ff',
              300: '#8ec0fe',
              400: '#589efc',
              500: '#1F75FE',
              600: '#1a60e1',
              700: '#154cb8',
              800: '#163f94',
              900: '#173775',
              950: '#102248',
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
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col items-center justify-center p-4 selection:bg-blue-600 selection:text-white">
  <div class="max-w-3xl w-full my-8 space-y-6">
    
    <!-- Top Header Card -->
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-8 text-center shadow-2xl relative overflow-hidden">
      <div class="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-32 bg-blue-600/15 blur-3xl rounded-full pointer-events-none"></div>

      <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-12 w-auto mx-auto object-contain mb-4 drop-shadow-[0_2px_8px_rgba(31,117,254,0.3)]" onerror="this.onerror=null; this.src='assets/logo.png';" />
      
      <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-500/15 border border-blue-500/30 text-blue-400 text-xs font-bold uppercase tracking-wider mb-3">
        <i class="fa-solid fa-circle-check"></i> Execution Complete
      </div>

      <h1 class="text-2xl sm:text-3xl font-extrabold text-white">
        Domain Watcher Check &amp; Report Done!
      </h1>
      <p class="text-xs sm:text-sm text-slate-400 mt-2 max-w-xl mx-auto">
        All monitored domains were scanned via live WHOIS sockets. Drop alerts and the comprehensive daily report were dispatched.
      </p>

      <!-- 4 KPI Box Row -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 text-left">
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
          <span class="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Checked</span>
          <span class="text-2xl font-extrabold text-white"><?= $totalChecked ?></span>
        </div>
        <div class="bg-slate-950 border border-blue-500/30 rounded-xl p-4">
          <span class="text-[11px] font-bold text-blue-400 uppercase tracking-wider block">New Drops</span>
          <span class="text-2xl font-extrabold text-blue-400"><?= $newlyAvailableCount ?></span>
        </div>
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
          <span class="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block">Available</span>
          <span class="text-2xl font-extrabold text-emerald-400"><?= $availableCount ?></span>
        </div>
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
          <span class="text-[11px] font-bold text-amber-400 uppercase tracking-wider block">Registered</span>
          <span class="text-2xl font-extrabold text-amber-400"><?= $registeredCount ?></span>
        </div>
      </div>

      <!-- Report Dispatch Notice -->
      <div class="mt-6 p-4 rounded-xl <?= $reportSent ? 'bg-blue-950/40 border-blue-500/30 text-blue-200' : 'bg-slate-950 border-slate-800 text-slate-400' ?> border text-xs flex items-center justify-between">
        <div class="flex items-center gap-2">
          <i class="fa-solid fa-envelope-circle-check text-blue-400 text-base"></i>
          <span>
            Daily Full Report dispatched to <strong class="text-white"><?= e($recipientsDisplay) ?></strong>: 
            <?= $reportSent ? 'Sent Successfully' : e($reportMsg) ?>
          </span>
        </div>
        <span class="text-[10px] text-slate-500 font-mono"><?= date('H:i:s') ?></span>
      </div>

      <div class="mt-8 flex justify-center gap-4">
        <a href="admin.php" class="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-blue-600/30">
          &larr; Return to Admin Dashboard
        </a>
      </div>

    </div>

    <!-- Execution Logs Accordion -->
    <?php if (!empty($executionLogs)): ?>
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">Live Drop Event Log</h3>
        <div class="space-y-2">
          <?php foreach ($executionLogs as $log): ?>
            <div class="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
              <?= e($log) ?>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    <?php endif; ?>

  </div>
</body>
</html>
<?php
    exit;
}

// CLI or JSON Response
if ($isCli) {
    echo "========================================================\n";
    echo "Banglar Server - Domain Availability Watcher Cron Engine\n";
    echo "Time: " . date('Y-m-d H:i:s T') . "\n";
    echo "Domains Checked: {$totalChecked}\n";
    echo "Newly Available Drops: {$newlyAvailableCount}\n";
    echo "Total Available: {$availableCount} | Total Registered: {$registeredCount}\n";
    echo "Daily Report to {$recipientsDisplay}: " . ($reportSent ? "SENT" : "SKIPPED/FAILED ({$reportMsg})") . "\n";
    echo "========================================================\n";
} else {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'status'              => 'success',
        'timestamp'           => date('Y-m-d H:i:s T'),
        'domains_checked'     => $totalChecked,
        'newly_dropped'       => $newlyAvailableCount,
        'stats'               => $stats,
        'report_sent'         => $reportSent,
        'report_recipients'   => $adminReportRecipients,
        'report_message'      => $reportMsg,
        'logs'                => $executionLogs
    ]);
}
