<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Admin Dashboard & Domain Watchlist Manager
 * With In-Row AJAX Recheck (No Refresh), Row Editing & Responsive Pagination
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/smtp_mailer.php';

startSessionSafe();
$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$logoUrl = !empty($adminSettings['logo_url']) ? $adminSettings['logo_url'] : 'assets/logo.png';
$bookingBaseUrl = rtrim($adminSettings['booking_base_url'] ?? '', '=') . '=';

$loginError = '';
$flashMessage = $_SESSION['bs_flash_message'] ?? null;
unset($_SESSION['bs_flash_message']);

// -------------------------------------------------------------
// Authentication Handling
// -------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: admin.php?action=login");
    exit;
}

// Login Rate Limiting & Brute-Force Throttling
$maxAttempts = 5;
$lockoutDuration = 15 * 60; // 15 minutes
$failCount = $_SESSION['bs_login_fails'] ?? 0;
$lockoutUntil = $_SESSION['bs_login_lockout'] ?? 0;

if ($lockoutUntil > time()) {
    $remainingMinutes = ceil(($lockoutUntil - time()) / 60);
    $loginError = "Too many failed login attempts. Security lockout active for {$remainingMinutes} more minute(s).";
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_submit'])) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $loginError = 'Security check failed (Invalid or expired CSRF token). Please refresh and try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $stmt = $pdo->prepare("SELECT * FROM `admins` WHERE `username` = ? LIMIT 1");
        $stmt->execute([$username]);
        $adminRow = $stmt->fetch();

        if ($adminRow && password_verify($password, $adminRow['password_hash'])) {
            // Successful login: reset throttle counters & regenerate session ID
            unset($_SESSION['bs_login_fails'], $_SESSION['bs_login_lockout']);
            session_regenerate_id(true);

            $_SESSION['bs_admin_id'] = $adminRow['id'];
            $_SESSION['bs_admin_user'] = $adminRow['username'];
            $_SESSION['bs_admin_email'] = $adminRow['admin_email'];
            
            // Mint a fresh CSRF token for the authenticated session
            $_SESSION['bs_csrf_token'] = bin2hex(random_bytes(32));

            header("Location: admin.php");
            exit;
        } else {
            // Failed login: throttle & increment counter
            sleep(1);
            $failCount++;
            $_SESSION['bs_login_fails'] = $failCount;
            if ($failCount >= $maxAttempts) {
                $_SESSION['bs_login_lockout'] = time() + $lockoutDuration;
                $loginError = "Too many failed login attempts. Account temporarily locked for 15 minutes.";
            } else {
                $left = $maxAttempts - $failCount;
                $loginError = "Invalid admin username or password. ({$left} attempt(s) remaining)";
            }
        }
    }
}

// Check if logged in
$isLoggedIn = isAdminLoggedIn();

// -------------------------------------------------------------
// If NOT logged in: Render Sleek Dark Mode Login Screen
// -------------------------------------------------------------
if (!$isLoggedIn) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - Banglar Server Watcher</title>
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
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4 selection:bg-blue-600 selection:text-white">
  <div class="w-full max-w-md">
    
    <!-- Header / Brand -->
    <div class="text-center mb-8">
      <a href="index.php" class="inline-block transition-transform hover:scale-105" title="Banglar Server Watcher">
        <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-12 w-auto mx-auto object-contain mb-3 drop-shadow-sm" onerror="this.onerror=null; this.src='assets/logo.png';" />
      </a>
      <h1 class="text-xl font-extrabold text-white">Admin Control Portal</h1>
      <p class="text-xs text-slate-400 mt-1">Banglar Server Domain Availability &amp; Lead System</p>
    </div>

    <!-- Login Card -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl">
      <?php if ($loginError): ?>
        <div class="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-500/40 text-rose-200 text-xs flex items-center gap-3">
          <i class="fa-solid fa-circle-exclamation text-rose-400 text-base"></i>
          <span><?= e($loginError) ?></span>
        </div>
      <?php endif; ?>

      <form action="admin.php" method="POST" class="space-y-5">
        <input type="hidden" name="login_submit" value="1">
        <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">

        <div>
          <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Username</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3.5 pointer-events-none text-slate-500">
              <i class="fa-solid fa-user"></i>
            </span>
            <input type="text" name="username" required autocomplete="username" autofocus
              class="w-full bg-slate-950 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
          </div>
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3.5 pointer-events-none text-slate-500">
              <i class="fa-solid fa-lock"></i>
            </span>
            <input type="password" name="password" required autocomplete="current-password"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
          </div>
        </div>

        <button type="submit" class="w-full py-3.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm uppercase tracking-wider transition-all shadow-lg shadow-blue-600/30 hover:shadow-blue-500/50 active:scale-[0.99] cursor-pointer">
          Sign In to Dashboard &rarr;
        </button>
      </form>
    </div>

    <div class="text-center mt-6">
      <a href="index.php" class="text-xs text-slate-400 hover:text-blue-400 transition-colors">
        &larr; Back to Public Watcher
      </a>
    </div>

  </div>
</body>
</html>
<?php
exit;
}

// -------------------------------------------------------------
// LOGGED IN ACTIONS (POST / GET / AJAX)
// -------------------------------------------------------------

// 1. Single Domain Re-check (Supports both In-Row AJAX & Standard GET)
if ($action === 'recheck' && isset($_GET['id'])) {
    $id = (int)$_GET['id'];
    $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') || isset($_GET['ajax']);

    $stmt = $pdo->prepare("SELECT * FROM `watched_domains` WHERE `id` = ? LIMIT 1");
    $stmt->execute([$id]);
    $domainRow = $stmt->fetch();

    if ($domainRow) {
        $clean = cleanDomain($domainRow['domain_name']);
        $isAvailable = isDomainAvailable($clean);
        $newStatus = $isAvailable ? 'available' : 'registered';
        $wasRegistered = ($domainRow['status'] === 'registered');

        // Check if domain just dropped!
        if ($isAvailable && $wasRegistered && $domainRow['notified_available'] == 0) {
            $mailer = new BanglarSmtpMailer(getSmtpSettings($pdo), $adminSettings);
            if (!empty($domainRow['user_email'])) {
                $mailer->sendDropAlert($clean, $domainRow['user_email']);
            }
            $mailer->sendDropAlert($clean, $adminSettings['admin_email'], true);
            $notified = 1;
        } else {
            $notified = $isAvailable ? 1 : 0;
        }

        $stmtUp = $pdo->prepare("UPDATE `watched_domains` SET `status` = ?, `last_checked` = NOW(), `notified_available` = ? WHERE `id` = ?");
        $stmtUp->execute([$newStatus, $notified, $id]);

        $directBookingUrl = $bookingBaseUrl . urlencode($clean);

        if ($isAjax) {
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode([
                'success'      => true,
                'id'           => $id,
                'domain'       => $clean,
                'status'       => $newStatus,
                'status_upper' => strtoupper($newStatus),
                'booking_url'  => $directBookingUrl,
                'last_checked' => date('M d, Y H:i'),
                'message'      => $isAvailable ? 'Available Now!' : 'Still Registered'
            ]);
            exit;
        }

        $_SESSION['bs_flash_message'] = [
            'type' => 'success',
            'text' => "Domain {$clean} re-checked successfully! Current Status: " . strtoupper($newStatus)
        ];
    } else {
        if ($isAjax) {
            header('Content-Type: application/json; charset=UTF-8', true, 404);
            echo json_encode(['success' => false, 'message' => 'Domain record not found.']);
            exit;
        }
    }
    header("Location: admin.php");
    exit;
}

// 2. Edit Domain Row
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_edit_domain'])) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: admin.php");
        exit;
    }

    $editId = (int)($_POST['edit_id'] ?? 0);
    $rawDomain = $_POST['edit_domain'] ?? '';
    $rawEmail  = $_POST['edit_email'] ?? '';
    $rawName   = trim($_POST['edit_name'] ?? '');
    $rawPhone  = trim($_POST['edit_phone'] ?? '');
    $editStatus = $_POST['edit_status'] ?? 'registered';
    $editSource = trim($_POST['edit_source'] ?? 'Admin Panel');

    $clean = cleanDomain($rawDomain);
    $email = trim($rawEmail);
    $userName = !empty($rawName) ? $rawName : null;
    $userPhone = !empty($rawPhone) ? $rawPhone : null;
    $status = ($editStatus === 'available') ? 'available' : 'registered';

    if ($editId > 0 && !empty($clean) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $stmtEdit = $pdo->prepare("
            UPDATE `watched_domains`
            SET `domain_name` = ?,
                `user_email` = ?,
                `user_name` = ?,
                `user_phone` = ?,
                `status` = ?,
                `source_app` = ?
            WHERE `id` = ?
        ");
        $stmtEdit->execute([$clean, $email, $userName, $userPhone, $status, $editSource, $editId]);

        $_SESSION['bs_flash_message'] = [
            'type' => 'success',
            'text' => "Domain record for {$clean} updated successfully."
        ];
    } else {
        $_SESSION['bs_flash_message'] = [
            'type' => 'error',
            'text' => "Failed to update. Please check domain name and email address format."
        ];
    }
    header("Location: admin.php");
    exit;
}

// 3. Delete Domain Entry (Supports in-row AJAX & standard redirect)
if ($action === 'delete' && (isset($_GET['id']) || isset($_POST['id']))) {
    $id = (int)($_REQUEST['id'] ?? 0);
    $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') || isset($_REQUEST['ajax']);

    $token = $_REQUEST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!verifyCsrfToken($token)) {
        if ($isAjax) {
            header('Content-Type: application/json; charset=UTF-8', true, 403);
            echo json_encode(['success' => false, 'message' => 'Security check failed (Invalid or missing CSRF token).']);
            exit;
        }
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: admin.php");
        exit;
    }

    if ($id > 0) {
        $stmt = $pdo->prepare("DELETE FROM `watched_domains` WHERE `id` = ?");
        $stmt->execute([$id]);
    }

    if ($isAjax) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'success' => true,
            'id'      => $id,
            'message' => 'Watched domain removed successfully.'
        ]);
        exit;
    }

    $_SESSION['bs_flash_message'] = [
        'type' => 'success',
        'text' => "Watched domain removed successfully."
    ];
    header("Location: admin.php");
    exit;
}

// 4. Add Single or Multiple Domains from Admin Dashboard
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_add_domain'])) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: admin.php");
        exit;
    }

    $rawDomains = $_POST['domains'] ?? '';
    $userEmail = trim($_POST['user_email'] ?? $adminSettings['admin_email']);
    $rawName   = trim($_POST['user_name'] ?? '');
    $rawPhone  = trim($_POST['user_phone'] ?? '');

    $userName  = !empty($rawName) ? $rawName : null;
    $userPhone = !empty($rawPhone) ? $rawPhone : null;

    if (empty($userEmail)) {
        $userEmail = $adminSettings['admin_email'];
    }

    $entries = preg_split('/[\r\n,]+/', $rawDomains);
    $addedCount = 0;

    foreach ($entries as $raw) {
        $domain = cleanDomain($raw);
        if (empty($domain)) continue;

        $isAvailable = isDomainAvailable($domain);
        $status = $isAvailable ? 'available' : 'registered';
        $notified = $isAvailable ? 1 : 0;

        $stmtCheck = $pdo->prepare("SELECT id, user_name, user_phone FROM `watched_domains` WHERE `domain_name` = ? AND `user_email` = ? LIMIT 1");
        $stmtCheck->execute([$domain, $userEmail]);
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
                    `source_app` = 'Admin Panel' 
                WHERE `id` = ?
            ");
            $stmtUp->execute([$status, $notified, $finalName, $finalPhone, $existing['id']]);
        } else {
            $stmtIns = $pdo->prepare("
                INSERT INTO `watched_domains` (`domain_name`, `user_email`, `user_name`, `user_phone`, `added_by`, `source_app`, `status`, `last_checked`, `notified_available`, `created_at`) 
                VALUES (?, ?, ?, ?, 'admin', 'Admin Panel', ?, NOW(), ?, NOW())
            ");
            $stmtIns->execute([$domain, $userEmail, $userName, $userPhone, $status, $notified]);
        }
        $addedCount++;
    }

    $_SESSION['bs_flash_message'] = [
        'type' => 'success',
        'text' => "Successfully processed {$addedCount} domain(s) into watchlist."
    ];
    header("Location: admin.php");
    exit;
}

// -------------------------------------------------------------
// Fetch KPI Statistics
// -------------------------------------------------------------
$totalDomains = (int)$pdo->query("SELECT COUNT(*) FROM `watched_domains`")->fetchColumn();
$availableDomains = (int)$pdo->query("SELECT COUNT(*) FROM `watched_domains` WHERE `status` = 'available'")->fetchColumn();
$registeredDomains = (int)$pdo->query("SELECT COUNT(*) FROM `watched_domains` WHERE `status` = 'registered'")->fetchColumn();
$totalLeads = (int)$pdo->query("SELECT COUNT(DISTINCT `user_email`) FROM `watched_domains`")->fetchColumn();

// -------------------------------------------------------------
// Search, Filter & Pagination Query
// -------------------------------------------------------------
$search = trim($_GET['search'] ?? '');
$filterStatus = trim($_GET['status'] ?? '');
$filterSource = trim($_GET['source'] ?? '');

$whereSql = " WHERE 1=1";
$params = [];

if ($search !== '') {
    $whereSql .= " AND (`domain_name` LIKE ? OR `user_email` LIKE ? OR `user_name` LIKE ? OR `user_phone` LIKE ?)";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

if ($filterStatus === 'available') {
    $whereSql .= " AND `status` = 'available'";
} elseif ($filterStatus === 'registered') {
    $whereSql .= " AND `status` = 'registered'";
}

if ($filterSource === 'admin') {
    $whereSql .= " AND `added_by` = 'admin'";
} elseif ($filterSource === 'public') {
    $whereSql .= " AND `added_by` = 'public'";
} elseif ($filterSource === 'api') {
    $whereSql .= " AND `added_by` = 'api'";
}

// Pagination setup
$perPage = 10;
if (isset($_GET['per_page']) && in_array((int)$_GET['per_page'], [10, 25, 50, 100])) {
    $perPage = (int)$_GET['per_page'];
}

$stmtCount = $pdo->prepare("SELECT COUNT(*) FROM `watched_domains`" . $whereSql);
$stmtCount->execute($params);
$totalFilteredRows = (int)$stmtCount->fetchColumn();

$totalPages = max(1, (int)ceil($totalFilteredRows / $perPage));
$page = max(1, min((int)($_GET['page'] ?? 1), $totalPages));
$offset = ($page - 1) * $perPage;

$query = "SELECT * FROM `watched_domains`" . $whereSql . " ORDER BY `id` DESC LIMIT {$perPage} OFFSET {$offset}";
$stmtList = $pdo->prepare($query);
$stmtList->execute($params);
$domainList = $stmtList->fetchAll();

// Helper to build URL query with current filters
function buildQueryUrl(array $extraParams = []): string {
    $current = $_GET;
    unset($current['action'], $current['id'], $current['ajax']);
    $merged = array_merge($current, $extraParams);
    return 'admin.php?' . http_build_query($merged);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Watchlist Dashboard - Banglar Server Admin</title>
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
    .font-mono { font-family: 'JetBrains Mono', monospace; }
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
          Admin Portal
        </span>
      </div>

      <!-- Navigation Tabs -->
      <nav class="hidden md:flex items-center gap-1 lg:gap-2 shrink-0">
        <a href="admin.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-semibold bg-slate-800 text-blue-400 border border-blue-500/30 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-list-check text-blue-400"></i> <span>Watchlist</span>
        </a>
        <a href="api_manager.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-key text-amber-400"></i> <span>REST API Keys</span>
        </a>
        <a href="settings.php?tab=templates" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-envelope-open-text text-purple-400"></i> <span>Email Templates</span>
        </a>
        <a href="settings.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-sliders text-teal-400"></i> <span>Settings &amp; SMTP</span>
        </a>
      </nav>

      <!-- Action items -->
      <div class="flex items-center gap-2 sm:gap-3 shrink-0">
        <a href="cron.php?manual=1" target="_blank" title="Run WHOIS check on all domains & send Daily Report to Admin Email"
           class="inline-flex items-center gap-2 px-3 lg:px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 shrink-0" style="white-space: nowrap !important;">
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
      <a href="admin.php" class="font-bold text-blue-400 flex items-center gap-1">
        <i class="fa-solid fa-list-check"></i> Watchlist
      </a>
      <a href="api_manager.php" class="text-slate-400 hover:text-white flex items-center gap-1">
        <i class="fa-solid fa-key"></i> API Keys
      </a>
      <a href="settings.php?tab=templates" class="text-slate-400 hover:text-white flex items-center gap-1">
        <i class="fa-solid fa-envelope-open-text"></i> Templates
      </a>
      <a href="settings.php" class="text-slate-400 hover:text-white flex items-center gap-1">
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

    <!-- KPI Summary Row -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
      
      <!-- Total Domains -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 sm:p-6 flex items-center justify-between">
        <div>
          <span class="text-xs font-bold text-slate-400 uppercase tracking-wider">Total Watched</span>
          <div id="kpi-total" class="text-2xl sm:text-3xl font-extrabold text-white mt-1"><?= $totalDomains ?></div>
        </div>
        <div class="w-12 h-12 rounded-xl bg-slate-800 text-slate-300 flex items-center justify-center text-xl">
          <i class="fa-solid fa-globe"></i>
        </div>
      </div>

      <!-- Available Domains -->
      <div class="bg-slate-900 border border-emerald-500/30 rounded-2xl p-5 sm:p-6 flex items-center justify-between bg-gradient-to-br from-slate-900 to-emerald-950/20">
        <div>
          <span class="text-xs font-bold text-emerald-400 uppercase tracking-wider">Available Now</span>
          <div id="kpi-available" class="text-2xl sm:text-3xl font-extrabold text-emerald-400 mt-1"><?= $availableDomains ?></div>
        </div>
        <div class="w-12 h-12 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xl">
          <i class="fa-solid fa-circle-check"></i>
        </div>
      </div>

      <!-- Still Registered -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 sm:p-6 flex items-center justify-between">
        <div>
          <span class="text-xs font-bold text-amber-400 uppercase tracking-wider">Under Watch</span>
          <div id="kpi-registered" class="text-2xl sm:text-3xl font-extrabold text-amber-400 mt-1"><?= $registeredDomains ?></div>
        </div>
        <div class="w-12 h-12 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center text-xl">
          <i class="fa-solid fa-hourglass-half"></i>
        </div>
      </div>

      <!-- Total Unique Leads -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 sm:p-6 flex items-center justify-between">
        <div>
          <span class="text-xs font-bold text-sky-400 uppercase tracking-wider">Captured Leads</span>
          <div id="kpi-leads" class="text-2xl sm:text-3xl font-extrabold text-sky-400 mt-1"><?= $totalLeads ?></div>
        </div>
        <div class="w-12 h-12 rounded-xl bg-sky-500/20 text-sky-400 flex items-center justify-center text-xl">
          <i class="fa-solid fa-users"></i>
        </div>
      </div>

    </div>

    <!-- Quick Add Domain Section -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8">
      <div class="flex items-center justify-between mb-4">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-plus-circle text-blue-400"></i> Add Domains to Watchlist
          </h2>
          <p class="text-xs text-slate-400">Add single or multiple domains (separated by line or comma) for instant WHOIS verification &amp; 24/7 monitoring.</p>
        </div>
      </div>

      <form action="admin.php" method="POST" class="space-y-4">
        <input type="hidden" name="admin_add_domain" value="1">
        <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
        
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div class="md:col-span-2">
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Domains</label>
            <textarea name="domains" required rows="3" placeholder="banglarserver.com, techbd.xyz, cloudhost.io (or one per line)"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono"></textarea>
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">User / Alert Email</label>
            <input type="email" name="user_email" placeholder="<?= e($adminSettings['admin_email']) ?>"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm mb-2">
            <label class="block text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Lead Name (Optional)</label>
            <input type="text" name="user_name" placeholder="e.g. Tanvir Ahmed"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-xs">
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Phone / WhatsApp</label>
            <input type="text" name="user_phone" placeholder="e.g. +8801712345678"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm mb-2">
            <p class="text-[11px] text-slate-400 leading-tight">Stored in lead record for direct calling &amp; 1-click WhatsApp messaging.</p>
          </div>
        </div>

        <div class="flex justify-end">
          <button type="submit" class="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
            <i class="fa-solid fa-bolt mr-1"></i> Add &amp; Run WHOIS Check Now
          </button>
        </div>
      </form>
    </div>

    <!-- Watchlist Table & Filter Bar -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      
      <!-- Filter Bar -->
      <div class="p-6 border-b border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-list text-blue-400"></i> Monitored Domains Watchlist
          </h2>
          <p class="text-xs text-slate-400">
            Showing <?= $totalFilteredRows > 0 ? ($offset + 1) : 0 ?> - <?= min($offset + $perPage, $totalFilteredRows) ?> of <?= $totalFilteredRows ?> active entries
          </p>
        </div>

        <!-- Filters Form -->
        <form action="admin.php" method="GET" class="flex flex-wrap items-center gap-2 w-full md:w-auto">
          
          <!-- Search -->
          <div class="relative flex-grow sm:flex-grow-0">
            <input type="text" name="search" value="<?= e($search) ?>" placeholder="Search domain or email..."
              class="bg-slate-950 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 w-full sm:w-48">
            <i class="fa-solid fa-magnifying-glass absolute left-2.5 top-2 text-slate-500 text-xs"></i>
          </div>

          <!-- Status Filter -->
          <select name="status" onchange="this.form.submit()" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
            <option value="">All Statuses</option>
            <option value="available" <?= $filterStatus === 'available' ? 'selected' : '' ?>>Available</option>
            <option value="registered" <?= $filterStatus === 'registered' ? 'selected' : '' ?>>Registered</option>
          </select>

          <!-- Source Filter -->
          <select name="source" onchange="this.form.submit()" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
            <option value="">All Sources</option>
            <option value="admin" <?= $filterSource === 'admin' ? 'selected' : '' ?>>Admin</option>
            <option value="public" <?= $filterSource === 'public' ? 'selected' : '' ?>>Public Web</option>
            <option value="api" <?= $filterSource === 'api' ? 'selected' : '' ?>>REST API</option>
          </select>

          <!-- Per Page Selector -->
          <select name="per_page" onchange="this.form.submit()" class="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-400 focus:outline-none focus:border-emerald-500" title="Rows per page">
            <option value="10" <?= $perPage === 10 ? 'selected' : '' ?>>10 / page</option>
            <option value="25" <?= $perPage === 25 ? 'selected' : '' ?>>25 / page</option>
            <option value="50" <?= $perPage === 50 ? 'selected' : '' ?>>50 / page</option>
          </select>

          <?php if ($search || $filterStatus || $filterSource): ?>
            <a href="admin.php" class="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white text-xs" title="Reset Filters">
              <i class="fa-solid fa-xmark"></i>
            </a>
          <?php endif; ?>

        </form>
      </div>

      <!-- Responsive Table -->
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="bg-slate-950/50 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
              <th class="py-3.5 px-4 font-semibold">Domain Name</th>
              <th class="py-3.5 px-4 font-semibold">User Email / Lead</th>
              <th class="py-3.5 px-4 font-semibold">Source</th>
              <th class="py-3.5 px-4 font-semibold text-center">Status</th>
              <th class="py-3.5 px-4 font-semibold">Last Checked</th>
              <th class="py-3.5 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800" id="domain-table-body">
            <?php if (empty($domainList)): ?>
              <tr>
                <td colspan="6" class="py-12 text-center text-slate-500">
                  <i class="fa-solid fa-inbox text-3xl mb-3 block"></i>
                  No watched domains found matching criteria.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($domainList as $row): 
                $isAvail = ($row['status'] === 'available');
                $bookingLink = $bookingBaseUrl . urlencode($row['domain_name']);
              ?>
                <tr id="row-<?= $row['id'] ?>" class="hover:bg-slate-850/50 transition-colors">
                  
                  <!-- Domain -->
                  <td class="py-4 px-4 font-bold text-white font-mono text-sm">
                    <span class="flex items-center gap-2">
                      <i id="icon-<?= $row['id'] ?>" class="fa-solid fa-globe text-xs <?= $isAvail ? 'text-emerald-400' : 'text-slate-500' ?>"></i>
                      <span id="domain-text-<?= $row['id'] ?>"><?= e($row['domain_name']) ?></span>
                    </span>
                  </td>

                  <!-- User Email / Lead Details -->
                  <td class="py-4 px-4 text-xs">
                    <?php if (!empty($row['user_name'])): ?>
                      <div class="font-semibold text-white flex items-center gap-1.5 mb-1">
                        <i class="fa-solid fa-circle-user text-emerald-400 text-xs"></i>
                        <span><?= e($row['user_name']) ?></span>
                      </div>
                    <?php endif; ?>

                    <div class="flex items-center gap-1 text-sky-400">
                      <a id="email-link-<?= $row['id'] ?>" href="mailto:<?= e($row['user_email']) ?>" class="hover:underline flex items-center gap-1">
                        <i class="fa-regular fa-envelope text-[11px] text-slate-400"></i>
                        <span><?= e($row['user_email']) ?></span>
                      </a>
                    </div>

                    <?php if (!empty($row['user_phone'])): 
                      $cleanPhone = preg_replace('/[^0-9]/', '', $row['user_phone']);
                    ?>
                      <div class="flex items-center gap-2 mt-1.5 text-[11px]">
                        <a href="tel:<?= e($row['user_phone']) ?>" class="text-slate-300 hover:text-white flex items-center gap-1 font-mono">
                          <i class="fa-solid fa-phone text-slate-500 text-[10px]"></i>
                          <?= e($row['user_phone']) ?>
                        </a>
                        <?php if (!empty($cleanPhone)): ?>
                          <a href="https://wa.me/<?= e($cleanPhone) ?>" target="_blank" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 border border-emerald-500/30 text-[10px] font-semibold transition-colors" title="Message on WhatsApp">
                            <i class="fa-brands fa-whatsapp text-emerald-400"></i> WhatsApp
                          </a>
                        <?php endif; ?>
                      </div>
                    <?php endif; ?>
                  </td>

                  <!-- Source Badge -->
                  <td class="py-4 px-4 text-xs">
                    <span id="source-badge-<?= $row['id'] ?>">
                      <?php if ($row['added_by'] === 'admin'): ?>
                        <span class="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30 font-medium">Admin</span>
                      <?php elseif ($row['added_by'] === 'api'): ?>
                        <span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-medium">
                          API: <?= e($row['source_app']) ?>
                        </span>
                      <?php else: ?>
                        <span class="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 font-medium">Public Web</span>
                      <?php endif; ?>
                    </span>
                  </td>

                  <!-- Status Badge -->
                  <td class="py-4 px-4 text-center">
                    <span id="status-badge-<?= $row['id'] ?>">
                      <?php if ($isAvail): ?>
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> AVAILABLE
                        </span>
                      <?php else: ?>
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> REGISTERED
                        </span>
                      <?php endif; ?>
                    </span>
                  </td>

                  <!-- Last Checked -->
                  <td class="py-4 px-4 text-xs text-slate-400" id="last-checked-<?= $row['id'] ?>">
                    <?= !empty($row['last_checked']) ? date('M d, Y H:i', strtotime($row['last_checked'])) : '<span class="text-slate-600">Never</span>' ?>
                  </td>

                  <!-- Actions -->
                  <td class="py-4 px-4 text-right space-x-1.5 text-xs whitespace-nowrap">
                    
                    <!-- Dynamic Book Button -->
                    <span id="book-btn-wrapper-<?= $row['id'] ?>">
                      <?php if ($isAvail): ?>
                        <a href="<?= e($bookingLink) ?>" target="_blank" class="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold transition-all shadow-sm shadow-blue-600/25">
                          <i class="fa-solid fa-cart-shopping"></i> Book
                        </a>
                      <?php endif; ?>
                    </span>

                    <!-- In-Row AJAX Recheck Button (NO Page Refresh!) -->
                    <button type="button" 
                            id="check-btn-<?= $row['id'] ?>"
                            onclick="recheckDomainAjax(<?= $row['id'] ?>, this)"
                            class="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer" 
                            title="Instant WHOIS re-check without page refresh">
                      <i class="fa-solid fa-rotate text-blue-400"></i> Check
                    </button>

                    <!-- Edit Row Button -->
                    <button type="button"
                            onclick="openEditModal(<?= htmlspecialchars(json_encode([
                              'id' => $row['id'],
                              'domain_name' => $row['domain_name'],
                              'user_email' => $row['user_email'],
                              'user_name' => $row['user_name'] ?? '',
                              'user_phone' => $row['user_phone'] ?? '',
                              'status' => $row['status'],
                              'source_app' => $row['source_app']
                            ]), ENT_QUOTES, 'UTF-8') ?>)"
                            class="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-blue-400 border border-slate-700 transition-colors cursor-pointer"
                            title="Edit Domain Record">
                      <i class="fa-solid fa-pen-to-square"></i>
                    </button>

                    <!-- Delete Button -->
                    <button type="button"
                            onclick="confirmDeleteDomain(<?= $row['id'] ?>, '<?= addslashes(e($row['domain_name'])) ?>')"
                            class="inline-flex items-center px-2 py-1 rounded bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700 transition-colors cursor-pointer" 
                            title="Delete Domain">
                      <i class="fa-solid fa-trash-can pointer-events-none"></i>
                    </button>

                    <!-- In-Row Micro Status Indicator Box -->
                    <div id="row-feedback-<?= $row['id'] ?>" class="text-[11px] font-semibold mt-1"></div>

                  </td>

                </tr>
              <?php endforeach; ?>
            <?php endif; ?>
          </tbody>
        </table>
      </div>

      <!-- Pagination Footer Bar -->
      <?php if ($totalFilteredRows > 0): ?>
        <div class="p-4 sm:p-6 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          
          <!-- Summary Text -->
          <div>
            Showing <span class="font-bold text-white"><?= $offset + 1 ?></span> to <span class="font-bold text-white"><?= min($offset + $perPage, $totalFilteredRows) ?></span> of <span class="font-bold text-white"><?= $totalFilteredRows ?></span> domains
          </div>

          <!-- Pagination Controls -->
          <div class="flex items-center gap-1">
            
            <!-- Previous Button -->
            <?php if ($page > 1): ?>
              <a href="<?= e(buildQueryUrl(['page' => $page - 1])) ?>" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors">
                &larr; Prev
              </a>
            <?php else: ?>
              <span class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-600 border border-slate-800 cursor-not-allowed">
                &larr; Prev
              </span>
            <?php endif; ?>

            <!-- Page Number Links -->
            <?php
            $startPage = max(1, $page - 2);
            $endPage = min($totalPages, $page + 2);

            if ($startPage > 1) {
                echo '<a href="' . e(buildQueryUrl(['page' => 1])) . '" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">1</a>';
                if ($startPage > 2) echo '<span class="px-1 text-slate-600">...</span>';
            }

            for ($p = $startPage; $p <= $endPage; $p++):
                $isCurrent = ($p === $page);
            ?>
              <a href="<?= e(buildQueryUrl(['page' => $p])) ?>" 
                 class="px-3 py-1.5 rounded-lg font-bold border transition-all <?= $isCurrent ? 'bg-blue-600 text-white border-blue-600 shadow-sm' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700' ?>">
                <?= $p ?>
              </a>
            <?php endfor; ?>

            <?php
            if ($endPage < $totalPages) {
                if ($endPage < $totalPages - 1) echo '<span class="px-1 text-slate-600">...</span>';
                echo '<a href="' . e(buildQueryUrl(['page' => $totalPages])) . '" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">' . $totalPages . '</a>';
            }
            ?>

            <!-- Next Button -->
            <?php if ($page < $totalPages): ?>
              <a href="<?= e(buildQueryUrl(['page' => $page + 1])) ?>" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors">
                Next &rarr;
              </a>
            <?php else: ?>
              <span class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-600 border border-slate-800 cursor-not-allowed">
                Next &rarr;
              </span>
            <?php endif; ?>

          </div>

        </div>
      <?php endif; ?>

    </div>

  </main>

  <!-- Edit Row Modal (Clean Dark Mode Dialog) -->
  <div id="editModal" class="fixed inset-0 z-50 hidden bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 sm:p-8 shadow-2xl space-y-6 relative animate-fadeIn">
      
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-pen-to-square text-blue-400"></i> Edit Domain Record
        </h3>
        <button type="button" onclick="closeEditModal()" class="text-slate-400 hover:text-white text-xl p-1">
          &times;
        </button>
      </div>

      <form action="admin.php" method="POST" class="space-y-4">
        <input type="hidden" name="admin_edit_domain" value="1">
        <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
        <input type="hidden" id="edit_id" name="edit_id" value="">

        <div>
          <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Domain Name</label>
          <input type="text" id="edit_domain" name="edit_domain" required
            class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono">
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">User Email / Lead</label>
          <input type="email" id="edit_email" name="edit_email" required
            class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Lead Full Name</label>
            <input type="text" id="edit_name" name="edit_name" placeholder="Lead Name"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Lead Phone / WhatsApp</label>
            <input type="text" id="edit_phone" name="edit_phone" placeholder="e.g. +8801712345678"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm">
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Status</label>
            <select id="edit_status" name="edit_status" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 text-sm">
              <option value="registered">Registered</option>
              <option value="available">Available</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Source App / Label</label>
            <input type="text" id="edit_source" name="edit_source"
              class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 text-sm">
          </div>
        </div>

        <div class="flex justify-end gap-3 pt-4 border-t border-slate-800">
          <button type="button" onclick="closeEditModal()" class="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer">
            Cancel
          </button>
          <button type="submit" class="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-blue-600/25 cursor-pointer">
            Save Changes
          </button>
        </div>
      </form>

    </div>
  </div>

  <!-- Delete Confirmation Modal (Custom Dark UI) -->
  <div id="deleteModal" class="fixed inset-0 z-50 hidden bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 sm:p-7 shadow-2xl space-y-5 relative animate-fadeIn">
      <div class="flex items-start gap-4">
        <div class="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center shrink-0 text-rose-400 text-xl">
          <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div class="space-y-1">
          <h3 class="text-base font-bold text-white">Delete Watched Domain?</h3>
          <p class="text-xs text-slate-400 leading-relaxed">
            Are you sure you want to remove <span id="deleteDomainTarget" class="font-bold text-white font-mono"></span> from the watchlist? Automated WHOIS monitoring and drop alerts will cease immediately.
          </p>
        </div>
      </div>

      <div class="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
        <button type="button" onclick="closeDeleteModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer">
          Cancel
        </button>
        <button type="button" id="confirmDeleteBtn" onclick="executeDeleteDomain()" class="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-rose-600/30 flex items-center gap-1.5 cursor-pointer">
          <i class="fa-solid fa-trash-can"></i> Yes, Delete
        </button>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
    Banglar Server Domain Availability Watcher &bull; Logged in as <span class="text-blue-400 font-semibold"><?= e($_SESSION['bs_admin_user']) ?></span> &bull; &copy; <?= date('Y') ?> Banglar Server
  </footer>

  <!-- Live In-Row AJAX & Modal JavaScript -->
  <script>
    // -------------------------------------------------------------
    // 1. Live In-Row WHOIS Re-check without Page Refresh
    // -------------------------------------------------------------
    async function recheckDomainAjax(id, btn) {
      const origContent = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-blue-400"></i> Checking...';

      const feedback = document.getElementById('row-feedback-' + id);
      if (feedback) {
        feedback.innerHTML = '<span class="text-slate-400"><i class="fa-solid fa-satellite-dish fa-spin mr-1"></i> Querying WHOIS socket...</span>';
      }

      try {
        const response = await fetch('admin.php?action=recheck&id=' + id + '&ajax=1', {
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          }
        });

        const data = await response.json();

        if (data.success) {
          // Update Status Badge in that row
          const statusBadge = document.getElementById('status-badge-' + id);
          const iconEl = document.getElementById('icon-' + id);
          const bookWrapper = document.getElementById('book-btn-wrapper-' + id);

          if (data.status === 'available') {
            statusBadge.innerHTML = `
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 animate-pulse">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> AVAILABLE
              </span>
            `;
            if (iconEl) {
              iconEl.className = 'fa-solid fa-globe text-xs text-emerald-400';
            }
            if (bookWrapper) {
              bookWrapper.innerHTML = `
                <a href="${data.booking_url}" target="_blank" class="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold transition-all shadow-sm">
                  <i class="fa-solid fa-cart-shopping"></i> Book
                </a>
              `;
            }
            if (feedback) {
              feedback.innerHTML = '<span class="text-emerald-400 animate-fadeIn">✓ Dropped &amp; Available!</span>';
            }
          } else {
            statusBadge.innerHTML = `
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> REGISTERED
              </span>
            `;
            if (iconEl) {
              iconEl.className = 'fa-solid fa-globe text-xs text-slate-500';
            }
            if (bookWrapper) {
              bookWrapper.innerHTML = '';
            }
            if (feedback) {
              feedback.innerHTML = '<span class="text-amber-400 animate-fadeIn">✓ Still Registered</span>';
            }
          }

          // Update Last Checked timestamp
          const lastChecked = document.getElementById('last-checked-' + id);
          if (lastChecked) {
            lastChecked.innerText = data.last_checked;
          }

          // Clear in-row micro text after 4 seconds
          setTimeout(() => {
            if (feedback) feedback.innerHTML = '';
          }, 4000);

        } else {
          if (feedback) {
            feedback.innerHTML = '<span class="text-rose-400">Error re-checking</span>';
          }
        }

      } catch (err) {
        if (feedback) {
          feedback.innerHTML = '<span class="text-rose-400">Connection error</span>';
        }
      } finally {
        btn.disabled = false;
        btn.innerHTML = origContent;
      }
    }

    // -------------------------------------------------------------
    // 2. Edit Modal Controller
    // -------------------------------------------------------------
    function openEditModal(data) {
      document.getElementById('edit_id').value = data.id;
      document.getElementById('edit_domain').value = data.domain_name;
      document.getElementById('edit_email').value = data.user_email;
      document.getElementById('edit_name').value = data.user_name || '';
      document.getElementById('edit_phone').value = data.user_phone || '';
      document.getElementById('edit_status').value = data.status;
      document.getElementById('edit_source').value = data.source_app || '';

      const modal = document.getElementById('editModal');
      modal.classList.remove('hidden');
    }

    function closeEditModal() {
      const modal = document.getElementById('editModal');
      modal.classList.add('hidden');
    }

    // Close on click backdrop
    document.getElementById('editModal').addEventListener('click', (e) => {
      if (e.target === document.getElementById('editModal')) {
        closeEditModal();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeEditModal();
        closeDeleteModal();
      }
    });

    // -------------------------------------------------------------
    // 3. Custom Delete Modal & In-Row AJAX Removal
    // -------------------------------------------------------------
    let domainToDeleteId = null;

    function confirmDeleteDomain(id, domainName) {
      domainToDeleteId = id;
      const target = document.getElementById('deleteDomainTarget');
      if (target) target.textContent = domainName;
      const modal = document.getElementById('deleteModal');
      if (modal) modal.classList.remove('hidden');
    }

    function closeDeleteModal() {
      domainToDeleteId = null;
      const modal = document.getElementById('deleteModal');
      if (modal) modal.classList.add('hidden');
    }

    // Close delete modal on backdrop click
    document.getElementById('deleteModal').addEventListener('click', (e) => {
      if (e.target === document.getElementById('deleteModal')) {
        closeDeleteModal();
      }
    });

    async function executeDeleteDomain() {
      if (!domainToDeleteId) return;
      const id = domainToDeleteId;
      const btn = document.getElementById('confirmDeleteBtn');
      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

      try {
        const csrfToken = '<?= e(getCsrfToken()) ?>';
        const res = await fetch('admin.php?action=delete&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken) + '&ajax=1', {
          headers: { 
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRF-Token': csrfToken
          }
        });
        const data = await res.json();

        if (data.success) {
          closeDeleteModal();
          const row = document.getElementById('row-' + id);
          if (row) {
            row.style.transition = 'all 0.35s ease';
            row.style.opacity = '0';
            row.style.transform = 'translateX(20px)';
            setTimeout(() => row.remove(), 350);
          }
          showToast('✓ Domain removed from watchlist.');
        } else {
          alert('Failed to delete domain: ' + (data.message || 'Unknown error'));
        }
      } catch (err) {
        // Fallback to standard HTTP GET request
        window.location.href = 'admin.php?action=delete&id=' + id;
      } finally {
        btn.disabled = false;
        btn.innerHTML = origText;
      }
    }

    function showToast(msg) {
      let toast = document.getElementById('adminToast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'adminToast';
        toast.className = 'fixed bottom-5 right-5 z-50 bg-slate-900 border border-slate-700 text-white px-4 py-3 rounded-xl shadow-2xl text-xs flex items-center gap-2.5 transition-all duration-300 transform translate-y-10 opacity-0';
        document.body.appendChild(toast);
      }
      toast.innerHTML = '<i class="fa-solid fa-circle-check text-blue-400 text-base"></i> <span class="font-medium">' + msg + '</span>';
      toast.classList.remove('translate-y-10', 'opacity-0');
      setTimeout(() => {
        toast.classList.add('translate-y-10', 'opacity-0');
      }, 3500);
    }
  </script>

</body>
</html>
