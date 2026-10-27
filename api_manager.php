<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Admin API Key Manager & Developer Integration Center
 */

require_once __DIR__ . '/config.php';
requireAdminAuth();

$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$logoUrl = !empty($adminSettings['logo_url']) ? $adminSettings['logo_url'] : 'assets/logo.png';

$flashMessage = $_SESSION['bs_flash_message'] ?? null;
unset($_SESSION['bs_flash_message']);

$action = $_GET['action'] ?? '';

// 1. Generate New API Key Pair
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_api_key'])) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: api_manager.php");
        exit;
    }

    $appName = trim($_POST['app_name'] ?? '');
    if (empty($appName)) {
        $appName = 'External Integration ' . date('Y-m-d');
    }

    $apiKey = 'bs_live_' . bin2hex(random_bytes(16));
    $secretKey = 'bs_sec_' . bin2hex(random_bytes(24));

    $stmt = $pdo->prepare("INSERT INTO `api_keys` (`app_name`, `api_key`, `secret_key`, `status`, `total_requests`, `created_at`) VALUES (?, ?, ?, 'active', 0, NOW())");
    $stmt->execute([$appName, $apiKey, $secretKey]);

    $_SESSION['bs_flash_message'] = [
        'type' => 'success',
        'text' => "New API credentials generated successfully for '{$appName}'."
    ];
    header("Location: api_manager.php");
    exit;
}

// 2. Toggle Status (Active / Revoked)
if ($action === 'toggle_status' && isset($_GET['id'])) {
    if (!verifyCsrfToken($_GET['csrf_token'] ?? '')) {
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: api_manager.php");
        exit;
    }

    $id = (int)$_GET['id'];
    $stmt = $pdo->prepare("SELECT `status`, `app_name` FROM `api_keys` WHERE `id` = ? LIMIT 1");
    $stmt->execute([$id]);
    $keyRow = $stmt->fetch();

    if ($keyRow) {
        $newStatus = ($keyRow['status'] === 'active') ? 'revoked' : 'active';
        $stmtUp = $pdo->prepare("UPDATE `api_keys` SET `status` = ? WHERE `id` = ?");
        $stmtUp->execute([$newStatus, $id]);

        $_SESSION['bs_flash_message'] = [
            'type' => 'success',
            'text' => "API Key for '{$keyRow['app_name']}' is now " . strtoupper($newStatus) . "."
        ];
    }
    header("Location: api_manager.php");
    exit;
}

// 3. Delete API Key
if ($action === 'delete' && (isset($_GET['id']) || isset($_POST['id']))) {
    $token = $_REQUEST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') || isset($_REQUEST['ajax']);

    if (!verifyCsrfToken($token)) {
        if ($isAjax) {
            header('Content-Type: application/json; charset=UTF-8', true, 403);
            echo json_encode(['success' => false, 'message' => 'Security check failed (Invalid CSRF token).']);
            exit;
        }
        $_SESSION['bs_flash_message'] = ['type' => 'error', 'text' => 'Security check failed (Invalid CSRF token).'];
        header("Location: api_manager.php");
        exit;
    }

    $id = (int)($_REQUEST['id'] ?? 0);

    if ($id > 0) {
        $stmt = $pdo->prepare("DELETE FROM `api_keys` WHERE `id` = ?");
        $stmt->execute([$id]);
    }

    if ($isAjax) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'success' => true,
            'id'      => $id,
            'message' => 'API Key deleted successfully.'
        ]);
        exit;
    }

    $_SESSION['bs_flash_message'] = [
        'type' => 'success',
        'text' => "API Key deleted permanently."
    ];
    header("Location: api_manager.php");
    exit;
}

// Fetch all keys
$stmtKeys = $pdo->query("SELECT * FROM `api_keys` ORDER BY `id` DESC");
$apiKeys = $stmtKeys->fetchAll();

// Determine base API endpoint URL
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$baseDir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
$apiEndpoint = $protocol . $host . $baseDir . '/api.php';

// First key for sample snippet
$firstKey = !empty($apiKeys) ? $apiKeys[0]['api_key'] : 'bs_live_your_api_key_here';
$firstSecret = !empty($apiKeys) ? $apiKeys[0]['secret_key'] : 'bs_sec_your_secret_key_here';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Key Manager - Banglar Server Admin</title>
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
        <span class="hidden sm:inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 uppercase tracking-wider shrink-0" style="white-space: nowrap !important;">
          API Management
        </span>
      </div>

      <!-- Navigation Tabs -->
      <nav class="hidden md:flex items-center gap-1 lg:gap-2 shrink-0">
        <a href="admin.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 shrink-0 transition-colors" style="white-space: nowrap !important;">
          <i class="fa-solid fa-list-check text-blue-400"></i> <span>Watchlist</span>
        </a>
        <a href="api_manager.php" class="inline-flex items-center gap-1.5 px-3 lg:px-4 py-2 rounded-lg text-xs lg:text-sm font-semibold bg-slate-800 text-amber-400 border border-slate-700 shrink-0 transition-colors" style="white-space: nowrap !important;">
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
      <a href="api_manager.php" class="font-bold text-amber-400 flex items-center gap-1">
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
      <div class="p-4 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-200 text-sm flex items-center justify-between">
        <div class="flex items-center gap-3">
          <i class="fa-solid fa-circle-check text-emerald-400 text-lg"></i>
          <span><?= e($flashMessage['text']) ?></span>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white">&times;</button>
      </div>
    <?php endif; ?>

    <!-- Header Section -->
    <div class="bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
      <div>
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <i class="fa-solid fa-shield-halved"></i> Dual-Key Authentication
        </div>
        <h1 class="text-2xl font-extrabold text-white">External REST API Management</h1>
        <p class="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
          Connect your WordPress websites, WHMCS order forms, custom landing pages, or mobile apps directly to Banglar Server Domain Watcher without requiring visitor accounts.
        </p>
      </div>

      <!-- Quick Endpoint Box -->
      <div class="bg-slate-950 border border-slate-700/80 rounded-xl p-3.5 w-full md:w-auto">
        <span class="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">API Endpoint (POST)</span>
        <div class="flex items-center gap-2">
          <code class="text-xs text-emerald-400 font-mono select-all"><?= e($apiEndpoint) ?></code>
          <button onclick="copyToClipboard('<?= e($apiEndpoint) ?>', this)" class="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white text-xs" title="Copy Endpoint">
            <i class="fa-solid fa-copy"></i>
          </button>
        </div>
      </div>
    </div>

    <!-- Generate Key Card -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8">
      <h2 class="text-lg font-bold text-white flex items-center gap-2 mb-2">
        <i class="fa-solid fa-plus-circle text-amber-400"></i> Generate New API Key Pair
      </h2>
      <p class="text-xs text-slate-400 mb-6">Create dedicated credentials for each app to track request volume and revoke access individually if needed.</p>

      <form action="api_manager.php" method="POST" class="flex flex-col sm:flex-row items-center gap-4">
        <input type="hidden" name="create_api_key" value="1">
        <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
        <div class="w-full sm:flex-grow">
          <input type="text" name="app_name" placeholder="App or Website Name (e.g., WHMCS Order Form, Client Portal, Landing Page)" required
            class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 text-sm">
        </div>
        <button type="submit" class="w-full sm:w-auto shrink-0 px-6 py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-md cursor-pointer">
          <i class="fa-solid fa-key mr-1.5"></i> Generate Key Pair
        </button>
      </form>
    </div>

    <!-- API Keys List -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      <div class="p-6 border-b border-slate-800">
        <h2 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-database text-amber-400"></i> Active &amp; Revoked API Credentials
        </h2>
        <p class="text-xs text-slate-400">Total <?= count($apiKeys) ?> client key pairs registered</p>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="bg-slate-950/50 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
              <th class="py-3.5 px-4 font-semibold">Application Name</th>
              <th class="py-3.5 px-4 font-semibold">API Key (Public)</th>
              <th class="py-3.5 px-4 font-semibold">Secret Key (Private)</th>
              <th class="py-3.5 px-4 font-semibold text-center">Status</th>
              <th class="py-3.5 px-4 font-semibold text-center">Requests</th>
              <th class="py-3.5 px-4 font-semibold">Last Used</th>
              <th class="py-3.5 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            <?php if (empty($apiKeys)): ?>
              <tr>
                <td colspan="7" class="py-12 text-center text-slate-500">
                  <i class="fa-solid fa-key text-3xl mb-3 block"></i>
                  No API keys generated yet. Use the form above to create your first API key pair.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($apiKeys as $key): 
                $isActive = ($key['status'] === 'active');
              ?>
                <tr id="key-row-<?= $key['id'] ?>" class="hover:bg-slate-850/50 transition-colors">
                  
                  <!-- App Name -->
                  <td class="py-4 px-4 font-bold text-white text-sm">
                    <div class="flex items-center gap-2">
                      <div class="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center text-amber-400 text-xs">
                        <i class="fa-solid fa-cube"></i>
                      </div>
                      <div>
                        <span><?= e($key['app_name']) ?></span>
                        <div class="text-[11px] text-slate-500 font-normal">Created: <?= date('M d, Y', strtotime($key['created_at'])) ?></div>
                      </div>
                    </div>
                  </td>

                  <!-- API Key -->
                  <td class="py-4 px-4 text-xs font-mono text-slate-300">
                    <div class="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 max-w-xs">
                      <span class="truncate"><?= e($key['api_key']) ?></span>
                      <button onclick="copyToClipboard('<?= e($key['api_key']) ?>', this)" class="text-slate-400 hover:text-white shrink-0 ml-1" title="Copy API Key">
                        <i class="fa-solid fa-copy"></i>
                      </button>
                    </div>
                  </td>

                  <!-- Secret Key (Masked with toggle) -->
                  <td class="py-4 px-4 text-xs font-mono text-slate-300">
                    <div class="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 max-w-xs">
                      <span id="secret_<?= $key['id'] ?>" class="truncate">••••••••••••••••••••••••</span>
                      <button onclick="toggleSecret('secret_<?= $key['id'] ?>', '<?= e($key['secret_key']) ?>', this)" class="text-slate-400 hover:text-white shrink-0 ml-1" title="Reveal/Hide Secret">
                        <i class="fa-solid fa-eye"></i>
                      </button>
                      <button onclick="copyToClipboard('<?= e($key['secret_key']) ?>', this)" class="text-slate-400 hover:text-white shrink-0" title="Copy Secret">
                        <i class="fa-solid fa-copy"></i>
                      </button>
                    </div>
                  </td>

                  <!-- Status -->
                  <td class="py-4 px-4 text-center">
                    <?php if ($isActive): ?>
                      <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        ACTIVE
                      </span>
                    <?php else: ?>
                      <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                        REVOKED
                      </span>
                    <?php endif; ?>
                  </td>

                  <!-- Total Requests -->
                  <td class="py-4 px-4 text-center font-bold text-white font-mono text-xs">
                    <?= number_format($key['total_requests']) ?>
                  </td>

                  <!-- Last Used -->
                  <td class="py-4 px-4 text-xs text-slate-400">
                    <?= !empty($key['last_used_at']) ? date('M d, H:i', strtotime($key['last_used_at'])) : '<span class="text-slate-600">Never</span>' ?>
                  </td>

                  <!-- Actions -->
                  <td class="py-4 px-4 text-right space-x-2 text-xs">
                    <a href="api_manager.php?action=toggle_status&id=<?= $key['id'] ?>&csrf_token=<?= e(getCsrfToken()) ?>" 
                       class="inline-flex items-center px-2.5 py-1 rounded <?= $isActive ? 'bg-slate-800 hover:bg-amber-950 text-slate-300 hover:text-amber-400' : 'bg-emerald-950 text-emerald-400 hover:bg-emerald-900' ?> border border-slate-700 transition-colors">
                      <?= $isActive ? 'Revoke' : 'Activate' ?>
                    </a>

                    <button type="button"
                            onclick="confirmDeleteApiKey(<?= $key['id'] ?>, '<?= addslashes(e($key['app_name'])) ?>')" 
                            class="inline-flex items-center px-2 py-1 rounded bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700 transition-colors cursor-pointer" 
                            title="Delete Key">
                      <i class="fa-solid fa-trash-can pointer-events-none"></i>
                    </button>
                  </td>

                </tr>
              <?php endforeach; ?>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Integration Code Snippets Card -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-code text-blue-400"></i> Copy &amp; Paste Integration Snippets
          </h2>
          <p class="text-xs text-slate-400">Plug domain checking and drop watching into any custom site or WHMCS page.</p>
        </div>

        <!-- Language Tabs -->
        <div class="flex items-center gap-2 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs">
          <button onclick="switchTab('php')" id="tab_php" class="px-3.5 py-1.5 rounded-lg font-bold bg-blue-600 text-white transition-all shadow-sm">PHP cURL</button>
          <button onclick="switchTab('js')" id="tab_js" class="px-3.5 py-1.5 rounded-lg font-medium text-slate-400 hover:text-white transition-all">JavaScript Fetch</button>
          <button onclick="switchTab('curl')" id="tab_curl" class="px-3.5 py-1.5 rounded-lg font-medium text-slate-400 hover:text-white transition-all">cURL CLI</button>
        </div>
      </div>

      <!-- Code Box: PHP cURL -->
      <div id="code_php" class="relative group">
        <pre class="bg-slate-950 border border-slate-800 rounded-xl p-5 text-xs text-slate-200 overflow-x-auto leading-relaxed"><code>&lt;?php
$apiUrl = '<?= e($apiEndpoint) ?>';
$apiKey = '<?= e($firstKey) ?>';
$apiSecret = '<?= e($firstSecret) ?>';

$payload = json_encode([
    'domain' =&gt; 'example.com',
    'email'  =&gt; 'client@example.com',
    'name'   =&gt; 'Tanvir Ahmed',        // Optional Lead Full Name
    'phone'  =&gt; '+8801712345678'      // Optional Lead Phone / WhatsApp
]);

$ch = curl_init($apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'X-API-KEY: ' . $apiKey,
    'X-API-SECRET: ' . $apiSecret
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$result = json_decode($response, true);
print_r($result);
// $result['domain_status'] will be 'available' or 'registered'
?&gt;</code></pre>
        <button onclick="copySnippet('code_php', this)" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-all">
          <i class="fa-solid fa-copy"></i> Copy
        </button>
      </div>

      <!-- Code Box: JS Fetch -->
      <div id="code_js" class="hidden relative group">
        <pre class="bg-slate-950 border border-slate-800 rounded-xl p-5 text-xs text-slate-200 overflow-x-auto leading-relaxed"><code>async function watchDomain(targetDomain, userEmail, userName = '', userPhone = '') {
  const response = await fetch('<?= e($apiEndpoint) ?>', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': '<?= e($firstKey) ?>',
      'X-API-SECRET': '<?= e($firstSecret) ?>'
    },
    body: JSON.stringify({
      domain: targetDomain,
      email: userEmail,
      name: userName,
      phone: userPhone
    })
  });

  const data = await response.json();
  console.log('Result:', data);
  if (data.domain_status === 'available') {
    alert('Domain is available! Booking link: ' + data.booking_url);
  } else {
    alert('Domain is registered. Added to drop watchlist.');
  }
}</code></pre>
        <button onclick="copySnippet('code_js', this)" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-all">
          <i class="fa-solid fa-copy"></i> Copy
        </button>
      </div>

      <!-- Code Box: cURL CLI -->
      <div id="code_curl" class="hidden relative group">
        <pre class="bg-slate-950 border border-slate-800 rounded-xl p-5 text-xs text-slate-200 overflow-x-auto leading-relaxed"><code>curl -X POST "<?= e($apiEndpoint) ?>" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: <?= e($firstKey) ?>" \
  -H "X-API-SECRET: <?= e($firstSecret) ?>" \
  -d '{"domain": "targetbrand.com", "email": "lead@client.com", "name": "Tanvir Ahmed", "phone": "+8801712345678"}'</code></pre>
        <button onclick="copySnippet('code_curl', this)" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-all">
          <i class="fa-solid fa-copy"></i> Copy
        </button>
      </div>

    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
    Banglar Server REST API Architecture &bull; Dual-Key Protected &bull; &copy; <?= date('Y') ?> Banglar Server
  </footer>

  <script>
    function toggleSecret(elementId, realSecret, btn) {
      const el = document.getElementById(elementId);
      const icon = btn.querySelector('i');
      if (el.textContent === realSecret) {
        el.textContent = '••••••••••••••••••••••••';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      } else {
        el.textContent = realSecret;
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      }
    }

    function copyToClipboard(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check text-blue-400"></i>';
        setTimeout(() => { btn.innerHTML = orig; }, 1500);
      });
    }

    function copySnippet(boxId, btn) {
      const code = document.querySelector('#' + boxId + ' code').innerText;
      navigator.clipboard.writeText(code).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check text-blue-400"></i> Copied!';
        setTimeout(() => { btn.innerHTML = orig; }, 1500);
      });
    }

    function switchTab(tab) {
      const tabs = ['php', 'js', 'curl'];
      tabs.forEach(t => {
        document.getElementById('code_' + t).classList.add('hidden');
        document.getElementById('tab_' + t).className = 'px-3.5 py-1.5 rounded-lg font-medium text-slate-400 hover:text-white transition-all';
      });

      document.getElementById('code_' + tab).classList.remove('hidden');
      document.getElementById('tab_' + tab).className = 'px-3.5 py-1.5 rounded-lg font-bold bg-blue-600 text-white transition-all shadow-sm';
    }

    // Custom Delete Key Modal
    let keyToDeleteId = null;

    function confirmDeleteApiKey(id, appName) {
      keyToDeleteId = id;
      const target = document.getElementById('deleteKeyAppTarget');
      if (target) target.textContent = appName;
      const modal = document.getElementById('deleteKeyModal');
      if (modal) modal.classList.remove('hidden');
    }

    function closeDeleteKeyModal() {
      keyToDeleteId = null;
      const modal = document.getElementById('deleteKeyModal');
      if (modal) modal.classList.add('hidden');
    }

    async function executeDeleteApiKey() {
      if (!keyToDeleteId) return;
      const id = keyToDeleteId;
      const btn = document.getElementById('confirmDeleteKeyBtn');
      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

      try {
        const csrfToken = '<?= e(getCsrfToken()) ?>';
        const res = await fetch('api_manager.php?action=delete&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken) + '&ajax=1', {
          headers: { 
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRF-Token': csrfToken
          }
        });
        const data = await res.json();
        if (data.success) {
          closeDeleteKeyModal();
          const row = document.getElementById('key-row-' + id);
          if (row) {
            row.style.transition = 'all 0.35s ease';
            row.style.opacity = '0';
            row.style.transform = 'translateX(20px)';
            setTimeout(() => row.remove(), 350);
          }
        } else {
          alert('Failed to delete key: ' + (data.message || 'Unknown error'));
        }
      } catch (err) {
        window.location.href = 'api_manager.php?action=delete&id=' + id + '&csrf_token=' + encodeURIComponent('<?= e(getCsrfToken()) ?>');
      } finally {
        btn.disabled = false;
        btn.innerHTML = origText;
      }
    }
  </script>

  <!-- Delete Key Modal (Custom Dark UI) -->
  <div id="deleteKeyModal" class="fixed inset-0 z-50 hidden bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 sm:p-7 shadow-2xl space-y-5 relative animate-fadeIn">
      <div class="flex items-start gap-4">
        <div class="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center shrink-0 text-rose-400 text-xl">
          <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div class="space-y-1">
          <h3 class="text-base font-bold text-white">Permanently Delete API Key?</h3>
          <p class="text-xs text-slate-400 leading-relaxed">
            Are you sure you want to delete the credentials for <span id="deleteKeyAppTarget" class="font-bold text-white font-mono"></span>? Any remote integrations using this API key will immediately fail.
          </p>
        </div>
      </div>

      <div class="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
        <button type="button" onclick="closeDeleteKeyModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer">
          Cancel
        </button>
        <button type="button" id="confirmDeleteKeyBtn" onclick="executeDeleteApiKey()" class="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-rose-600/30 flex items-center gap-1.5 cursor-pointer">
          <i class="fa-solid fa-trash-can"></i> Yes, Delete
        </button>
      </div>
    </div>
  </div>
</body>
</html>
