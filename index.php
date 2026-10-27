<?php
/**
 * Banglar Server - Domain Availability Watcher & Lead System
 * Public Interface - Instant WHOIS Check & Drop Watchlist
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/smtp_mailer.php';

$pdo = getDbConnection();
$adminSettings = getAdminSettings($pdo);
$logoUrl = !empty($adminSettings['logo_url']) ? $adminSettings['logo_url'] : 'assets/logo.png';
$bookingBaseUrl = rtrim($adminSettings['booking_base_url'] ?? '', '=') . '=';

$messageResult = null;
$isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') 
          || (isset($_GET['ajax']) && $_GET['ajax'] == '1');

// Process submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Anti-Bot Honeypot: Ignore automated bot submissions
    if (!empty($_POST['website_hp'])) {
        $messageResult = [
            'type'          => 'registered',
            'title'         => 'Watchlist Activated',
            'bengali_title' => 'আপনার অনুরোধ গ্রহণ করা হয়েছে',
            'message'       => 'Your monitoring request has been queued.'
        ];
    } else {
        $rawDomain = $_POST['domain'] ?? '';
        $rawEmail  = $_POST['email'] ?? '';
        $rawName   = trim($_POST['name'] ?? '');
        $rawPhone  = trim($_POST['phone'] ?? '');

        $domain = cleanDomain($rawDomain);
        $email  = trim($rawEmail);
        $userName  = !empty($rawName) ? $rawName : null;
        $userPhone = !empty($rawPhone) ? $rawPhone : null;

        if (empty($domain)) {
            $messageResult = [
                'type'    => 'error',
                'title'   => 'Invalid Domain Name',
                'message' => 'Please enter a valid domain name (e.g., example.com, mybusiness.xyz, digitalbangla.org).'
            ];
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $messageResult = [
                'type'    => 'error',
                'title'   => 'Invalid Email Address',
                'message' => 'Please provide a valid email address to receive availability and drop alerts.'
            ];
        } else {
        // Execute Instant Day-1 WHOIS Check
        $isAvailable = isDomainAvailable($domain);
        $newStatus = $isAvailable ? 'available' : 'registered';
        $notified = $isAvailable ? 1 : 0;

        // Duplicate Prevention: Check if domain + email already exists
        $stmtCheck = $pdo->prepare("SELECT id, status, user_name, user_phone FROM `watched_domains` WHERE `domain_name` = ? AND `user_email` = ? LIMIT 1");
        $stmtCheck->execute([$domain, $email]);
        $existing = $stmtCheck->fetch();

        if ($existing) {
            // Update existing record
            $finalName = $userName ?? $existing['user_name'];
            $finalPhone = $userPhone ?? $existing['user_phone'];

            $stmtUpdate = $pdo->prepare("
                UPDATE `watched_domains`
                SET `status` = ?,
                    `last_checked` = NOW(),
                    `notified_available` = ?,
                    `user_name` = ?,
                    `user_phone` = ?,
                    `source_app` = 'Public Web'
                WHERE `id` = ?
            ");
            $stmtUpdate->execute([$newStatus, $notified, $finalName, $finalPhone, $existing['id']]);
        } else {
            // Insert new record with lead contact info
            $stmtInsert = $pdo->prepare("
                INSERT INTO `watched_domains` (`domain_name`, `user_email`, `user_name`, `user_phone`, `added_by`, `source_app`, `status`, `last_checked`, `notified_available`, `created_at`)
                VALUES (?, ?, ?, ?, 'public', 'Public Web', ?, NOW(), ?, NOW())
            ");
            $stmtInsert->execute([$domain, $email, $userName, $userPhone, $newStatus, $notified]);
        }

        // Initialize Standalone Mailer
        $mailer = new BanglarSmtpMailer(getSmtpSettings($pdo), $adminSettings);

        if ($isAvailable) {
            // SCENARIO 1: Domain is ALREADY Available on the day of submission!
            // 1. Send HTML Email to User (personalized with Name)
            $mailer->sendUserAvailableAlert($domain, $email, $userName);

            // 2. Send HTML Lead Alert to Admin (with Full Name and Phone)
            $mailer->sendAdminLeadAlert($domain, $email, 'Public Web', 'available', $userName, $userPhone);

            $directBookingUrl = $bookingBaseUrl . urlencode($domain);

            $messageResult = [
                'type'             => 'available',
                'title'            => 'Congratulations! Domain is Available Right Now!',
                'bengali_title'    => 'অভিনন্দন! আপনার ডোমেইনটি বর্তমানে উন্মুক্ত আছে!',
                'domain'           => $domain,
                'email'            => $email,
                'name'             => $userName,
                'status'           => 'available',
                'booking_url'      => $directBookingUrl,
                'message'          => "Good news! {$domain} is not registered yet. We have sent registration details to {$email}. You can claim it immediately on Banglar Server before someone else takes it!"
            ];
        } else {
            // SCENARIO 2: Domain is Registered / Taken
            // 1. Send confirmation email to user using 'domain_added' template
            $mailer->sendWatchlistConfirmation($domain, $email, $userName);

            // 2. Send notification to Admin that a new lead is monitoring this domain
            $mailer->sendAdminLeadAlert($domain, $email, 'Public Web', 'registered', $userName, $userPhone);

            $messageResult = [
                'type'             => 'registered',
                'title'            => 'Domain is Registered - Watchlist Activated!',
                'bengali_title'    => 'ডোমেইনটি বর্তমানে রেজিস্টার্ড - নজরদারি সক্রিয় করা হয়েছে!',
                'domain'           => $domain,
                'email'            => $email,
                'name'             => $userName,
                'status'           => 'registered',
                'message'          => "Domain {$domain} is currently owned by someone else. Don't worry! We have added it to our 24/7 automated drop watcher. As soon as it expires and drops, we will immediately send an instant drop alert to {$email}!"
            ];
        }
    }
}

    if ($isAjax) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($messageResult);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Banglar Server - Domain Availability Watcher & Lead System</title>
  <meta name="description" content="Never lose your dream domain. Banglar Server monitors domain availability 24/7 and sends instant drop alerts right to your inbox.">
  <!-- Tailwind CSS CDN -->
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
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Noto+Sans+Bengali:wght@400;600;700&display=swap');
    body {
      font-family: 'Plus Jakarta Sans', 'Noto Sans Bengali', sans-serif;
    }
    .glow-brand {
      box-shadow: 0 0 50px -10px rgba(31, 117, 254, 0.35);
    }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-blue-600 selection:text-white">

  <!-- Public Navbar -->
  <header class="border-b border-slate-800/80 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
      <!-- Dynamic Logo -->
      <a href="index.php" class="flex items-center gap-3 group" title="Banglar Server">
        <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-10 sm:h-12 w-auto object-contain transition-transform group-hover:scale-105 drop-shadow-sm" onerror="this.onerror=null; this.src='assets/logo.png';" />
      </a>

      <!-- Navigation items -->
      <nav class="hidden md:flex items-center gap-6 text-sm font-medium">
        <a href="#watcher" class="text-slate-300 hover:text-blue-400 transition-colors">Domain Watcher</a>
        <a href="#features" class="text-slate-300 hover:text-blue-400 transition-colors">How It Works</a>
        <a href="#api" class="text-slate-300 hover:text-blue-400 transition-colors">REST API</a>
        <a href="admin.php" class="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-blue-500/50 transition-all text-xs font-semibold uppercase tracking-wider">
          <i class="fa-solid fa-shield-halved text-blue-400"></i> Admin Login
        </a>
      </nav>

      <!-- Mobile Menu Button -->
      <div class="flex items-center gap-3 md:hidden">
        <a href="admin.php" class="text-xs px-3 py-1.5 rounded bg-slate-800 text-slate-200 border border-slate-700 hover:border-blue-500/50">
          <i class="fa-solid fa-lock text-blue-400 mr-1"></i> Admin
        </a>
      </div>
    </div>
  </header>

  <!-- Hero & Watcher Form Section -->
  <main class="flex-grow">
    <section id="watcher" class="relative pt-12 pb-20 overflow-hidden">
      <!-- Background Ambient Glow -->
      <div class="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-blue-600/15 blur-[130px] rounded-full pointer-events-none"></div>

      <div class="max-w-4xl mx-auto px-4 sm:px-6 text-center relative z-10">
        <!-- Badge -->
        <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-300 text-xs sm:text-sm font-medium mb-6">
          <span class="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>
          24/7 Automated WHOIS Drop Watcher &bull; ২৪/৭ ডোমেইন ড্রপ নজরদারি
        </div>

        <h1 class="text-3xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white mb-4">
          Never Lose Your <span class="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-sky-300 to-indigo-300">Dream Domain</span>
        </h1>
        <p class="text-base sm:text-xl text-slate-300 max-w-2xl mx-auto mb-10 leading-relaxed">
          কাঙ্খিত ডোমেইনটি কি ইতিমধ্যে বুক করা? আমাদের ওয়াচলিস্টে ডোমেইনটি যোগ করুন। ডোমেইনটি এক্সপায়ার হয়ে মুক্ত হলেই আপনি সাথে সাথে পাবেন নোটিফিকেশন!
        </p>

        <!-- Main Watcher Card -->
        <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-10 shadow-2xl glow-brand text-left">
          
          <!-- Live Result Alert Box (if submitted via standard POST) -->
          <div id="alertBox" class="<?= $messageResult ? '' : 'hidden' ?> mb-8">
            <?php if ($messageResult): ?>
              <?php if ($messageResult['type'] === 'available'): ?>
                <div class="p-6 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-200">
                  <div class="flex items-start gap-4">
                    <div class="w-12 h-12 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 text-2xl">
                      <i class="fa-solid fa-circle-check"></i>
                    </div>
                    <div class="space-y-2 flex-grow">
                      <div class="flex flex-wrap items-center justify-between gap-2">
                        <h3 class="text-lg font-bold text-white"><?= e($messageResult['title']) ?></h3>
                        <span class="px-2.5 py-1 text-xs font-bold rounded-full bg-emerald-500 text-slate-950 uppercase tracking-wider">AVAILABLE NOW</span>
                      </div>
                      <p class="text-sm text-emerald-300/90 font-medium"><?= e($messageResult['bengali_title']) ?></p>
                      <p class="text-sm text-slate-300 leading-relaxed"><?= e($messageResult['message']) ?></p>
                      <div class="pt-3">
                        <a href="<?= e($messageResult['booking_url']) ?>" target="_blank" class="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm tracking-wide uppercase transition-all shadow-lg shadow-blue-600/30 hover:shadow-blue-500/50">
                          <i class="fa-solid fa-cart-shopping"></i> Book <?= e($messageResult['domain']) ?> Now &rarr;
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              <?php elseif ($messageResult['type'] === 'registered'): ?>
                <div class="p-6 rounded-xl bg-amber-950/50 border border-amber-500/40 text-amber-200">
                  <div class="flex items-start gap-4">
                    <div class="w-12 h-12 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0 text-2xl">
                      <i class="fa-solid fa-bell"></i>
                    </div>
                    <div class="space-y-2">
                      <div class="flex flex-wrap items-center justify-between gap-2">
                        <h3 class="text-lg font-bold text-white"><?= e($messageResult['title']) ?></h3>
                        <span class="px-2.5 py-1 text-xs font-bold rounded-full bg-amber-500 text-slate-950 uppercase tracking-wider">UNDER 24/7 WATCH</span>
                      </div>
                      <p class="text-sm text-amber-300/90 font-medium"><?= e($messageResult['bengali_title']) ?></p>
                      <p class="text-sm text-slate-300 leading-relaxed"><?= e($messageResult['message']) ?></p>
                    </div>
                  </div>
                </div>
              <?php else: ?>
                <div class="p-5 rounded-xl bg-rose-950/50 border border-rose-500/40 text-rose-200 flex items-start gap-3">
                  <i class="fa-solid fa-circle-exclamation text-rose-400 text-xl mt-0.5"></i>
                  <div>
                    <h4 class="font-bold text-rose-100"><?= e($messageResult['title']) ?></h4>
                    <p class="text-sm text-rose-300"><?= e($messageResult['message']) ?></p>
                  </div>
                </div>
              <?php endif; ?>
            <?php endif; ?>
          </div>

          <!-- Watcher Input Form -->
          <form id="watcherForm" action="index.php" method="POST" class="space-y-5">
            <!-- Anti-Bot Honeypot Field (Hidden from real users) -->
            <div style="display:none !important;" aria-hidden="true">
              <input type="text" name="website_hp" tabindex="-1" autocomplete="off" value="">
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
              
              <!-- Domain Field -->
              <div>
                <label for="domainInput" class="block text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
                  <i class="fa-solid fa-globe text-blue-400 mr-1.5"></i> Target Domain Name
                </label>
                <div class="relative">
                  <input type="text" id="domainInput" name="domain" placeholder="example.com or brand.xyz" required autocomplete="off"
                    value="<?= e($_POST['domain'] ?? '') ?>"
                    class="w-full bg-slate-950/80 border border-slate-700 rounded-xl px-4 py-3.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono text-sm sm:text-base">
                </div>
                <p class="mt-1.5 text-xs text-slate-400">Supports .com, .net, .org, .xyz, .in, .co, .io, .shop, etc.</p>
              </div>

              <!-- Email Field -->
              <div>
                <label for="emailInput" class="block text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
                  <i class="fa-solid fa-envelope text-blue-400 mr-1.5"></i> Notification Email
                </label>
                <div class="relative">
                  <input type="email" id="emailInput" name="email" placeholder="you@example.com" required autocomplete="email"
                    value="<?= e($_POST['email'] ?? '') ?>"
                    class="w-full bg-slate-950/80 border border-slate-700 rounded-xl px-4 py-3.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-sm sm:text-base">
                </div>
                <p class="mt-1.5 text-xs text-slate-400">We will instantly email you the moment it drops.</p>
              </div>

              <!-- Full Name Field -->
              <div>
                <label for="nameInput" class="block text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
                  <i class="fa-solid fa-user text-blue-400 mr-1.5"></i> Your Full Name
                </label>
                <div class="relative">
                  <input type="text" id="nameInput" name="name" placeholder="Sayan Roy / আপনার নাম" autocomplete="name"
                    value="<?= e($_POST['name'] ?? '') ?>"
                    class="w-full bg-slate-950/80 border border-slate-700 rounded-xl px-4 py-3.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-sm sm:text-base">
                </div>
                <p class="mt-1.5 text-xs text-slate-400">Helps us address you personally in alert emails.</p>
              </div>

              <!-- Phone / WhatsApp Field -->
              <div>
                <label for="phoneInput" class="block text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">
                  <i class="fa-solid fa-phone text-blue-400 mr-1.5"></i> Mobile / WhatsApp Number
                </label>
                <div class="relative">
                  <input type="tel" id="phoneInput" name="phone" placeholder="+91123456789" autocomplete="tel"
                    value="<?= e($_POST['phone'] ?? '') ?>"
                    class="w-full bg-slate-950/80 border border-slate-700 rounded-xl px-4 py-3.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-sm sm:text-base">
                </div>
                <p class="mt-1.5 text-xs text-slate-400">For instant WhatsApp drop alerts &amp; priority booking support.</p>
              </div>

            </div>

            <!-- Submit Button with Spinner -->
            <div class="pt-2">
              <button type="submit" id="submitBtn" class="w-full group relative inline-flex items-center justify-center gap-2 px-8 py-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-base uppercase tracking-wider transition-all shadow-xl shadow-blue-600/30 hover:shadow-blue-500/50 active:scale-[0.99] cursor-pointer">
                <span id="btnText" class="inline-flex items-center gap-2">
                  <i class="fa-solid fa-magnifying-glass"></i> Check &amp; Watch Domain Now
                </span>
                <span id="btnSpinner" class="hidden items-center gap-2">
                  <i class="fa-solid fa-spinner fa-spin text-lg"></i> Querying Registry &amp; Checking Availability...
                </span>
              </button>
            </div>

            <p class="text-center text-xs text-slate-400 pt-1">
              <i class="fa-solid fa-shield text-blue-400 mr-1"></i> 100% Free Service &bull; No credit card or account registration required.
            </p>
          </form>

        </div>
      </div>
    </section>

    <!-- How It Works Section -->
    <section id="features" class="py-16 border-t border-slate-800/80 bg-slate-900/40">
      <div class="max-w-6xl mx-auto px-4 sm:px-6">
        <div class="text-center max-w-2xl mx-auto mb-12">
          <h2 class="text-2xl sm:text-3xl font-extrabold text-white">How Banglar Server Watcher Works</h2>
          <p class="text-sm sm:text-base text-slate-400 mt-2">আমাদের সিস্টেম কিভাবে ডোমেইন মনিটর করে এবং আপনাকে সতর্ক করে</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
          
          <!-- Step 1 -->
          <div class="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-blue-500/40 transition-all group">
            <div class="w-12 h-12 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center text-xl font-bold mb-5 group-hover:scale-110 transition-transform">
              1
            </div>
            <h3 class="text-lg font-bold text-white mb-2">Instant WHOIS Verification</h3>
            <p class="text-sm text-slate-400 leading-relaxed">
              Upon entry, our engine directly queries registry socket servers (Port 43) to check if your desired domain is already free or owned.
            </p>
          </div>

          <!-- Step 2 -->
          <div class="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-blue-500/40 transition-all group">
            <div class="w-12 h-12 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center text-xl font-bold mb-5 group-hover:scale-110 transition-transform">
              2
            </div>
            <h3 class="text-lg font-bold text-white mb-2">24/7 Automated Drop Watch</h3>
            <p class="text-sm text-slate-400 leading-relaxed">
              If registered, our cron engine checks the domain daily. We watch for registry release, redemption, and drop cycles automatically.
            </p>
          </div>

          <!-- Step 3 -->
          <div class="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-blue-500/40 transition-all group">
            <div class="w-12 h-12 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center text-xl font-bold mb-5 group-hover:scale-110 transition-transform">
              3
            </div>
            <h3 class="text-lg font-bold text-white mb-2">Instant 1-Click Drop Alert</h3>
            <p class="text-sm text-slate-400 leading-relaxed">
              The moment it drops, you receive a high-priority HTML alert with a 1-click booking link into Banglar Server's automated WHMCS cart.
            </p>
          </div>

        </div>
      </div>
    </section>

    <!-- REST API Banner Section -->
    <section id="api" class="py-16 border-t border-slate-800">
      <div class="max-w-6xl mx-auto px-4 sm:px-6">
        <div class="bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 rounded-3xl p-8 sm:p-12 flex flex-col lg:flex-row items-center justify-between gap-8">
          <div class="space-y-4 max-w-xl">
            <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-semibold uppercase tracking-wider">
              <i class="fa-solid fa-code"></i> Developer Ready
            </div>
            <h2 class="text-2xl sm:text-3xl font-extrabold text-white">
              Connect External Sites with our REST API
            </h2>
            <p class="text-sm sm:text-base text-slate-400 leading-relaxed">
              Embed domain drop watching into your WordPress sites, WHMCS modules, custom landing pages, or mobile apps via secure JSON API.
            </p>
          </div>
          <div class="flex flex-col sm:flex-row gap-4 w-full sm:w-auto">
            <a href="admin.php" class="px-6 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-center text-sm uppercase tracking-wider transition-all shadow-lg shadow-blue-600/30 hover:shadow-blue-500/50">
              Get API Keys
            </a>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Branded Footer -->
  <footer class="border-t border-slate-800 bg-slate-950 py-10 text-slate-400 text-sm">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
      <div class="flex items-center gap-3">
        <img src="<?= e($logoUrl) ?>" alt="Banglar Server" class="h-8 w-auto object-contain opacity-90 drop-shadow-sm" onerror="this.onerror=null; this.src='assets/logo.png';" />
        <span class="text-xs text-slate-400">&bull; Premium Cloud Infrastructure</span>
      </div>
      <div class="flex items-center gap-6 text-xs text-slate-400">
        <a href="#watcher" class="hover:text-blue-400 transition-colors">Watcher</a>
        <a href="admin.php" class="hover:text-blue-400 transition-colors">Admin Area</a>
        <a href="https://banglarserver.com" target="_blank" class="hover:text-blue-400 transition-colors">BanglarServer.com</a>
      </div>
      <div class="text-xs text-slate-500 text-center md:text-right">
        &copy; <?= date('Y') ?> Banglar Server. All rights reserved.
      </div>
    </div>
  </footer>

  <!-- AJAX Form Handler Script -->
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      const form = document.getElementById('watcherForm');
      const submitBtn = document.getElementById('submitBtn');
      const btnText = document.getElementById('btnText');
      const btnSpinner = document.getElementById('btnSpinner');
      const alertBox = document.getElementById('alertBox');

      form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const domain = document.getElementById('domainInput').value.trim();
        const email = document.getElementById('emailInput').value.trim();

        if (!domain || !email) {
          return;
        }

        // Show loading state
        submitBtn.disabled = true;
        btnText.classList.add('hidden');
        btnSpinner.classList.remove('hidden');
        btnSpinner.classList.add('inline-flex');

        try {
          const formData = new FormData(form);
          const response = await fetch('index.php?ajax=1', {
            method: 'POST',
            body: formData,
            headers: {
              'X-Requested-With': 'XMLHttpRequest'
            }
          });

          const data = await response.json();
          renderAlert(data);

        } catch (err) {
          // If AJAX fails for any reason, submit standard form
          form.submit();
        } finally {
          submitBtn.disabled = false;
          btnText.classList.remove('hidden');
          btnSpinner.classList.add('hidden');
          btnSpinner.classList.remove('inline-flex');
        }
      });

      function renderAlert(res) {
        alertBox.classList.remove('hidden');
        if (res.type === 'available') {
          alertBox.innerHTML = `
            <div class="p-6 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-200 animate-fadeIn">
              <div class="flex items-start gap-4">
                <div class="w-12 h-12 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 text-2xl">
                  <i class="fa-solid fa-circle-check"></i>
                </div>
                <div class="space-y-2 flex-grow">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <h3 class="text-lg font-bold text-white">${escapeHtml(res.title)}</h3>
                    <span class="px-2.5 py-1 text-xs font-bold rounded-full bg-emerald-500 text-slate-950 uppercase tracking-wider">AVAILABLE NOW</span>
                  </div>
                  <p class="text-sm text-emerald-300/90 font-medium">${escapeHtml(res.bengali_title || '')}</p>
                  <p class="text-sm text-slate-300 leading-relaxed">${escapeHtml(res.message)}</p>
                  <div class="pt-3">
                    <a href="${escapeHtml(res.booking_url)}" target="_blank" class="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm tracking-wide uppercase transition-all shadow-lg shadow-blue-600/30 hover:shadow-blue-500/50">
                      <i class="fa-solid fa-cart-shopping"></i> Book ${escapeHtml(res.domain)} Now &rarr;
                    </a>
                  </div>
                </div>
              </div>
            </div>
          `;
        } else if (res.type === 'registered') {
          alertBox.innerHTML = `
            <div class="p-6 rounded-xl bg-amber-950/50 border border-amber-500/40 text-amber-200 animate-fadeIn">
              <div class="flex items-start gap-4">
                <div class="w-12 h-12 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0 text-2xl">
                  <i class="fa-solid fa-bell"></i>
                </div>
                <div class="space-y-2">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <h3 class="text-lg font-bold text-white">${escapeHtml(res.title)}</h3>
                    <span class="px-2.5 py-1 text-xs font-bold rounded-full bg-amber-500 text-slate-950 uppercase tracking-wider">UNDER 24/7 WATCH</span>
                  </div>
                  <p class="text-sm text-amber-300/90 font-medium">${escapeHtml(res.bengali_title || '')}</p>
                  <p class="text-sm text-slate-300 leading-relaxed">${escapeHtml(res.message)}</p>
                </div>
              </div>
            </div>
          `;
        } else {
          alertBox.innerHTML = `
            <div class="p-5 rounded-xl bg-rose-950/50 border border-rose-500/40 text-rose-200 flex items-start gap-3 animate-fadeIn">
              <i class="fa-solid fa-circle-exclamation text-rose-400 text-xl mt-0.5"></i>
              <div>
                <h4 class="font-bold text-rose-100">${escapeHtml(res.title)}</h4>
                <p class="text-sm text-rose-300">${escapeHtml(res.message)}</p>
              </div>
            </div>
          `;
        }
        alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
      }
    });
  </script>
</body>
</html>
