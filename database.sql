-- ========================================================
-- Banglar Server - Domain Availability Watcher & Lead System
-- Database Schema: database.sql
-- Compatible with MySQL 5.7+ / MySQL 8.x / MariaDB 10.x / cPanel / aaPanel
-- Character Set: utf8mb4 / Collation: utf8mb4_unicode_ci
-- ========================================================

-- INSTRUCTIONS FOR CPANEL USERS:
-- 1. Create a MySQL Database & User in cPanel (e.g. `cpaneluser_dwatcher`).
-- 2. Grant ALL PRIVILEGES to the user for that database.
-- 3. Open phpMyAdmin, select your database from the left sidebar, and click "Import" -> choose this file.

-- --------------------------------------------------------
-- 1. Table structure for table `admins`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `admins` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(100) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `admin_email` VARCHAR(191) NOT NULL,
  `daily_report_emails` TEXT DEFAULT NULL,
  `logo_url` VARCHAR(255) NOT NULL DEFAULT 'assets/logo.png',
  `booking_base_url` VARCHAR(255) NOT NULL DEFAULT 'https://dash.banglarserver.com/cart.php?a=add&domain=register&query=',
  `daily_report_time` TIME NOT NULL DEFAULT '09:00:00',
  `last_report_date` DATE DEFAULT NULL,
  `cron_token` VARCHAR(64) NOT NULL DEFAULT 'bs_cron_7f8a3c9b2e1d',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 2. Table structure for table `smtp_settings`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `smtp_settings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `smtp_host` VARCHAR(191) NOT NULL DEFAULT 'smtp.mailtrap.io',
  `smtp_port` INT UNSIGNED NOT NULL DEFAULT 587,
  `smtp_user` VARCHAR(191) NOT NULL DEFAULT '',
  `smtp_pass` VARCHAR(255) NOT NULL DEFAULT '',
  `smtp_secure` ENUM('ssl', 'tls', 'none') NOT NULL DEFAULT 'tls',
  `from_email` VARCHAR(191) NOT NULL DEFAULT 'support@banglarserver.com',
  `from_name` VARCHAR(191) NOT NULL DEFAULT 'Banglar Server Watcher',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 3. Table structure for table `api_keys`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `api_keys` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_name` VARCHAR(191) NOT NULL,
  `api_key` VARCHAR(64) NOT NULL UNIQUE,
  `secret_key` VARCHAR(128) NOT NULL,
  `status` ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
  `total_requests` INT UNSIGNED NOT NULL DEFAULT 0,
  `last_used_at` DATETIME DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `idx_api_key_status` (`api_key`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 4. Table structure for table `watched_domains`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `watched_domains` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_name` VARCHAR(191) NOT NULL,
  `user_email` VARCHAR(191) NOT NULL,
  `user_name` VARCHAR(191) DEFAULT NULL,
  `user_phone` VARCHAR(50) DEFAULT NULL,
  `added_by` ENUM('admin', 'public', 'api') NOT NULL DEFAULT 'public',
  `source_app` VARCHAR(191) NOT NULL DEFAULT 'Public Web',
  `status` ENUM('registered', 'available') NOT NULL DEFAULT 'registered',
  `last_checked` DATETIME DEFAULT NULL,
  `notified_available` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `idx_domain_name` (`domain_name`),
  INDEX `idx_user_email` (`user_email`),
  INDEX `idx_domain_user` (`domain_name`, `user_email`),
  INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 5. Table structure for table `email_templates`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `email_templates` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `template_key` VARCHAR(64) NOT NULL UNIQUE,
  `template_name` VARCHAR(191) NOT NULL,
  `subject` VARCHAR(255) NOT NULL,
  `headline` VARCHAR(255) NOT NULL,
  `body_html` TEXT NOT NULL,
  `button_text` VARCHAR(100) NOT NULL DEFAULT 'Book Domain Now',
  `button_url` VARCHAR(255) NOT NULL DEFAULT '{booking_url}',
  `is_enabled` TINYINT(1) NOT NULL DEFAULT 1,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Default Clean Data Seeding (No Demo Domains / No Demo Keys)
-- --------------------------------------------------------
INSERT INTO `admins` (`id`, `username`, `password_hash`, `admin_email`, `logo_url`, `booking_base_url`, `daily_report_time`, `last_report_date`, `cron_token`)
VALUES (
  1,
  'admin',
  '$2y$10$AJCNrBhzR.qoGt/RVRJnveAOrdpfuqcivtMjaCNOTig2S1Ki2cID.',
  'admin@banglarserver.com',
  'assets/logo.png',
  'https://dash.banglarserver.com/cart.php?a=add&domain=register&query=',
  '09:00:00',
  NULL,
  'bs_cron_7f8a3c9b2e1d'
) ON DUPLICATE KEY UPDATE `id`=`id`;

INSERT INTO `smtp_settings` (`id`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_pass`, `smtp_secure`, `from_email`, `from_name`)
VALUES (
  1,
  'smtp.mailtrap.io',
  587,
  '',
  '',
  'tls',
  'support@banglarserver.com',
  'Banglar Server'
) ON DUPLICATE KEY UPDATE `id`=`id`;

INSERT INTO `email_templates` (`id`, `template_key`, `template_name`, `subject`, `headline`, `body_html`, `button_text`, `button_url`, `is_enabled`)
VALUES
(
  1,
  'domain_added',
  'Domain Added to Watchlist (Enrollment Confirmation)',
  'Domain {domain} Successfully Added to Banglar Server Watchlist',
  'Watchlist Activated for {domain}',
  '<p style="color: #cbd5e1; font-size: 15px;">Thank you for choosing <strong>Banglar Server Domain Watcher</strong>. We have successfully enrolled your target domain into our 24/7 automated monitoring system.</p><p style="color: #cbd5e1; font-size: 15px;">Our engine monitors registry WHOIS servers continuously. The moment <strong><span style="color: #10b981;">{domain}</span></strong> expires and drops into availability, we will dispatch an instant notification to <strong>{email}</strong> so you can claim it immediately!</p>',
  'Search on Banglar Server',
  'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}',
  1
),
(
  2,
  'domain_available',
  'Domain Available / Drop Alert Notification',
  '🔥 URGENT: {domain} is Available to Register Right Now!',
  'Congratulations! {domain} is Available',
  '<p style="color: #cbd5e1; font-size: 15px;">Great news! We just verified domain <strong><span style="color: #10b981;">{domain}</span></strong> via registry lookup, and it is <strong>100% available for immediate purchase</strong>.</p><p style="color: #cbd5e1; font-size: 15px;">Domain names are registered on a first-come, first-served basis. Secure it right now through Banglar Server before someone else claims it!</p>',
  'Claim & Book Domain Now',
  'https://dash.banglarserver.com/cart.php?a=add&domain=register&query={domain}',
  1
),
(
  3,
  'admin_daily_report',
  'Admin Daily Watcher Summary Report (দৈনিক ডোমেন রিপোর্ট)',
  '📊 Banglar Server Daily Watcher Report: {newly_available} Newly Available Domains ({date_short})',
  'Daily Domain Watcher Executive Summary',
  '<p style="color: #cbd5e1; font-size: 15px;">Here is your scheduled daily executive summary of all monitored domains. Our automated WHOIS engine checked all watchlist targets.</p><p style="color: #cbd5e1; font-size: 15px;">Today we detected <strong><span style="color: #10b981;">{newly_available} newly available</span></strong> domain(s) ready for registration. Check the breakdown and full domain database below.</p>',
  'Open Admin Watchlist',
  'admin.php',
  1
) ON DUPLICATE KEY UPDATE `id`=`id`;
