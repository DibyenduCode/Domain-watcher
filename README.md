# Domain-watcher

An enterprise-ready **Domain Availability Watcher & Lead Generation System** with 24/7 automated registry WHOIS drop monitoring, instant drop email alerts, dual-key REST API authentication, and native PHP socket SMTP mailer.

---

## 🌟 Key Features

- **24/7 Automated WHOIS Monitoring**: Continuous socket-based WHOIS query engine tracking domain status across global TLDs (`.com`, `.net`, `.org`, `.xyz`, `.in`, `.co`, `.io`, etc.).
- **Instant Drop Alerts**: Automatically dispatches HTML notification emails to users with 1-click booking links when target domains become available.
- **Executive Daily Reports**: Scheduled daily digests sent to admin and executive email lists summarizing newly available domains and active watchlist counts.
- **Dual-Key REST API**: External integrations for WordPress, WHMCS order forms, custom landing pages, and mobile apps with API Key + Secret Key authentication.
- **Native Socket SMTP Mailer**: Pure PHP socket implementation supporting SSL (465) and TLS/STARTTLS (587) with zero external dependency bloat.
- **Admin Control Portal**: Dark-mode dashboard with live in-row AJAX rechecks, responsive layout, full branding customization, and template editors.
- **Production-Hardened Security**:
  - Brute-force protection & rate-limiting on admin login
  - Cross-Site Request Forgery (CSRF) tokens on all actions
  - Anti-bot invisible honeypot on public forms
  - Apache `.htaccess` rules protecting database dumps and sensitive files
  - Full PDO prepared statements preventing SQL injection

---

## 📁 Project Structure

```text
├── .htaccess            # Apache & cPanel security configuration
├── admin.php            # Admin Dashboard & Watchlist Controller
├── api.php              # Secure External REST API Endpoint
├── api_manager.php      # REST API Key Management Portal
├── assets/              # Brand logos and static resources
├── config.php           # Core configuration, database connection, & WHOIS engine
├── cron.php             # Scheduled check engine & CLI runner
├── database.sql         # Production-ready MySQL schema (cPanel/phpMyAdmin friendly)
├── index.php            # Public domain lookup & watchlist enrollment interface
├── settings.php         # System settings, SMTP config, and Email template editor
└── smtp_mailer.php      # Native PHP socket SMTP email dispatcher
```

---

## 🚀 Installation & Deployment

### Localhost (XAMPP / WampServer)
1. Clone this repository into your web root (e.g. `htdocs/dwatcher`):
   ```bash
   git clone https://github.com/DibyenduCode/Domain-watcher.git
   ```
2. Import `database.sql` into MySQL via phpMyAdmin or MySQL CLI.
3. Verify connection settings in `config.php`:
   ```php
   define('DB_HOST', 'localhost');
   define('DB_NAME', 'dwatcher_db');
   define('DB_USER', 'root');
   define('DB_PASS', '');
   ```
4. Access the application in your browser:
   - **Public Page**: `http://localhost/dwatcher/index.php`
   - **Admin Portal**: `http://localhost/dwatcher/admin.php`

### cPanel / Shared Hosting
1. Create a MySQL Database & User in cPanel (`MySQL Databases`).
2. Open phpMyAdmin, select your database, and import `database.sql`.
3. Upload and extract project files to `public_html` (or subdomain directory).
4. Update database credentials in `config.php`:
   ```php
   define('DB_NAME', 'cpaneluser_dwatcher');
   define('DB_USER', 'cpaneluser_dbuser');
   define('DB_PASS', 'YourStrongPassword');
   ```
5. Set up a Cron Job in cPanel to run `cron.php` daily:
   ```bash
   /usr/local/bin/php /home/username/public_html/cron.php
   ```

---

## 🛡️ Default Admin Credentials

- **Username**: `admin`
- **Password**: `admin123` *(Change immediately in Settings > Profile)*

---

## 📄 License
This project is proprietary and open for custom deployments. Built with ❤️ for **Banglar Server**.
