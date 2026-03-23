require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

async function migrate() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(190) NOT NULL,
    role ENUM('super_admin','user') NOT NULL DEFAULT 'user',
    two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
    two_factor_secret VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS controllers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(190) NOT NULL,
    base_url VARCHAR(255) NOT NULL,
    username VARCHAR(190) NOT NULL,
    password_plain TEXT NOT NULL,
    site_name_hint VARCHAR(190) NULL,
    mode ENUM('unifi_os','legacy') NOT NULL DEFAULT 'unifi_os',
    created_by_user_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    controller_id INT NOT NULL,
    unifi_site_name VARCHAR(190) NOT NULL,
    description_text VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_controller_site (controller_id, unifi_site_name),
    FOREIGN KEY (controller_id) REFERENCES controllers(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS user_sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    site_id INT NOT NULL,
    UNIQUE KEY uniq_user_site (user_id, site_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS wifi_networks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    wlan_id VARCHAR(190) NOT NULL,
    ssid_name VARCHAR(190) NOT NULL,
    security_type VARCHAR(100) NULL,
    last_password VARCHAR(255) NULL,
    last_changed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_site_wlan (site_id, wlan_id),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    wifi_network_id INT NOT NULL,
    name VARCHAR(190) NOT NULL,
    cron_expr VARCHAR(100) NOT NULL,
    timezone_name VARCHAR(100) NOT NULL DEFAULT 'Europe/London',
    use_random_password TINYINT(1) NOT NULL DEFAULT 1,
    password_length INT NOT NULL DEFAULT 16,
    fixed_password VARCHAR(255) NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_by_user_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    wifi_network_id INT NOT NULL,
    changed_by_user_id INT NULL,
    change_type ENUM('manual','scheduled') NOT NULL,
    password_plain VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action_text VARCHAR(255) NOT NULL,
    detail_text TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

module.exports = { pool, migrate };
