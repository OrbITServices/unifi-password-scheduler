require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');
const cron = require('node-cron');

const { pool, migrate } = require('./lib/db');
const {
  listSites,
  listWlans,
  changePassword,
  createHotspotVouchers,
  listHotspotVouchers
} = require('./lib/unifi');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  }
}));

function randomPassword(length = 16) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function wifiQrPayload(ssid, password) {
  return `WIFI:T:WPA;S:${String(ssid).replace(/([\\;,:\"])/g, '\\$1')};P:${String(password).replace(/([\\;,:\"])/g, '\\$1')};;`;
}

async function logAudit(userId, action, detail = '') {
  await pool.query(
    'INSERT INTO audit_logs (user_id, action_text, detail_text) VALUES (?, ?, ?)',
    [userId || null, action, detail]
  );
}

function setFlash(req, message) {
  req.session.flash = message;
}

function getFlash(req) {
  const message = req.session.flash;
  delete req.session.flash;
  return message;
}

function requireAuthPending(req, res, next) {
  if (!req.session.userId || !req.session.pending2fa) {
    return res.redirect('/login');
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  if (req.session.pending2fa) {
    return res.redirect('/2fa');
  }
  next();
}

function requireSuperAdmin(req, res, next) {
  if (!res.locals.currentUser || res.locals.currentUser.role !== 'super_admin') {
    return res.status(403).send('Forbidden');
  }
  next();
}

app.use(async (req, res, next) => {
  try {
    res.locals.currentUser = null;
    res.locals.flash = getFlash(req);

    if (req.session.userId) {
      const [rows] = await pool.query(
        'SELECT id, email, full_name, role, two_factor_enabled FROM users WHERE id = ?',
        [req.session.userId]
      );
      if (rows[0]) {
        res.locals.currentUser = rows[0];
      }
    }

    next();
  } catch (err) {
    next(err);
  }
});

async function allowedSiteIds(user) {
  if (!user) return [];

  if (user.role === 'super_admin') {
    const [rows] = await pool.query('SELECT id FROM sites');
    return rows.map(r => Number(r.id));
  }

  const [rows] = await pool.query(
    'SELECT site_id AS id FROM user_sites WHERE user_id = ?',
    [user.id]
  );
  return rows.map(r => Number(r.id));
}

async function getController(controllerId) {
  const [rows] = await pool.query(
    'SELECT * FROM controllers WHERE id = ?',
    [controllerId]
  );
  return rows[0] || null;
}

/* =========================
   AUTH
========================= */

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      setFlash(req, 'Invalid email or password');
      return res.redirect('/login');
    }

    req.session.userId = user.id;

    if (user.role === 'super_admin' && user.two_factor_enabled) {
      req.session.pending2fa = true;
      return res.redirect('/2fa');
    }

    await logAudit(user.id, 'login_success');
    return res.redirect('/');
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    setFlash(req, 'Login failed');
    return res.redirect('/login');
  }
});

app.get('/2fa', requireAuthPending, (req, res) => {
  res.render('twofactor');
});

app.post('/2fa', requireAuthPending, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE id = ?',
      [req.session.userId]
    );

    const user = rows[0];
    if (!user) {
      return res.redirect('/login');
    }

    const ok = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: String(req.body.token || '').replace(/\s+/g, '')
    });

    if (!ok) {
      setFlash(req, 'Invalid 2FA code');
      return res.redirect('/2fa');
    }

    delete req.session.pending2fa;
    await logAudit(user.id, 'login_success_2fa');
    return res.redirect('/');
  } catch (err) {
    console.error('2FA ERROR:', err);
    setFlash(req, '2FA failed');
    return res.redirect('/2fa');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

/* =========================
   DASHBOARD
========================= */

app.get('/', requireAuth, async (req, res) => {
  try {
    const user = res.locals.currentUser;
    const siteIds = await allowedSiteIds(user);

    let sites = [];
    let chosenSiteId = null;
    let wifiRows = [];
    let scheduleRows = [];
	let voucherRows = [];

    if (siteIds.length) {
      const [siteRows] = await pool.query(
        `SELECT s.*, c.name AS controller_name
         FROM sites s
         JOIN controllers c ON c.id = s.controller_id
         WHERE s.id IN (${siteIds.map(() => '?').join(',')})
         ORDER BY c.name, s.unifi_site_name`,
        siteIds
      );
      sites = siteRows;

      const selected = Number(req.session.selectedSiteId || 0);
      chosenSiteId = siteIds.includes(selected) ? selected : siteIds[0];
      req.session.selectedSiteId = chosenSiteId;

      const [wifiResult] = await pool.query(
        'SELECT * FROM wifi_networks WHERE site_id = ? ORDER BY ssid_name',
        [chosenSiteId]
      );
      wifiRows = wifiResult;

           const [scheduleResult] = await pool.query(
        `SELECT sc.*, wn.ssid_name
         FROM schedules sc
         JOIN wifi_networks wn ON wn.id = sc.wifi_network_id
         WHERE wn.site_id = ?
         ORDER BY sc.id DESC`,
        [chosenSiteId]
      );
      scheduleRows = scheduleResult;

      const [voucherResult] = await pool.query(
        `SELECT v.*, vb.guest_name, vb.booking_reference, wn.ssid_name
         FROM vouchers v
         JOIN voucher_batches vb ON vb.id = v.batch_id
         JOIN wifi_networks wn ON wn.id = v.wifi_id
         WHERE wn.site_id = ?
         ORDER BY v.created_at DESC
         LIMIT 20`,
        [chosenSiteId]
      );
      voucherRows = voucherResult;
    }

    return res.render('dashboard', {
      sites,
      chosenSiteId,
      wifiRows,
      scheduleRows,
	  voucherRows
    });
  } catch (err) {
    console.error('DASHBOARD ERROR:', err);
    return res.status(500).send('Failed to load dashboard: ' + err.message);
  }
});

app.post('/select-site', requireAuth, async (req, res) => {
  try {
    const siteId = Number(req.body.site_id || 0);
    const ids = await allowedSiteIds(res.locals.currentUser);

    if (!ids.includes(siteId)) {
      return res.status(403).send('Forbidden');
    }

    req.session.selectedSiteId = siteId;
    return res.redirect('/');
  } catch (err) {
    console.error('SELECT SITE ERROR:', err);
    return res.status(500).send('Failed to switch site');
  }
});

/* =========================
   CONTROLLERS
========================= */

app.get('/controller', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const [controllers] = await pool.query(
      'SELECT * FROM controllers ORDER BY id DESC'
    );
    return res.render('controller', { controllers });
  } catch (err) {
    console.error('CONTROLLER PAGE ERROR:', err);
    return res.status(500).send('Failed to load controller page');
  }
});

app.post('/controller', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { name, base_url, username, password_plain, mode } = req.body;

    await pool.query(
      `INSERT INTO controllers
       (name, base_url, username, password_plain, mode, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        name,
        base_url,
        username,
        password_plain,
        mode || 'unifi_os',
        res.locals.currentUser.id
      ]
    );

    await logAudit(res.locals.currentUser.id, 'controller_created', name);
    setFlash(req, 'Controller saved');
    return res.redirect('/controller');
  } catch (err) {
    console.error('CREATE CONTROLLER ERROR:', err);
    setFlash(req, 'Failed to save controller');
    return res.redirect('/controller');
  }
});

app.post('/controller/:id/test', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const controller = await getController(req.params.id);
    const sites = await listSites(controller);
    setFlash(req, `Connection OK. Found ${sites.length} site(s).`);
  } catch (err) {
    setFlash(req, `Connection failed: ${err.message}`);
  }
  return res.redirect('/controller');
});

app.post('/controller/:id/sync-sites', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const controller = await getController(req.params.id);
    const sites = await listSites(controller);

    for (const site of sites) {
      await pool.query(
        `INSERT INTO sites (controller_id, unifi_site_name, description_text)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE description_text = VALUES(description_text)`,
        [controller.id, site.name, site.desc || '']
      );
    }

    setFlash(req, `Synced ${sites.length} site(s)`);
  } catch (err) {
    setFlash(req, `Site sync failed: ${err.message}`);
  }

  return res.redirect('/controller');
});

/* =========================
   USERS
========================= */

app.get('/users', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, email, full_name, role, two_factor_enabled FROM users ORDER BY id DESC'
    );

    const [sites] = await pool.query(
      `SELECT s.id, s.unifi_site_name, c.name AS controller_name
       FROM sites s
       JOIN controllers c ON c.id = s.controller_id
       ORDER BY c.name, s.unifi_site_name`
    );

    const [assignments] = await pool.query('SELECT * FROM user_sites');

    return res.render('users', { users, sites, assignments });
  } catch (err) {
    console.error('USERS PAGE ERROR:', err);
    return res.status(500).send('Failed to load users page');
  }
});

app.post('/users', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { email, password, full_name, role } = req.body;
    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      'INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)',
      [email, hash, full_name, role || 'user']
    );

    setFlash(req, 'User created');
    return res.redirect('/users');
  } catch (err) {
    console.error('CREATE USER ERROR:', err);
    setFlash(req, 'Failed to create user');
    return res.redirect('/users');
  }
});

app.post('/users/:id/sites', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const siteIds = Array.isArray(req.body.site_ids)
      ? req.body.site_ids.map(Number)
      : (req.body.site_ids ? [Number(req.body.site_ids)] : []);

    await pool.query('DELETE FROM user_sites WHERE user_id = ?', [userId]);

    for (const sid of siteIds) {
      await pool.query(
        'INSERT IGNORE INTO user_sites (user_id, site_id) VALUES (?, ?)',
        [userId, sid]
      );
    }

    setFlash(req, 'Site assignments updated');
    return res.redirect('/users');
  } catch (err) {
    console.error('USER SITE ASSIGN ERROR:', err);
    setFlash(req, 'Failed to update site assignments');
    return res.redirect('/users');
  }
});

/* =========================
   2FA SETUP
========================= */

app.get('/2fa/setup', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const user = res.locals.currentUser;

    if (user.two_factor_enabled) {
      return res.redirect('/');
    }

    const secret = speakeasy.generateSecret({
      name: `UniFi App (${user.email})`
    });

    req.session.setup2faSecret = secret.base32;
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.render('setup2fa', {
      qrDataUrl,
      secret: secret.base32
    });
  } catch (err) {
    console.error('2FA SETUP PAGE ERROR:', err);
    return res.status(500).send('Failed to load 2FA setup');
  }
});

app.post('/2fa/setup', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const secret = req.session.setup2faSecret;
    if (!secret) {
      return res.redirect('/2fa/setup');
    }

    const ok = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: String(req.body.token || '').trim()
    });

    if (!ok) {
      setFlash(req, 'Invalid setup code');
      return res.redirect('/2fa/setup');
    }

    await pool.query(
      'UPDATE users SET two_factor_enabled = 1, two_factor_secret = ? WHERE id = ?',
      [secret, res.locals.currentUser.id]
    );

    delete req.session.setup2faSecret;
    setFlash(req, '2FA enabled');
    return res.redirect('/');
  } catch (err) {
    console.error('2FA ENABLE ERROR:', err);
    setFlash(req, 'Failed to enable 2FA');
    return res.redirect('/2fa/setup');
  }
});

/* =========================
   WIFI SYNC / PASSWORDS
========================= */

app.post('/sites/:id/sync-wifi', requireAuth, async (req, res) => {
  try {
    const siteId = Number(req.params.id);
    const ids = await allowedSiteIds(res.locals.currentUser);

    if (!ids.includes(siteId)) {
      return res.status(403).send('Forbidden');
    }

    const [[site]] = await pool.query(
      'SELECT * FROM sites WHERE id = ?',
      [siteId]
    );

    if (!site) {
      return res.status(404).send('Site not found');
    }

    const controller = await getController(site.controller_id);
    const wlans = await listWlans(controller, site.unifi_site_name);

    for (const wlan of wlans) {
      await pool.query(
        `INSERT INTO wifi_networks (site_id, wlan_id, ssid_name, security_type)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           ssid_name = VALUES(ssid_name),
           security_type = VALUES(security_type)`,
        [siteId, wlan.wlan_id, wlan.ssid_name, wlan.security_type]
      );
    }

    setFlash(req, `Synced ${wlans.length} WiFi network(s)`);
  } catch (err) {
    setFlash(req, `WiFi sync failed: ${err.message}`);
  }

  return res.redirect('/');
});

app.post('/wifi/:id/manual-change', requireAuth, async (req, res) => {
  try {
    const wifiId = Number(req.params.id);

    const [[wifi]] = await pool.query(
      `SELECT wn.*, s.unifi_site_name, s.controller_id
       FROM wifi_networks wn
       JOIN sites s ON s.id = wn.site_id
       WHERE wn.id = ?`,
      [wifiId]
    );

    const ids = await allowedSiteIds(res.locals.currentUser);
    if (!wifi || !ids.includes(Number(wifi.site_id))) {
      return res.status(403).send('Forbidden');
    }

    const controller = await getController(wifi.controller_id);

    const result = await changePassword(
      controller,
      wifi.unifi_site_name,
      wifi.wlan_id,
      req.body.password
    );

    await pool.query(
      'UPDATE wifi_networks SET last_password = ?, last_changed_at = NOW() WHERE id = ?',
      [result.password, wifiId]
    );

    await pool.query(
      `INSERT INTO password_history
       (wifi_network_id, changed_by_user_id, change_type, password_plain)
       VALUES (?, ?, ?, ?)`,
      [wifiId, res.locals.currentUser.id, 'manual', result.password]
    );

    setFlash(req, 'Password changed');
    return res.redirect('/');
  } catch (err) {
    console.error('MANUAL PASSWORD ERROR:', err);
    setFlash(req, `Manual change failed: ${err.message}`);
    return res.redirect('/');
  }
});

app.post('/wifi/:id/schedules', requireAuth, async (req, res) => {
  try {
    const wifiId = Number(req.params.id);

    const [[wifi]] = await pool.query(
      `SELECT wn.*, s.id AS site_id
       FROM wifi_networks wn
       JOIN sites s ON s.id = wn.site_id
       WHERE wn.id = ?`,
      [wifiId]
    );

    const ids = await allowedSiteIds(res.locals.currentUser);
    if (!wifi || !ids.includes(Number(wifi.site_id))) {
      return res.status(403).send('Forbidden');
    }

    await pool.query(
      `INSERT INTO schedules
       (wifi_network_id, name, cron_expr, timezone_name, use_random_password, password_length, fixed_password, enabled, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
      [
        wifiId,
        req.body.name,
        req.body.cron_expr,
        req.body.timezone_name || 'Europe/London',
        req.body.use_random_password === '1' ? 1 : 0,
        Number(req.body.password_length || 16),
        req.body.fixed_password || null,
        res.locals.currentUser.id
      ]
    );

    await rebuildSchedules();
    setFlash(req, 'Schedule created');
    return res.redirect('/');
  } catch (err) {
    console.error('CREATE SCHEDULE ERROR:', err);
    setFlash(req, 'Failed to create schedule');
    return res.redirect('/');
  }
});

app.get('/share/:wifiId', requireAuth, async (req, res) => {
  try {
    const wifiId = Number(req.params.wifiId);

    const [[wifi]] = await pool.query(
      `SELECT wn.*, s.id AS site_id
       FROM wifi_networks wn
       JOIN sites s ON s.id = wn.site_id
       WHERE wn.id = ?`,
      [wifiId]
    );

    const ids = await allowedSiteIds(res.locals.currentUser);
    if (!wifi || !ids.includes(Number(wifi.site_id))) {
      return res.status(403).send('Forbidden');
    }

    if (!wifi.last_password) {
      setFlash(req, 'No password stored for this WiFi yet');
      return res.redirect('/');
    }

    const qr = await QRCode.toDataURL(
      wifiQrPayload(wifi.ssid_name, wifi.last_password)
    );

    return res.render('share', { wifi, qr });
  } catch (err) {
    console.error('SHARE PAGE ERROR:', err);
    return res.status(500).send('Failed to load share page');
  }
});

/* =========================
   ACCESS MODE
========================= */

app.post('/wifi/:id/access-mode', requireAuth, async (req, res) => {
  try {
    const mode = String(req.body.access_mode || '').trim();

    if (!['password', 'voucher'].includes(mode)) {
      return res.status(400).send('Invalid access mode');
    }

    await pool.query(
      'UPDATE wifi_networks SET access_mode = ? WHERE id = ?',
      [mode, req.params.id]
    );

    return res.redirect('/');
  } catch (err) {
    console.error('ACCESS MODE SAVE ERROR:', err);
    return res.status(500).send('Failed to save access mode: ' + err.message);
  }
});

/* =========================
   VOUCHERS
========================= */

app.post('/wifi/:id/vouchers/create', requireAuth, async (req, res) => {
  try {
    const [[wifi]] = await pool.query(
      `SELECT wn.*, s.unifi_site_name, c.base_url, c.username, c.password_plain, c.mode
       FROM wifi_networks wn
       JOIN sites s ON s.id = wn.site_id
       JOIN controllers c ON c.id = s.controller_id
       WHERE wn.id = ?`,
      [req.params.id]
    );

    if (!wifi) {
      return res.status(404).send('WiFi network not found');
    }

    const guestName = req.body.guest_name || '';
    const bookingReference = req.body.booking_reference || '';
    const count = Math.max(1, Number(req.body.voucher_count || 1));
    const durationHours = Math.max(1, Number(req.body.duration_hours || 24));
    const durationMinutes = durationHours * 60;

    const settings = {
      controllerUrl: wifi.base_url,
      username: wifi.username,
      password: wifi.password_plain,
      mode: wifi.mode || 'unifi_os',
      site: wifi.unifi_site_name
    };

    const note = [guestName, bookingReference].filter(Boolean).join(' / ');
	await createHotspotVouchers(
  settings,
  wifi.unifi_site_name,
  {
    count,
    minutes: durationMinutes,
    note
  }
);

const [batchResult] = await pool.query(
  `INSERT INTO voucher_batches
   (wifi_id, guest_name, booking_reference, voucher_count, duration_minutes, created_by_user_id)
   VALUES (?, ?, ?, ?, ?, ?)`,
  [
    wifi.id,
    guestName,
    bookingReference,
    count,
    durationMinutes,
    req.session.userId
  ]
);

const batchId = batchResult.insertId;

const allVouchers = await listHotspotVouchers(settings, wifi.unifi_site_name);
console.log('UNIFI VOUCHER LIST RESPONSE:', JSON.stringify(allVouchers, null, 2));

const recentVouchers = allVouchers
  .slice()
  .sort((a, b) => Number(b.create_time || 0) - Number(a.create_time || 0))
  .slice(0, count);

for (const v of recentVouchers) {
  const code =
    v.code ||
    v.voucher_code ||
    v.voucher ||
    v.qrcode ||
    v.password ||
    v.name ||
    null;

  if (code) {
    await pool.query(
      `INSERT INTO vouchers
       (batch_id, wifi_id, voucher_code, note, valid_minutes)
       VALUES (?, ?, ?, ?, ?)`,
      [batchId, wifi.id, String(code), note, durationMinutes]
    );
  }
}   
    

    return res.redirect(`/wifi/${wifi.id}/vouchers`);
  } catch (err) {
    console.error('CREATE VOUCHERS ERROR:', err);
    return res.status(500).send('Failed to create vouchers: ' + err.message);
  }
});

app.post('/wifi/:id/vouchers/from-booking', requireAuth, async (req, res) => {
  try {
    const [[wifi]] = await pool.query(
      `SELECT wn.*, s.unifi_site_name, c.base_url, c.username, c.password_plain, c.mode
       FROM wifi_networks wn
       JOIN sites s ON s.id = wn.site_id
       JOIN controllers c ON c.id = s.controller_id
       WHERE wn.id = ?`,
      [req.params.id]
    );

    if (!wifi) {
      return res.status(404).send('WiFi network not found');
    }

    const guestName = req.body.guest_name || '';
    const bookingReference = req.body.booking_reference || '';
    const checkIn = new Date(req.body.check_in);
    const checkOut = new Date(req.body.check_out);
    const people = Math.max(1, Number(req.body.people || 1));

    if (
      Number.isNaN(checkIn.getTime()) ||
      Number.isNaN(checkOut.getTime()) ||
      checkOut <= checkIn
    ) {
      return res.status(400).send('Invalid booking dates');
    }

    const durationMinutes = Math.max(
      60,
      Math.ceil((checkOut.getTime() - checkIn.getTime()) / 60000)
    );

    const settings = {
      controllerUrl: wifi.base_url,
      username: wifi.username,
      password: wifi.password_plain,
      mode: wifi.mode || 'unifi_os',
      site: wifi.unifi_site_name
    };

    const note = [guestName, bookingReference].filter(Boolean).join(' / ');

    await createHotspotVouchers(
  settings,
  wifi.unifi_site_name,
  {
    count,
    minutes: durationMinutes,
    note
  }
);

const [batchResult] = await pool.query(
  `INSERT INTO voucher_batches
   (wifi_id, guest_name, booking_reference, voucher_count, duration_minutes, created_by_user_id)
   VALUES (?, ?, ?, ?, ?, ?)`,
  [
    wifi.id,
    guestName,
    bookingReference,
    count,
    durationMinutes,
    req.session.userId
  ]
);

const batchId = batchResult.insertId;

const allVouchers = await listHotspotVouchers(settings, wifi.unifi_site_name);
console.log('UNIFI VOUCHER LIST RESPONSE:', JSON.stringify(allVouchers, null, 2));

const recentVouchers = allVouchers
  .slice()
  .sort((a, b) => Number(b.create_time || 0) - Number(a.create_time || 0))
  .slice(0, count);

for (const v of recentVouchers) {
  const code =
    v.code ||
    v.voucher_code ||
    v.voucher ||
    v.qrcode ||
    v.password ||
    v.name ||
    null;

  if (code) {
    await pool.query(
      `INSERT INTO vouchers
       (batch_id, wifi_id, voucher_code, note, valid_minutes)
       VALUES (?, ?, ?, ?, ?)`,
      [batchId, wifi.id, String(code), note, durationMinutes]
    );
  }
}

    return res.redirect(`/wifi/${wifi.id}/vouchers`);
  } catch (err) {
    console.error('BOOKING VOUCHERS ERROR:', err);
    return res.status(500).send('Failed to create booking vouchers: ' + err.message);
  }
});

app.get('/wifi/:id/vouchers', requireAuth, async (req, res) => {
  try {
    const [[wifi]] = await pool.query(
      'SELECT * FROM wifi_networks WHERE id = ?',
      [req.params.id]
    );

    const [batches] = await pool.query(
      `SELECT * FROM voucher_batches
       WHERE wifi_id = ?
       ORDER BY created_at DESC`,
      [req.params.id]
    );

    const [codes] = await pool.query(
      `SELECT v.*, vb.guest_name, vb.booking_reference
       FROM vouchers v
       JOIN voucher_batches vb ON vb.id = v.batch_id
       WHERE v.wifi_id = ?
       ORDER BY v.created_at DESC`,
      [req.params.id]
    );

    return res.render('wifi_vouchers', { wifi, batches, codes });
  } catch (err) {
    console.error('VOUCHER PAGE ERROR:', err);
    return res.status(500).send('Failed to load vouchers page: ' + err.message);
  }
});

/* =========================
   SCHEDULE WORKER
========================= */

let tasks = [];

async function runSchedule(scheduleId) {
  const [[row]] = await pool.query(
    `SELECT sc.*, wn.wlan_id, wn.id AS wifi_id, wn.ssid_name, s.unifi_site_name, s.controller_id
     FROM schedules sc
     JOIN wifi_networks wn ON wn.id = sc.wifi_network_id
     JOIN sites s ON s.id = wn.site_id
     WHERE sc.id = ? AND sc.enabled = 1`,
    [scheduleId]
  );

  if (!row) return;

  const controller = await getController(row.controller_id);
  const password = row.use_random_password
    ? randomPassword(row.password_length)
    : row.fixed_password;

  const result = await changePassword(
    controller,
    row.unifi_site_name,
    row.wlan_id,
    password
  );

  await pool.query(
    'UPDATE wifi_networks SET last_password = ?, last_changed_at = NOW() WHERE id = ?',
    [result.password, row.wifi_id]
  );

  await pool.query(
    `INSERT INTO password_history
     (wifi_network_id, changed_by_user_id, change_type, password_plain)
     VALUES (?, NULL, ?, ?)`,
    [row.wifi_id, 'scheduled', result.password]
  );
}

async function rebuildSchedules() {
  tasks.forEach(task => task.stop());
  tasks = [];

  const [rows] = await pool.query(
    'SELECT id, cron_expr, timezone_name FROM schedules WHERE enabled = 1'
  );

  for (const row of rows) {
    try {
      const task = cron.schedule(
        row.cron_expr,
        () => runSchedule(row.id).catch(console.error),
        { timezone: row.timezone_name || 'Europe/London' }
      );
      tasks.push(task);
    } catch (err) {
      console.error('Invalid cron for schedule', row.id, err.message);
    }
  }
}

/* =========================
   STARTUP
========================= */

(async () => {
  try {
    await migrate();
    await rebuildSchedules();
    app.listen(PORT, () => {
      console.log(`App running on ${PORT}`);
    });
  } catch (err) {
    console.error('APP START ERROR:', err);
    process.exit(1);
  }
})();