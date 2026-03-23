async function login(controller) {
  const base = String(controller.base_url || controller.controllerUrl || '').replace(/\/$/, '');
  const username = controller.username || '';
  const password = controller.password_plain || controller.password || '';
  const mode = controller.mode || 'unifi_os';

  const loginPath = mode === 'legacy' ? '/api/login' : '/api/auth/login';

  const response = await fetch(base + loginPath, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      password
    })
  });

  if (!response.ok) {
    throw new Error(`UniFi login failed: ${response.status} ${response.statusText}`);
  }

  const raw = response.headers.get('set-cookie') || '';
  if (!raw) {
    throw new Error('No session cookie returned by UniFi controller');
  }

  return raw
    .split(',')
    .map(x => x.split(';')[0].trim())
    .filter(Boolean)
    .join('; ');
}

function apiBase(controller, siteName) {
  const base = String(controller.base_url || controller.controllerUrl || '').replace(/\/$/, '');
  const site = encodeURIComponent(siteName || controller.site || 'default');
  const mode = controller.mode || 'unifi_os';

  return mode === 'legacy'
    ? `${base}/api/s/${site}`
    : `${base}/proxy/network/api/s/${site}`;
}

async function request(controller, cookie, siteName, method, path, body) {
  const response = await fetch(apiBase(controller, siteName) + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Cookie': cookie
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await response.text();

  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    data = { raw: text };
  }

  if (!response.ok) {
    throw new Error(`UniFi API ${method} ${path} failed: ${response.status} ${response.statusText} ${text}`);
  }

  return data;
}

async function listSites(controller) {
  const cookie = await login(controller);
  const base = String(controller.base_url || controller.controllerUrl || '').replace(/\/$/, '');
  const mode = controller.mode || 'unifi_os';

  const path = mode === 'legacy'
    ? '/api/self/sites'
    : '/proxy/network/api/self/sites';

  const response = await fetch(base + path, {
    headers: {
      'Cookie': cookie
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to list sites: ${response.status} ${response.statusText}`);
  }

  const json = await response.json();

  return Array.isArray(json.data)
    ? json.data.map(s => ({
        name: s.name,
        desc: s.desc || ''
      }))
    : [];
}

async function listWlans(controller, siteName) {
  const cookie = await login(controller);
  const json = await request(controller, cookie, siteName, 'GET', '/rest/wlanconf');

  return Array.isArray(json.data)
    ? json.data.map(w => ({
        wlan_id: w._id,
        ssid_name: w.name,
        security_type: w.security || ''
      }))
    : [];
}

async function changePassword(controller, siteName, wlanId, newPassword) {
  const cookie = await login(controller);
  const current = await request(controller, cookie, siteName, 'GET', '/rest/wlanconf');

  const wlan = (current.data || []).find(x => x._id === wlanId);
  if (!wlan) {
    throw new Error('WiFi network not found in UniFi');
  }

  const payload = {
    ...wlan,
    x_passphrase: newPassword
  };

  delete payload._id;
  delete payload.site_id;

  await request(
    controller,
    cookie,
    siteName,
    'PUT',
    `/rest/wlanconf/${encodeURIComponent(wlanId)}`,
    payload
  );

  return {
    ssid_name: wlan.name,
    password: newPassword
  };
}

async function createHotspotVouchers(controller, siteName, payload) {
  const cookie = await login(controller);

 const body = {
  cmd: 'create-voucher',
  n: Number(payload.count || 1),
  minutes: Number(payload.minutes || 1440),
  note: payload.note || ''
};

// Only send optional limits if they have real values
if (payload.quota && Number(payload.quota) > 0) {
  body.quota = Number(payload.quota);
}

if (payload.up && Number(payload.up) >= 2) {
  body.up = Number(payload.up);
}

if (payload.down && Number(payload.down) >= 2) {
  body.down = Number(payload.down);
}

if (payload.bytes && Number(payload.bytes) > 0) {
  body.bytes = Number(payload.bytes);
}
  return await request(
    controller,
    cookie,
    siteName,
    'POST',
    '/cmd/hotspot',
    body
  );
}

async function listHotspotVouchers(controller, siteName) {
  const cookie = await login(controller);
  const result = await request(controller, cookie, siteName, 'GET', '/stat/voucher');
  return Array.isArray(result.data) ? result.data : [];
}

module.exports = {
  login,
  listSites,
  listWlans,
  changePassword,
  createHotspotVouchers,
  listHotspotVouchers
};