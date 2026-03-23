require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool, migrate } = require('../lib/db');

async function main() {
  const [, , email, password, fullName] = process.argv;
  if (!email || !password || !fullName) {
    console.log('Usage: node scripts/init-admin.js admin@example.com StrongPassword123! "Admin Name"');
    process.exit(1);
  }
  await migrate();
  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    'INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), full_name = VALUES(full_name), role = VALUES(role)',
    [email, hash, fullName, 'super_admin']
  );
  console.log(`Super admin ready: ${email}`);
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
