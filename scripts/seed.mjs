import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const nodeEnv = process.env.NODE_ENV ?? 'development';
if (nodeEnv === 'production') {
  throw new Error('Refusing to run seed in production');
}

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const sql = postgres(process.env.DATABASE_URL, { prepare: false });

async function upsertUser(email, name, role) {
  const passwordHash = await bcrypt.hash('ChangeMe123!', 10);
  const now = new Date();
  await sql`
    insert into users (id, email, name, password_hash, role, status, created_at, updated_at, email_verified_at)
    values (${crypto.randomUUID()}, ${email}, ${name}, ${passwordHash}, ${role}, 'active', ${now}, ${now}, ${now})
    on conflict (email) do update
    set
      name = excluded.name,
      role = excluded.role,
      status = excluded.status,
      password_hash = excluded.password_hash,
      email_verified_at = excluded.email_verified_at,
      updated_at = excluded.updated_at
  `;
}

try {
  await upsertUser('superadmin@swissknife.dev', 'Super Admin', 'superadmin');
  await upsertUser('admin@swissknife.dev', 'Admin User', 'admin');
  await upsertUser('user1@swissknife.dev', 'User One', 'user');
  await upsertUser('user2@swissknife.dev', 'User Two', 'user');
  await upsertUser('user3@swissknife.dev', 'User Three', 'user');
  await upsertUser('user4@swissknife.dev', 'User Four', 'user');
  await upsertUser('user5@swissknife.dev', 'User Five', 'user');
  console.log('Seed completed');
} finally {
  await sql.end({ timeout: 5 });
}
