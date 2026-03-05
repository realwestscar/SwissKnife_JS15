import { execSync } from 'node:child_process';
import postgres from 'postgres';

const nodeEnv = process.env.NODE_ENV ?? 'development';
if (nodeEnv === 'production') {
  throw new Error('Refusing to reset database in production');
}

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const sql = postgres(process.env.DATABASE_URL, { prepare: false });

try {
  await sql`drop schema public cascade`;
  await sql`create schema public`;
  await sql`grant all on schema public to postgres`;
  await sql`grant all on schema public to public`;
} finally {
  await sql.end({ timeout: 5 });
}

execSync('npm.cmd run db:migrate', { stdio: 'inherit' });
execSync('node scripts/seed.mjs', { stdio: 'inherit' });

console.log('Database reset completed');
