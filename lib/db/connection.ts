import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '@/lib/config/env';

let sqlClient: postgres.Sql | null = null;
let drizzleClient: ReturnType<typeof drizzle> | null = null;

function getSslMode(): boolean | 'require' {
  return env.NODE_ENV === 'development' || env.NODE_ENV === 'test' ? false : 'require';
}

export function getSqlClient(): postgres.Sql {
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not configured');
  }

  if (!sqlClient) {
    sqlClient = postgres(env.DATABASE_URL, {
      max: 10,
      ssl: getSslMode(),
      prepare: false,
      idle_timeout: 20,
      connect_timeout: 10,
    });
  }

  return sqlClient;
}

export function getDrizzleClient() {
  if (!drizzleClient) {
    drizzleClient = drizzle(getSqlClient());
  }

  return drizzleClient;
}

export async function closeDatabaseConnection() {
  if (sqlClient) {
    await sqlClient.end({ timeout: 1 });
    sqlClient = null;
    drizzleClient = null;
  }
}

export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const client = getSqlClient();
    await client`select 1`;
    return true;
  } catch {
    return false;
  }
}
