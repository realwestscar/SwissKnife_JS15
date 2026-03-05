import crypto from 'crypto';
import { and, count, desc, eq, ilike, isNull, or } from 'drizzle-orm';
import { env } from '@/lib/config/env';
import { checkDatabaseHealth, getDrizzleClient } from '@/lib/db/connection';
import { auditLogs, sessions, users, type AuditLogRow, type SessionRow, type UserRow } from '@/lib/db/schema';
import { logger } from '@/lib/utils/logger';
import { type User } from '@/lib/types';

export interface DatabaseUser extends User {
  passwordHash: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  familyId: string;
  parentSessionId: string | null;
  refreshTokenHash: string;
  refreshTokenJti: string;
  ipAddress: string | null;
  userAgent: string | null;
  replacedBySessionId: string | null;
  revokedAt: Date | null;
  reuseDetectedAt: Date | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateSessionInput {
  id: string;
  userId: string;
  familyId: string;
  parentSessionId?: string | null;
  refreshTokenHash: string;
  refreshTokenJti: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  expiresAt: Date;
}

export interface RotateSessionInput {
  currentSessionId: string;
  replacement: CreateSessionInput;
}

export interface AuditLogInput {
  userId?: string | null;
  actorUserId?: string | null;
  eventType: string;
  severity?: 'info' | 'warn' | 'error';
  requestId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

interface UserListResult {
  users: DatabaseUser[];
  total: number;
}

interface DatabaseClient {
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  findUserByEmail(email: string): Promise<DatabaseUser | null>;
  findUserById(id: string): Promise<DatabaseUser | null>;
  createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser>;
  updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(page?: number, limit?: number): Promise<UserListResult>;
  searchUsers(query: string, page?: number, limit?: number): Promise<UserListResult>;
  createSession(session: CreateSessionInput): Promise<SessionRecord>;
  findSessionById(sessionId: string): Promise<SessionRecord | null>;
  rotateSession(input: RotateSessionInput): Promise<SessionRecord>;
  revokeSession(sessionId: string): Promise<boolean>;
  revokeSessionFamily(familyId: string): Promise<number>;
  markSessionReuseDetected(sessionId: string): Promise<void>;
  createAuditLog(log: AuditLogInput): Promise<void>;
  reset(): Promise<void>;
}

function mapUserRow(row: UserRow): DatabaseUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    passwordHash: row.passwordHash,
    role: row.role,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapSessionRow(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    userId: row.userId,
    familyId: row.familyId,
    parentSessionId: row.parentSessionId,
    refreshTokenHash: row.refreshTokenHash,
    refreshTokenJti: row.refreshTokenJti,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    replacedBySessionId: row.replacedBySessionId,
    revokedAt: row.revokedAt,
    reuseDetectedAt: row.reuseDetectedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function sanitizeUserUpdate(
  updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>
): Partial<Omit<DatabaseUser, 'id' | 'createdAt'>> {
  const sanitized: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>> = {};
  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      (sanitized as Record<string, unknown>)[key] = key === 'email' ? normalizeEmail(String(value)) : value;
    }
  }
  return sanitized;
}

class PostgresDatabase implements DatabaseClient {
  async initialize(): Promise<void> {
    await checkDatabaseHealth();
  }

  async healthCheck(): Promise<boolean> {
    return checkDatabaseHealth();
  }

  async findUserByEmail(email: string): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const [result] = await drizzle.select().from(users).where(eq(users.email, normalizeEmail(email))).limit(1);
    return result ? mapUserRow(result) : null;
  }

  async findUserById(id: string): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const [result] = await drizzle.select().from(users).where(eq(users.id, id)).limit(1);
    return result ? mapUserRow(result) : null;
  }

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser> {
    const drizzle = getDrizzleClient();
    const now = new Date();
    const id = crypto.randomUUID();
    const [inserted] = await drizzle
      .insert(users)
      .values({
        id,
        email: normalizeEmail(user.email),
        name: user.name,
        passwordHash: user.passwordHash,
        role: user.role,
        status: user.status,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    return mapUserRow(inserted);
  }

  async updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const sanitized = sanitizeUserUpdate(updates);
    if (Object.keys(sanitized).length === 0) {
      return this.findUserById(id);
    }

    const [updated] = await drizzle
      .update(users)
      .set({
        ...sanitized,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();

    return updated ? mapUserRow(updated) : null;
  }

  async deleteUser(id: string): Promise<boolean> {
    const drizzle = getDrizzleClient();
    const [deleted] = await drizzle.delete(users).where(eq(users.id, id)).returning({ id: users.id });
    return Boolean(deleted?.id);
  }

  async getAllUsers(page: number = 1, limit: number = 20): Promise<UserListResult> {
    const drizzle = getDrizzleClient();
    const offset = (page - 1) * limit;
    const [totalResult, pageResults] = await Promise.all([
      drizzle.select({ total: count(users.id) }).from(users),
      drizzle.select().from(users).orderBy(desc(users.createdAt)).limit(limit).offset(offset),
    ]);

    return {
      users: pageResults.map(mapUserRow),
      total: Number(totalResult[0]?.total ?? 0),
    };
  }

  async searchUsers(query: string, page: number = 1, limit: number = 20): Promise<UserListResult> {
    const drizzle = getDrizzleClient();
    const offset = (page - 1) * limit;
    const condition = or(ilike(users.email, `%${query}%`), ilike(users.name, `%${query}%`));

    const [totalResult, pageResults] = await Promise.all([
      drizzle.select({ total: count(users.id) }).from(users).where(condition),
      drizzle.select().from(users).where(condition).orderBy(desc(users.createdAt)).limit(limit).offset(offset),
    ]);

    return {
      users: pageResults.map(mapUserRow),
      total: Number(totalResult[0]?.total ?? 0),
    };
  }

  async createSession(session: CreateSessionInput): Promise<SessionRecord> {
    const drizzle = getDrizzleClient();
    const now = new Date();
    const [inserted] = await drizzle
      .insert(sessions)
      .values({
        id: session.id,
        userId: session.userId,
        familyId: session.familyId,
        parentSessionId: session.parentSessionId ?? null,
        refreshTokenHash: session.refreshTokenHash,
        refreshTokenJti: session.refreshTokenJti,
        ipAddress: session.ipAddress ?? null,
        userAgent: session.userAgent ?? null,
        expiresAt: session.expiresAt,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    return mapSessionRow(inserted);
  }

  async findSessionById(sessionId: string): Promise<SessionRecord | null> {
    const drizzle = getDrizzleClient();
    const [session] = await drizzle.select().from(sessions).where(eq(sessions.id, sessionId)).limit(1);
    return session ? mapSessionRow(session) : null;
  }

  async rotateSession(input: RotateSessionInput): Promise<SessionRecord> {
    const drizzle = getDrizzleClient();
    const now = new Date();

    return drizzle.transaction(async (tx) => {
      const currentUpdate = await tx
        .update(sessions)
        .set({
          revokedAt: now,
          replacedBySessionId: input.replacement.id,
          updatedAt: now,
        })
        .where(and(eq(sessions.id, input.currentSessionId), isNull(sessions.revokedAt)))
        .returning({ id: sessions.id });

      if (currentUpdate.length === 0) {
        throw new Error('Session was already rotated or revoked');
      }

      const [newSession] = await tx
        .insert(sessions)
        .values({
          id: input.replacement.id,
          userId: input.replacement.userId,
          familyId: input.replacement.familyId,
          parentSessionId: input.replacement.parentSessionId ?? null,
          refreshTokenHash: input.replacement.refreshTokenHash,
          refreshTokenJti: input.replacement.refreshTokenJti,
          ipAddress: input.replacement.ipAddress ?? null,
          userAgent: input.replacement.userAgent ?? null,
          expiresAt: input.replacement.expiresAt,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      return mapSessionRow(newSession);
    });
  }

  async revokeSession(sessionId: string): Promise<boolean> {
    const drizzle = getDrizzleClient();
    const [revoked] = await drizzle
      .update(sessions)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });

    return Boolean(revoked?.id);
  }

  async revokeSessionFamily(familyId: string): Promise<number> {
    const drizzle = getDrizzleClient();
    const revoked = await drizzle
      .update(sessions)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(sessions.familyId, familyId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });

    return revoked.length;
  }

  async markSessionReuseDetected(sessionId: string): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle
      .update(sessions)
      .set({ reuseDetectedAt: new Date(), updatedAt: new Date() })
      .where(eq(sessions.id, sessionId));
  }

  async createAuditLog(log: AuditLogInput): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle.insert(auditLogs).values({
      id: crypto.randomUUID(),
      userId: log.userId ?? null,
      actorUserId: log.actorUserId ?? null,
      eventType: log.eventType,
      severity: log.severity ?? 'info',
      requestId: log.requestId ?? null,
      ipAddress: log.ipAddress ?? null,
      userAgent: log.userAgent ?? null,
      metadata: log.metadata ?? null,
      createdAt: new Date(),
    });
  }

  async reset(): Promise<void> {
    if (env.NODE_ENV !== 'test') {
      return;
    }

    const drizzle = getDrizzleClient();
    await drizzle.delete(auditLogs);
    await drizzle.delete(sessions);
    await drizzle.delete(users);
  }
}

class InMemoryDatabase implements DatabaseClient {
  private users = new Map<string, DatabaseUser>();
  private usersByEmail = new Map<string, string>();
  private sessions = new Map<string, SessionRecord>();
  private auditTrail: AuditLogRow[] = [];

  async initialize(): Promise<void> {}

  async healthCheck(): Promise<boolean> {
    return true;
  }

  async findUserByEmail(email: string): Promise<DatabaseUser | null> {
    const id = this.usersByEmail.get(normalizeEmail(email));
    return id ? (this.users.get(id) ?? null) : null;
  }

  async findUserById(id: string): Promise<DatabaseUser | null> {
    return this.users.get(id) ?? null;
  }

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser> {
    const now = new Date();
    const created: DatabaseUser = {
      ...user,
      id: crypto.randomUUID(),
      email: normalizeEmail(user.email),
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(created.id, created);
    this.usersByEmail.set(created.email, created.id);
    return created;
  }

  async updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null> {
    const user = this.users.get(id);
    if (!user) {
      return null;
    }

    const updated: DatabaseUser = {
      ...user,
      ...sanitizeUserUpdate(updates),
      updatedAt: new Date(),
    };

    this.users.set(id, updated);
    this.usersByEmail.set(updated.email, updated.id);
    return updated;
  }

  async deleteUser(id: string): Promise<boolean> {
    const user = this.users.get(id);
    if (!user) {
      return false;
    }
    this.users.delete(id);
    this.usersByEmail.delete(user.email);
    return true;
  }

  async getAllUsers(page: number = 1, limit: number = 20): Promise<UserListResult> {
    const allUsers = Array.from(this.users.values()).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const start = (page - 1) * limit;
    return { users: allUsers.slice(start, start + limit), total: allUsers.length };
  }

  async searchUsers(query: string, page: number = 1, limit: number = 20): Promise<UserListResult> {
    const normalizedQuery = query.toLowerCase();
    const filtered = Array.from(this.users.values())
      .filter((user) => user.email.includes(normalizedQuery) || user.name.toLowerCase().includes(normalizedQuery))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const start = (page - 1) * limit;
    return { users: filtered.slice(start, start + limit), total: filtered.length };
  }

  async createSession(session: CreateSessionInput): Promise<SessionRecord> {
    const now = new Date();
    const created: SessionRecord = {
      id: session.id,
      userId: session.userId,
      familyId: session.familyId,
      parentSessionId: session.parentSessionId ?? null,
      refreshTokenHash: session.refreshTokenHash,
      refreshTokenJti: session.refreshTokenJti,
      ipAddress: session.ipAddress ?? null,
      userAgent: session.userAgent ?? null,
      replacedBySessionId: null,
      revokedAt: null,
      reuseDetectedAt: null,
      expiresAt: session.expiresAt,
      createdAt: now,
      updatedAt: now,
    };
    this.sessions.set(created.id, created);
    return created;
  }

  async findSessionById(sessionId: string): Promise<SessionRecord | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async rotateSession(input: RotateSessionInput): Promise<SessionRecord> {
    const current = this.sessions.get(input.currentSessionId);
    if (current && !current.revokedAt) {
      current.revokedAt = new Date();
      current.replacedBySessionId = input.replacement.id;
      current.updatedAt = new Date();
      this.sessions.set(current.id, current);
    }

    return this.createSession(input.replacement);
  }

  async revokeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session || session.revokedAt) {
      return false;
    }

    session.revokedAt = new Date();
    session.updatedAt = new Date();
    this.sessions.set(sessionId, session);
    return true;
  }

  async revokeSessionFamily(familyId: string): Promise<number> {
    let revoked = 0;
    for (const session of this.sessions.values()) {
      if (session.familyId === familyId && !session.revokedAt) {
        session.revokedAt = new Date();
        session.updatedAt = new Date();
        this.sessions.set(session.id, session);
        revoked++;
      }
    }
    return revoked;
  }

  async markSessionReuseDetected(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return;
    }
    session.reuseDetectedAt = new Date();
    session.updatedAt = new Date();
    this.sessions.set(sessionId, session);
  }

  async createAuditLog(log: AuditLogInput): Promise<void> {
    this.auditTrail.push({
      id: crypto.randomUUID(),
      userId: log.userId ?? null,
      actorUserId: log.actorUserId ?? null,
      eventType: log.eventType,
      severity: log.severity ?? 'info',
      requestId: log.requestId ?? null,
      ipAddress: log.ipAddress ?? null,
      userAgent: log.userAgent ?? null,
      metadata: log.metadata ?? null,
      createdAt: new Date(),
    });
  }

  async reset(): Promise<void> {
    this.users.clear();
    this.usersByEmail.clear();
    this.sessions.clear();
    this.auditTrail = [];
  }
}

const useInMemoryAdapter = env.ALLOW_IN_MEMORY_DB || !env.DATABASE_URL;

if (useInMemoryAdapter) {
  if (env.NODE_ENV === 'test' && !env.BUILD_VERIFY) {
    logger.warn('DATABASE_URL not set in test mode. Using in-memory database adapter for tests.');
  }
}

export const db: DatabaseClient = useInMemoryAdapter ? new InMemoryDatabase() : new PostgresDatabase();

export async function resetMockDatabase() {
  await db.reset();
}

db.initialize().catch((error) => {
  logger.error('Database initialization failed', { error: error instanceof Error ? error.message : String(error) });
});
