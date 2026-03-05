import { type User } from '@/lib/types';

export interface DatabaseUser extends User {
  emailVerifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
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

export interface PasswordResetTokenRecord {
  tokenHash: string;
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface EmailVerificationTokenRecord {
  tokenHash: string;
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
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

export interface DatabaseClient {
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  findUserByEmail(email: string): Promise<DatabaseUser | null>;
  findUserById(id: string): Promise<DatabaseUser | null>;
  createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt' | 'emailVerifiedAt'>): Promise<DatabaseUser>;
  updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(page?: number, limit?: number): Promise<UserListResult>;
  searchUsers(query: string, page?: number, limit?: number): Promise<UserListResult>;
  createSession(session: CreateSessionInput): Promise<SessionRecord>;
  findSessionById(sessionId: string): Promise<SessionRecord | null>;
  rotateSession(input: RotateSessionInput): Promise<SessionRecord>;
  revokeSession(sessionId: string): Promise<boolean>;
  revokeSessionFamily(familyId: string): Promise<number>;
  revokeAllSessionsForUser(userId: string): Promise<number>;
  markSessionReuseDetected(sessionId: string): Promise<void>;
  createPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findPasswordResetToken(tokenHash: string): Promise<PasswordResetTokenRecord | null>;
  markPasswordResetTokenUsed(tokenHash: string): Promise<void>;
  createEmailVerificationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findEmailVerificationToken(tokenHash: string): Promise<EmailVerificationTokenRecord | null>;
  markEmailVerificationTokenUsed(tokenHash: string): Promise<void>;
  markEmailVerified(userId: string): Promise<void>;
  createAuditLog(log: AuditLogInput): Promise<void>;
  reset(): Promise<void>;
}
