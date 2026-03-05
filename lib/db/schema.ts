import { index, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';

export const userRoleEnum = pgEnum('user_role', ['user', 'admin', 'superadmin']);
export const userStatusEnum = pgEnum('user_status', ['active', 'inactive', 'suspended']);
export const auditSeverityEnum = pgEnum('audit_severity', ['info', 'warn', 'error']);

export const users = pgTable(
  'users',
  {
    id: text('id').primaryKey(),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash').notNull(),
    role: userRoleEnum('role').notNull().default('user'),
    status: userStatusEnum('status').notNull().default('active'),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    emailUniqueIdx: uniqueIndex('users_email_unique_idx').on(table.email),
  })
);

export const passwordResetTokens = pgTable(
  'password_reset_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userIdx: index('password_reset_tokens_user_idx').on(table.userId),
    expiresAtIdx: index('password_reset_tokens_expires_at_idx').on(table.expiresAt),
  })
);

export const emailVerificationTokens = pgTable(
  'email_verification_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userIdx: index('email_verification_tokens_user_idx').on(table.userId),
    expiresAtIdx: index('email_verification_tokens_expires_at_idx').on(table.expiresAt),
  })
);

export const sessions = pgTable(
  'sessions',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    familyId: text('family_id').notNull(),
    parentSessionId: text('parent_session_id'),
    refreshTokenHash: text('refresh_token_hash').notNull(),
    refreshTokenJti: text('refresh_token_jti').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    replacedBySessionId: text('replaced_by_session_id'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    reuseDetectedAt: timestamp('reuse_detected_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userRevokedIdx: index('sessions_user_revoked_idx').on(table.userId, table.revokedAt),
    expiresAtIdx: index('sessions_expires_at_idx').on(table.expiresAt),
    jtiUniqueIdx: uniqueIndex('sessions_refresh_token_jti_unique_idx').on(table.refreshTokenJti),
    familyIdx: index('sessions_family_idx').on(table.familyId),
  })
);

export const auditLogs = pgTable(
  'audit_logs',
  {
    id: text('id').primaryKey(),
    userId: text('user_id').references(() => users.id, { onDelete: 'set null' }),
    actorUserId: text('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    eventType: text('event_type').notNull(),
    severity: auditSeverityEnum('severity').notNull().default('info'),
    requestId: text('request_id'),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>().default(null),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userCreatedAtIdx: index('audit_logs_user_created_at_idx').on(table.userId, table.createdAt),
    actorCreatedAtIdx: index('audit_logs_actor_created_at_idx').on(table.actorUserId, table.createdAt),
  })
);

export type UserRow = typeof users.$inferSelect;
export type SessionRow = typeof sessions.$inferSelect;
export type AuditLogRow = typeof auditLogs.$inferSelect;
export type PasswordResetTokenRow = typeof passwordResetTokens.$inferSelect;
export type EmailVerificationTokenRow = typeof emailVerificationTokens.$inferSelect;
