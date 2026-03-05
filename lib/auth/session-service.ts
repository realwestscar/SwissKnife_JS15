import { type JWTPayload } from 'jose';
import { env } from '@/lib/config/env';
import { db, type DatabaseUser, type SessionRecord } from '@/lib/db/client';
import { signToken, verifyToken } from '@/lib/auth/jwt';
import { durationToMs, durationToSeconds } from '@/lib/utils/duration';
import { AuthenticationError } from '@/lib/utils/errors';
import { generateTokenId, hashRefreshToken, safeEqualHash } from '@/lib/auth/session-security';
import { withTrace } from '@/lib/observability/monitoring';

interface SessionContext {
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
}

interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshExpiresIn: number;
  sessionId: string;
}

interface RefreshTokenClaims {
  sub: string;
  sid: string;
  jti: string;
  type: 'refresh';
}

function buildAccessTokenPayload(user: DatabaseUser, sessionId: string) {
  return {
    sub: user.id,
    email: user.email,
    role: user.role,
    status: user.status,
    type: 'access',
    sid: sessionId,
  };
}

function parseRefreshClaims(payload: JWTPayload): RefreshTokenClaims {
  if (
    payload.type !== 'refresh' ||
    typeof payload.sub !== 'string' ||
    typeof payload.sid !== 'string' ||
    typeof payload.jti !== 'string'
  ) {
    throw new AuthenticationError('Invalid refresh token');
  }

  return {
    sub: payload.sub,
    sid: payload.sid,
    jti: payload.jti,
    type: 'refresh',
  };
}

async function buildSessionTokens(
  user: DatabaseUser,
  sessionId: string,
  refreshJti: string,
  familyId: string,
  context: SessionContext,
  parentSessionId?: string | null
): Promise<SessionTokens> {
  const refreshToken = await signToken(
    {
      sub: user.id,
      type: 'refresh',
      sid: sessionId,
      jti: refreshJti,
    },
    env.JWT_REFRESH_EXPIRY
  );

  const refreshHash = hashRefreshToken(refreshToken);
  const refreshExpiresAt = new Date(Date.now() + durationToMs(env.JWT_REFRESH_EXPIRY));

  await withTrace('auth.session.create', () =>
    db.createSession({
      id: sessionId,
      userId: user.id,
      familyId,
      parentSessionId: parentSessionId ?? null,
      refreshTokenHash: refreshHash,
      refreshTokenJti: refreshJti,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      expiresAt: refreshExpiresAt,
    })
  );

  const accessToken = await signToken(buildAccessTokenPayload(user, sessionId), env.JWT_EXPIRY);

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: durationToSeconds(env.JWT_EXPIRY),
    refreshExpiresIn: durationToSeconds(env.JWT_REFRESH_EXPIRY),
    sessionId,
  };
}

export async function createSessionTokensForUser(user: DatabaseUser, context: SessionContext): Promise<SessionTokens> {
  const sessionId = generateTokenId();
  const refreshJti = generateTokenId();
  return buildSessionTokens(user, sessionId, refreshJti, sessionId, context);
}

async function revokeFamilyForReuse(sessionId: string, familyId: string, context: SessionContext) {
  await db.markSessionReuseDetected(sessionId);
  await db.revokeSessionFamily(familyId);
  await db.createAuditLog({
    eventType: 'auth.refresh_reuse_detected',
    severity: 'warn',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: { sessionId, familyId },
  });
}

export async function rotateSessionTokens(refreshToken: string, context: SessionContext): Promise<SessionTokens> {
  const claims = parseRefreshClaims(await verifyToken(refreshToken));
  const session = await withTrace('auth.session.findById', () => db.findSessionById(claims.sid));

  if (!session || session.userId !== claims.sub) {
    throw new AuthenticationError('Invalid refresh token');
  }

  if (session.revokedAt || session.replacedBySessionId || session.reuseDetectedAt) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  if (session.expiresAt.getTime() <= Date.now()) {
    await db.revokeSession(session.id);
    throw new AuthenticationError('Refresh token expired');
  }

  if (session.refreshTokenJti !== claims.jti) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const providedHash = hashRefreshToken(refreshToken);
  if (!safeEqualHash(session.refreshTokenHash, providedHash)) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const user = await withTrace('auth.user.findById', () => db.findUserById(session.userId));
  if (!user || user.status !== 'active') {
    await db.revokeSessionFamily(session.familyId);
    throw new AuthenticationError('User account is not active');
  }

  const nextSessionId = generateTokenId();
  const nextJti = generateTokenId();
  const newRefreshToken = await signToken(
    {
      sub: user.id,
      type: 'refresh',
      sid: nextSessionId,
      jti: nextJti,
    },
    env.JWT_REFRESH_EXPIRY
  );

  const nextRefreshHash = hashRefreshToken(newRefreshToken);
  let rotatedSession: SessionRecord;
  try {
    rotatedSession = await withTrace('auth.session.rotate', () =>
      db.rotateSession({
        currentSessionId: session.id,
        replacement: {
          id: nextSessionId,
          userId: user.id,
          familyId: session.familyId,
          parentSessionId: session.id,
          refreshTokenHash: nextRefreshHash,
          refreshTokenJti: nextJti,
          ipAddress: context.ipAddress ?? null,
          userAgent: context.userAgent ?? null,
          expiresAt: new Date(Date.now() + durationToMs(env.JWT_REFRESH_EXPIRY)),
        },
      })
    );
  } catch {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const accessToken = await signToken(buildAccessTokenPayload(user, rotatedSession.id), env.JWT_EXPIRY);

  await db.createAuditLog({
    userId: user.id,
    actorUserId: user.id,
    eventType: 'auth.refresh_rotated',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: {
      previousSessionId: session.id,
      newSessionId: rotatedSession.id,
    },
  });

  return {
    accessToken,
    refreshToken: newRefreshToken,
    tokenType: 'Bearer',
    expiresIn: durationToSeconds(env.JWT_EXPIRY),
    refreshExpiresIn: durationToSeconds(env.JWT_REFRESH_EXPIRY),
    sessionId: rotatedSession.id,
  };
}

export async function revokeSessionByRefreshToken(refreshToken: string, context: SessionContext): Promise<void> {
  const claims = parseRefreshClaims(await verifyToken(refreshToken));
  const session = await withTrace('auth.session.findById', () => db.findSessionById(claims.sid));
  if (!session) {
    return;
  }

  if (session.userId !== claims.sub) {
    throw new AuthenticationError('Invalid refresh token');
  }

  await db.revokeSession(session.id);
  await db.createAuditLog({
    userId: session.userId,
    actorUserId: session.userId,
    eventType: 'auth.logout',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: { sessionId: session.id },
  });
}
