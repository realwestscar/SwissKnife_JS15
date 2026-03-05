import { type NextRequest } from 'next/server';
import { updateUserSchema } from '@/lib/validation/schemas';
import { db } from '@/lib/db/client';
import { extractUser, requireAuth, requireRole, requireActiveStatus } from '@/lib/middleware/auth';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { ValidationError, NotFoundError, AuthorizationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { captureException } from '@/lib/observability/monitoring';

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireActiveStatus(user);

    // Authorization: can only view own profile or if admin
    if (user.id !== id && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('You can only view your own profile');
    }

    logger.info('Fetching user details', { userId: id }, requestId);

    // Fetch user
    const targetUser = await db.findUserById(id);
    if (!targetUser) {
      throw new NotFoundError('User not found');
    }

    return successResponse(
      {
        id: targetUser.id,
        email: targetUser.email,
        name: targetUser.name,
        role: targetUser.role,
        status: targetUser.status,
        createdAt: targetUser.createdAt,
        updatedAt: targetUser.updatedAt,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:GET', userId: id });
    logger.error('Failed to fetch user', details, requestId, {
      endpoint: '/api/users/[id]:GET',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireActiveStatus(user);

    // Authorization: can only update own profile or if admin
    if (user.id !== id && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('You can only update your own profile');
    }

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    const body = await request.json();

    // Validate input
    const validation = updateUserSchema.safeParse(body);
    if (!validation.success) {
      throw new ValidationError('Invalid input', { errors: validation.error.flatten() });
    }

    if (validation.data.role && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('Only admins can update user roles');
    }

    const existing = await db.findUserById(id);
    if (!existing) {
      throw new NotFoundError('User not found');
    }

    logger.info('Updating user', { userId: id }, requestId);

    // Update user
    const updated = await db.updateUser(id, validation.data);
    if (!updated) {
      throw new NotFoundError('User not found');
    }

    if (validation.data.role || validation.data.status) {
      await db.createAuditLog({
        userId: updated.id,
        actorUserId: user.id,
        eventType: 'users.privileged_update',
        requestId,
        ipAddress: ip,
        userAgent,
        metadata: {
          previousRole: existing.role,
          newRole: updated.role,
          previousStatus: existing.status,
          newStatus: updated.status,
        },
      });
    }

    return successResponse(
      {
        id: updated.id,
        email: updated.email,
        name: updated.name,
        role: updated.role,
        status: updated.status,
        createdAt: updated.createdAt,
        updatedAt: updated.updatedAt,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:PATCH', userId: id });
    logger.error('Failed to update user', details, requestId, {
      endpoint: '/api/users/[id]:PATCH',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireRole(user, 'admin', 'superadmin');

    const targetUser = await db.findUserById(id);
    if (!targetUser) {
      throw new NotFoundError('User not found');
    }

    logger.info('Deleting user', { userId: id }, requestId);

    // Delete user
    const deleted = await db.deleteUser(id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

    await db.createAuditLog({
      userId: id,
      actorUserId: user.id,
      eventType: 'users.deleted',
      severity: 'warn',
      requestId,
      ipAddress: ip,
      userAgent,
      metadata: {
        deletedUserEmail: targetUser.email,
        deletedUserRole: targetUser.role,
      },
    });

    return successResponse({ message: 'User deleted successfully' }, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:DELETE', userId: id });
    logger.error('Failed to delete user', details, requestId, {
      endpoint: '/api/users/[id]:DELETE',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
