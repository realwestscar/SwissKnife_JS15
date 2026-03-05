import { type ApiResponse, type PaginatedResponse } from '@/lib/types';
import { NextResponse } from 'next/server';
import crypto from 'crypto';

function generateRequestId(): string {
  return crypto.randomUUID();
}

export function successResponse<T>(data: T, status: number = 200, requestId?: string) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const response: ApiResponse<T> = {
    success: true,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}

export function paginatedResponse<T>(
  data: T[],
  page: number,
  limit: number,
  total: number,
  status: number = 200,
  requestId?: string
) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const totalPages = Math.ceil(total / limit);
  const response: PaginatedResponse<T> = {
    success: true,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}

export function errorResponse(
  code: string,
  message: string,
  status: number,
  details?: Record<string, unknown>,
  requestId?: string
) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const response: ApiResponse = {
    success: false,
    error: {
      code,
      message,
      details,
    },
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}
