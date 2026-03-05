import { describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { errorResponse, paginatedResponse, successResponse } from '@/lib/utils/response';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';

describe('Response helpers', () => {
  it('threads explicit requestId through body and header for success responses', async () => {
    const response = successResponse({ ok: true }, 201, 'req-123');
    const payload = await response.json();

    expect(response.status).toBe(201);
    expect(response.headers.get('x-request-id')).toBe('req-123');
    expect(payload.meta.requestId).toBe('req-123');
    expect(payload.success).toBe(true);
  });

  it('generates and mirrors requestId when none is provided', async () => {
    const response = successResponse({ ok: true });
    const payload = await response.json();

    const headerRequestId = response.headers.get('x-request-id');
    expect(headerRequestId).toBeTruthy();
    expect(payload.meta.requestId).toBe(headerRequestId);
  });

  it('includes requestId in error responses', async () => {
    const response = errorResponse('VALIDATION_ERROR', 'Invalid input', 400, { field: 'email' }, 'err-456');
    const payload = await response.json();

    expect(response.status).toBe(400);
    expect(response.headers.get('x-request-id')).toBe('err-456');
    expect(payload.meta.requestId).toBe('err-456');
    expect(payload.error.code).toBe('VALIDATION_ERROR');
  });

  it('returns pagination metadata and requestId in paginated responses', async () => {
    const response = paginatedResponse([{ id: '1' }], 2, 10, 45, 200, 'page-789');
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('x-request-id')).toBe('page-789');
    expect(payload.meta.pagination.totalPages).toBe(5);
    expect(payload.meta.pagination.page).toBe(2);
  });
});

describe('Request helpers', () => {
  it('returns the first forwarded IP when x-forwarded-for has multiple values', () => {
    const request = new NextRequest('http://localhost/api/demo', {
      headers: { 'x-forwarded-for': '203.0.113.2, 198.51.100.20' },
    });

    expect(getClientIp(request)).toBe('203.0.113.2');
  });

  it('falls back to x-real-ip and then unknown', () => {
    const withRealIp = new NextRequest('http://localhost/api/demo', {
      headers: { 'x-real-ip': '198.51.100.4' },
    });
    const withNoIp = new NextRequest('http://localhost/api/demo');

    expect(getClientIp(withRealIp)).toBe('198.51.100.4');
    expect(getClientIp(withNoIp)).toBe('unknown');
  });

  it('accepts json content-type with charset suffix', () => {
    const request = new NextRequest('http://localhost/api/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ hello: 'world' }),
    });

    expect(hasJsonContentType(request)).toBe(true);
  });
});
