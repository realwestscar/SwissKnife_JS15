import { type NextRequest } from 'next/server';

export function getClientIp(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

export function hasJsonContentType(request: NextRequest): boolean {
  const contentType = request.headers.get('content-type');
  return Boolean(contentType && contentType.toLowerCase().includes('application/json'));
}
