import { successResponse } from '@/lib/utils/response';

export async function GET() {
  const requestId = crypto.randomUUID();
  return successResponse(
    {
      status: 'ok',
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    },
    200,
    requestId
  );
}
