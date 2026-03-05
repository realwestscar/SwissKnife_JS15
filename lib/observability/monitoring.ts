import { SpanStatusCode, context, trace } from '@opentelemetry/api';
import { env } from '@/lib/config/env';
import { logger } from '@/lib/utils/logger';

type SentryModule = {
  init: (options: { dsn: string; environment: string; tracesSampleRate: number }) => void;
  captureException: (error: unknown, context?: { extra?: Record<string, unknown> }) => void;
};

let sentryModulePromise: Promise<SentryModule | null> | null = null;
let sentryInitialized = false;

async function loadSentryModule(): Promise<SentryModule | null> {
  if (!env.SENTRY_DSN) {
    return null;
  }

  if (!sentryModulePromise) {
    sentryModulePromise = import(/* webpackIgnore: true */ '@sentry/node')
      .then((mod) => mod as unknown as SentryModule)
      .catch((error) => {
        logger.warn('Sentry module could not be loaded', {
          error: error instanceof Error ? error.message : String(error),
        });
        return null;
      });
  }

  return sentryModulePromise;
}

async function initializeSentryIfNeeded() {
  if (sentryInitialized || !env.SENTRY_DSN) {
    return;
  }

  const sentry = await loadSentryModule();
  if (!sentry) {
    return;
  }

  sentry.init({
    dsn: env.SENTRY_DSN,
    environment: env.NODE_ENV,
    tracesSampleRate: 0.1,
  });
  sentryInitialized = true;
}

export function captureException(error: unknown, metadata?: Record<string, unknown>) {
  if (!env.SENTRY_DSN) {
    return;
  }

  void (async () => {
    await initializeSentryIfNeeded();
    const sentry = await loadSentryModule();
    if (!sentry) {
      return;
    }

    sentry.captureException(error, {
      extra: metadata,
    });
  })();
}

export async function withTrace<T>(spanName: string, fn: () => Promise<T>): Promise<T> {
  const tracer = trace.getTracer('swissknife');
  const span = tracer.startSpan(spanName);

  return context.with(trace.setSpan(context.active(), span), async () => {
    try {
      const result = await fn();
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally {
      span.end();
    }
  });
}
