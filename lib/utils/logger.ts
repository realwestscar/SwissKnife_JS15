export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  requestId?: string;
  userId?: string;
  endpoint?: string;
  status?: number;
  latencyMs?: number;
}

interface LogEntry {
  level: LogLevel;
  timestamp: string;
  message: string;
  requestId?: string;
  context?: LogContext;
  data?: unknown;
}

const REDACTED = '[REDACTED]';
const SENSITIVE_FIELD_PATTERN = /(password|token|secret|authorization|cookie|pepper|key)/i;

function redactValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).map(([key, nestedValue]) => {
      if (SENSITIVE_FIELD_PATTERN.test(key)) {
        return [key, REDACTED];
      }
      return [key, redactValue(nestedValue)];
    });

    return Object.fromEntries(entries);
  }

  if (typeof value === 'string' && value.length > 2000) {
    return `${value.slice(0, 2000)}...`;
  }

  return value;
}

class Logger {
  private readonly isDevelopment = process.env.NODE_ENV === 'development';

  private write(level: LogLevel, message: string, data?: unknown, requestId?: string, context?: LogContext) {
    const entry: LogEntry = {
      level,
      timestamp: new Date().toISOString(),
      message,
      requestId,
      context,
      data: data === undefined ? undefined : redactValue(data),
    };

    if (this.isDevelopment) {
      const base = `[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}`;
      console.log(base, JSON.stringify({ requestId: entry.requestId, context: entry.context, data: entry.data }));
      return;
    }

    console.log(JSON.stringify(entry));
  }

  debug(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    if (!this.isDevelopment) {
      return;
    }
    this.write('debug', message, data, requestId, context);
  }

  info(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('info', message, data, requestId, context);
  }

  warn(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('warn', message, data, requestId, context);
  }

  error(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('error', message, data, requestId, context);
  }
}

export const logger = new Logger();
