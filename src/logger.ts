/**
 * Minimal structured logger — one JSON object per line on stdout/stderr.
 *
 * Hand-rolled rather than a dependency on purpose: this repo ships publicly
 * and every dependency is a supply-chain surface a self-hoster inherits. A
 * logger is thirty lines; pino is not worth the audit.
 *
 * DISCIPLINE THAT MATTERS MORE THAN THE IMPLEMENTATION: never pass a raw
 * error object, a request body, a header, or an `authHash`/token to `fields`.
 * Every call site in this service logs a scrubbed message string and
 * non-secret identifiers only (account id, status code, byte counts). The
 * mail transports (`mail/transport.ts`) follow the same rule for the same
 * reason.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER = { debug: 10, info: 20, warn: 30, error: 40 } satisfies Record<LogLevel, number>;

export type LogFields = Record<string, string | number | boolean | null>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

export function isLogLevel(value: string | undefined): value is LogLevel {
  return value === 'debug' || value === 'info' || value === 'warn' || value === 'error';
}

export function createLogger(options: { component: string; level: LogLevel }): Logger {
  const threshold = LEVEL_ORDER[options.level];

  function emit(level: LogLevel, message: string, fields?: LogFields): void {
    if (LEVEL_ORDER[level] < threshold) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      component: options.component,
      message,
      ...fields,
    });
    if (level === 'error' || level === 'warn') {
      process.stderr.write(`${line}\n`);
      return;
    }
    process.stdout.write(`${line}\n`);
  }

  return {
    debug: (message, fields) => emit('debug', message, fields),
    info: (message, fields) => emit('info', message, fields),
    warn: (message, fields) => emit('warn', message, fields),
    error: (message, fields) => emit('error', message, fields),
  };
}

/** A logger that discards everything — for tests and for optional-logger call sites. */
export function createSilentLogger(): Logger {
  return {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
  };
}
