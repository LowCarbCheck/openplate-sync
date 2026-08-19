/**
 * Per-IP (and per-IP+account) attempt throttle with exponential backoff —
 * ported from the openplate app, trimmed to what a headless service needs.
 *
 * In-memory by design, not by omission. A single-container self-host is the
 * target deployment; adding Redis to get a shared bucket would make the
 * service harder to run for everyone in order to close a gap that only exists
 * for multi-replica operators. The state resets on restart, which is a real
 * limitation and is documented in the README rather than hidden.
 *
 * KEYING: the bucket combines the client IP with the submitted account
 * identifier where one exists. An attacker hammering `victim@example.com`
 * from IP A locks `A::victim@example.com` only — the real user on IP B hits
 * an untouched bucket. That is what keeps a throttle from becoming a free
 * account-lockout DoS. Signup has no pre-existing identifier to key on, so it
 * throttles by IP alone (keying it by the submitted email would let an
 * attacker evade it by rotating addresses).
 *
 * The DECISION functions are pure and unit-tested; the `Map`-backed wrappers
 * at the bottom are the imperative shell.
 */

export interface ThrottleConfig {
  /** Consecutive failures allowed before any lockout kicks in. */
  freeAttempts: number;
  baseLockoutMs: number;
  maxLockoutMs: number;
  /** Idle window after which a bucket is stale and its failure count restarts. */
  attemptResetMs: number;
}

export interface AttemptRecord {
  failures: number;
  lastFailureAt: number;
  /** Absolute epoch-ms instant the lock lifts, or `null` when unlocked. */
  lockedUntil: number | null;
}

export interface ThrottleDecision {
  locked: boolean;
  /** Milliseconds until the lock lifts; `0` when not locked. Surfaced as `Retry-After`. */
  retryAfterMs: number;
}

/** Failures 1–5 are free; the 6th locks for 1 min, then 2, 4, 8, capped at 15. A bucket idle 15 min resets. */
export const DEFAULT_THROTTLE_CONFIG: ThrottleConfig = {
  freeAttempts: 5,
  baseLockoutMs: 60 * 1000,
  maxLockoutMs: 15 * 60 * 1000,
  attemptResetMs: 15 * 60 * 1000,
};

export interface ThrottleKeyInput {
  /** Separates unrelated throttle domains sharing one store — `'login'` vs `'signup'`. Required so every call site names its domain. */
  namespace: string;
  ip: string;
  /** Account identifier to scope by in addition to IP. Omit when there is none (see the module header on signup). */
  identifier?: string;
}

export function throttleKey({ namespace, ip, identifier }: ThrottleKeyInput): string {
  const scope = identifier ? `${ip}::${identifier.trim().toLowerCase()}` : ip;
  return `${namespace}::${scope}`;
}

function lockoutDurationMs(overBy: number, config: ThrottleConfig): number {
  return Math.min(config.baseLockoutMs * 2 ** (overBy - 1), config.maxLockoutMs);
}

/** Pure lock check. Records nothing — call it before attempting authentication. */
export function evaluateThrottle(record: AttemptRecord | undefined, now: number): ThrottleDecision {
  if (!record || record.lockedUntil === null || now >= record.lockedUntil) {
    return { locked: false, retryAfterMs: 0 };
  }
  return { locked: true, retryAfterMs: record.lockedUntil - now };
}

/** Pure state transition for one failed attempt. Returns a new record — never mutates the input. */
export function registerFailure(
  record: AttemptRecord | undefined,
  now: number,
  config: ThrottleConfig = DEFAULT_THROTTLE_CONFIG,
): AttemptRecord {
  const isStale = !record || now - record.lastFailureAt > config.attemptResetMs;
  const failures = isStale ? 1 : record.failures + 1;
  const overBy = failures - config.freeAttempts;
  return {
    failures,
    lastFailureAt: now,
    lockedUntil: overBy > 0 ? now + lockoutDurationMs(overBy, config) : null,
  };
}

// ── Memory-growth control ──────────────────────────────────────────────────
// An attacker cycling through many fake IP/identifier pairs would otherwise
// grow the store forever. Two independent guards: a time-gated sweep of stale
// entries, and a hard entry cap with oldest-first eviction as the backstop
// between sweeps.

export const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
export const MAX_THROTTLE_ENTRIES = 10_000;

/**
 * A record is safe to drop once it is both unlocked AND idle past
 * `attemptResetMs` — exactly the condition under which `registerFailure`
 * already restarts it at `failures: 1`, so early deletion changes no
 * observable behaviour.
 */
export function isEntryStale(record: AttemptRecord, now: number, config: ThrottleConfig): boolean {
  return !evaluateThrottle(record, now).locked && now - record.lastFailureAt >= config.attemptResetMs;
}

export function findStaleKeys(
  entries: Iterable<[string, AttemptRecord]>,
  now: number,
  config: ThrottleConfig = DEFAULT_THROTTLE_CONFIG,
): string[] {
  const stale: string[] = [];
  for (const [key, record] of entries) {
    if (isEntryStale(record, now, config)) stale.push(key);
  }
  return stale;
}

/** Oldest-first keys to drop to bring the count back to `maxEntries`. Empty when already at or under the cap. */
export function findOverflowKeys(entries: Array<[string, AttemptRecord]>, maxEntries: number): string[] {
  if (entries.length <= maxEntries) return [];
  return entries
    .toSorted((a, b) => a[1].lastFailureAt - b[1].lastFailureAt)
    .slice(0, entries.length - maxEntries)
    .map(([key]) => key);
}

export function shouldSweep(lastSweepAt: number, now: number, intervalMs: number = SWEEP_INTERVAL_MS): boolean {
  return now - lastSweepAt >= intervalMs;
}

// ── Imperative shell ───────────────────────────────────────────────────────

export interface ThrottleStore {
  check(key: string, now?: number): ThrottleDecision;
  recordFailure(key: string, now?: number): void;
  clear(key: string): void;
}

/**
 * A `Map`-backed store. A FACTORY rather than a module singleton so tests get
 * an isolated instance and never leak throttle state between files.
 */
export function createThrottleStore(config: ThrottleConfig = DEFAULT_THROTTLE_CONFIG): ThrottleStore {
  const buckets = new Map<string, AttemptRecord>();
  let lastSweepAt = 0;

  function maybeSweep(now: number): void {
    if (shouldSweep(lastSweepAt, now)) {
      lastSweepAt = now;
      for (const key of findStaleKeys(buckets.entries(), now, config)) {
        buckets.delete(key);
      }
    }
    if (buckets.size > MAX_THROTTLE_ENTRIES) {
      for (const key of findOverflowKeys([...buckets.entries()], MAX_THROTTLE_ENTRIES)) {
        buckets.delete(key);
      }
    }
  }

  return {
    check(key, now = Date.now()) {
      maybeSweep(now);
      return evaluateThrottle(buckets.get(key), now);
    },
    recordFailure(key, now = Date.now()) {
      maybeSweep(now);
      buckets.set(key, registerFailure(buckets.get(key), now, config));
    },
    clear(key) {
      buckets.delete(key);
    },
  };
}
