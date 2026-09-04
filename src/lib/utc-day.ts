/**
 * The UTC calendar day an instant falls in, as `YYYY-MM-DD`.
 *
 * ONE FUNCTION, ONE RULE, ONE PLACE. The AI quota resets at UTC midnight
 * (`accounts.daily_ai_limit` against `ai_usage_days.day`), and the client
 * renders "used today" from the same boundary. Two implementations of that
 * arithmetic would disagree for one hour a day somewhere in the world, and the
 * disagreement would look like a quota that reset twice.
 *
 * UTC RATHER THAN THE OPERATOR'S ZONE, deliberately: a zone would have to be
 * configured, agreed with the client, and re-agreed for a person travelling.
 * A quota boundary needs to be predictable, not local.
 *
 * Pure — the instant is injected, never read from the clock.
 */

/** `YYYY-MM-DD` in UTC. `toISOString` is the shortest total implementation and never depends on a locale. */
export function utcDayKey(instant: Date): string {
  return instant.toISOString().slice(0, 10);
}
