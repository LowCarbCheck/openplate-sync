/**
 * Asserts that every timestamp this service serves over the wire is declared
 * at millisecond precision — the property whose absence made key-record
 * rotation impossible (ADR-0002, M160/06).
 *
 * The rule is deliberately WIDER than "columns that are CAS tokens today".
 * `research_contributions` compare-and-swaps on an integer version, not on a
 * timestamp, and `research_withdrawals.withdrawn_at` is not a token at all —
 * but both are handed to a client as ISO-8601, and a per-column judgement
 * about which timestamps will one day be compared for equality is exactly the
 * judgement that got this wrong the first time. One rule, every table.
 *
 * It reads the REAL column type through drizzle's `getTableConfig` rather than
 * grepping `schema.ts`. A grep over a table declaration depends on the order
 * of the columns and on how many lines the window happens to span, so it goes
 * green for a correct fix and a broken one alike. This cannot: a bare
 * `timestamp` is `timestamp(6)` and fails here.
 */
import { getTableConfig } from 'drizzle-orm/pg-core';
import { researchContributions, researchWithdrawals, syncKeyRecords, syncShares } from '../src/db/schema.ts';

const CAS_TABLES = [syncKeyRecords, syncShares, researchContributions, researchWithdrawals];
const TIMESTAMPS = new Set(['created_at', 'updated_at', 'withdrawn_at']);

let failed = false;
for (const table of CAS_TABLES) {
  const config = getTableConfig(table);
  for (const column of config.columns) {
    if (!TIMESTAMPS.has(column.name)) continue;
    const sqlType = column.getSQLType();
    if (/\(3\)/.test(sqlType)) continue;
    failed = true;
    console.error(
      `${config.name}.${column.name} is "${sqlType}" — it can hold a sub-millisecond tail ` +
        'the wire cannot carry, so a CAS token round-tripped through ISO-8601 will never match.',
    );
  }
}
if (failed) process.exit(1);
console.log('All wire-facing timestamps are millisecond-precision.');
