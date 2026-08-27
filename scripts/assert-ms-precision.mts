/**
 * Asserts that every CAS-bearing timestamp is declared at millisecond
 * precision — the property whose absence made key-record rotation impossible
 * (ADR-0002, M160/06).
 *
 * It reads the REAL column type through drizzle's `getTableConfig` rather than
 * grepping `schema.ts`. A grep over a table declaration depends on the order
 * of the columns and on how many lines the window happens to span, so it goes
 * green for a correct fix and a broken one alike. This cannot: a bare
 * `timestamp` is `timestamp(6)` and fails here.
 */
import { getTableConfig } from 'drizzle-orm/pg-core';
import { syncKeyRecords, syncShares } from '../src/db/schema.ts';

const CAS_TABLES = [syncKeyRecords, syncShares];
const TIMESTAMPS = new Set(['created_at', 'updated_at']);

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
console.log('All CAS timestamps are millisecond-precision.');
