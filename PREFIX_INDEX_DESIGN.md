# pg_algorand: byte-prefix index for `note` searches (design brief)

Status: IMPLEMENTED in pg_algorand 2.1 (`note_prefix.c`), 2026-09-01, tested
locally on PG 18.6 (regression suite `sql/note_prefix.sql` + a 200k-row rig).
Deployed to the first mainnet indexer host on 2026-09-02 (section 8); index
builds on the remaining mainnet hosts started the same day. Written 2026-09-01
from a live investigation on two mainnet indexer hosts; section 7 records what
changed between the original design and the implementation.

## 1. Problem

The Algorand indexer API (`ghcr.io/algonode/indexer`, read-only role, direct
connections to the mainnet `ledgerdb` PGs) generates note-prefix searches:

```sql
SELECT t.round, t.intra, t.txn, root.txn, t.extra, t.asset, h.realtime
FROM txn t JOIN block_header h ON t.round = h.round
[JOIN txn_participation p ...]
WHERE t.round >= $1 AND t.typeenum = $2
  AND substring(decode(t.txn -> 'txn' ->> 'note', 'base64') from 1 for 7) = $3
ORDER BY t.round, t.intra LIMIT 1000
```

- `txn` is ~3.67B rows / multi-TB per host. The substring qual is a full
  filter today -> ~1,650 statement-timeout kills/day on one mainnet host alone
  (75s timeout at the connection proxy; the kills predate it).
- The prefix LENGTH is a **literal in the SQL text**; only the value is a
  parameter. Observed distribution over 24h of killed statements
  (`docker logs <pg container> | grep -oE 'from 1 for [0-9]+' | sort | uniq -c`):
  `for 7` ≈ 84%, `for 3` ≈ 10%, `for 6` ≈ 6%, tail of 12 other lengths (1–34).
- **HARD CONSTRAINT (owner decision): the query shape will not be changed**,
  and per-length expression indexes were rejected ("I will not create tens of
  indexes for every possible substring range"). Storage matters: index should
  hold only the first X bytes (MySQL `INDEX(col(7))` semantics).

Related but out of scope: the other large source of kills is a client-side
recursive CTE that is absent from the indexer source and cannot be fixed on
our side. The connection proxy in front of the databases cannot rewrite
queries (its rewrite engine is sharding-only; plugins are route-only). So the
fix belongs in PostgreSQL, in pg_algorand.

## 2. Verified facts to build on (2026-09-01)

- **Planner matches the full expression chain.** A btree expression index on
  `(typeenum, substring(decode(txn->'txn'->>'note','base64') from 1 for 7), round)`
  is used by the verbatim query shape — proven on a temp table on a mainnet
  host (Index Cond carried all three columns). The decode/jsonb/substring chain is
  immutable and index-safe on PG 18.6.
- **Note stats** (0.01% TABLESAMPLE of a mainnet txn table): 50.7% of rows carry a
  note; avg decoded length 189 bytes; est_total_rows 3,672,504,320.
  => full-note expression index ≈ 400 GB; 7-byte prefix ≈ 25–45 GB
  (before PG13+ btree dedup, which will crush repeated spam prefixes);
  `(prefix7, round)` ≈ 40–60 GB.
- **No existing extension does this.** The `prefix` extension (prefix_range)
  solves the inverse problem; SP-GiST `text_ops`/`pg_trgm` require `^@`/LIKE
  operators the query does not use. Web-searched 2026-09-01: nothing ships a
  substring-equality-to-range planner support function.

## 3. Design: two components

### 3a. Planner support function (the essential piece)

A C function implementing `SupportRequestIndexCondition`
(`src/include/nodes/supportnodes.h`), attached to bytea equality, that
recognizes at plan time:

```
substring(<indexed-expr> from 1 for N) = <const/param>
```

and derives **lossy** index conditions on `<indexed-expr>`, with the original
qual retained as recheck. Semantics (B = the compared value, n = N):

- `substring(x,1,n) = B` ⇔
  `(length(B) = n AND x starts_with B) OR (length(B) < n AND x = B)`.
  A single derived range `x >= B AND x < byte_successor(B)` covers both
  (lossy; recheck filters). `byte_successor` = increment last non-0xFF byte,
  truncating trailing 0xFFs; if B is all-0xFF, drop the upper bound.
- NULL/absent note: `->>` yields NULL -> qual is NULL -> row excluded; the
  derived range never matches NULL. Consistent.
- Model implementation: `src/backend/utils/adt/like_support.c`
  (`match_pattern_prefix`) — it does exactly this for `LIKE 'abc%'`.

Attachment routes, in order of preference (both need testing):
1. `ALTER FUNCTION pg_catalog.byteaeq(bytea,bytea) SUPPORT pg_algorand_prefix_support;`
   — superuser DDL; TEST whether PG18 permits altering a builtin's prosupport.
   Plan-time-only cost; the hook returns NULL instantly for non-matching quals.
2. If builtins refuse: shadow operator `=(bytea,bytea)` in a dedicated schema
   placed ahead of pg_catalog in the API role's search_path — same
   oprcode behavior (RESTRICT/JOIN/HASHES/MERGES identical to the original)
   plus the support function. Scoped to the one role, no catalog mods.

### 3b. Storage-truncated index (the storage-saving piece)

Two options; decide during prototyping:

- **Option 1 (cheapest, recommended first): plain btree expression index**
  on `substring(decode(...) from 1 for 7)` — partial:
  `WHERE substring(decode(...) from 1 for 7) IS NOT NULL`
  (the predicate MUST be IS NOT NULL on the exact expression: predtest can
  prove strict-equality -> IS NOT NULL, but cannot prove `txn->'txn' ? 'note'`).
  Storage already capped at 7 bytes/entry. The support function then derives
  conditions **against this indexed expression**: for N >= 7, equality on
  `substring(B,1,7)`; for N < 7, a range over the prefix column. All lengths,
  one index, no custom AM. Include `round` as 2nd column so hot (spam)
  prefixes stream out round-ordered into the LIMIT instead of sort-exploding.
- **Option 2 (fully general X): GiST opclass** with a `compress` support
  function storing `first_X_bytes(val)` and opclass options (PG13+) for
  per-index `prefixlen = X` (crib: `contrib/btree_gist` bytea opclass +
  `pg_trgm`'s siglen options). GiST `consistent` may return lossy -> heap
  recheck is native. More code (~1–2k lines); only worth it if Option 1's
  fixed-7 expression proves too rigid.
- Existence proof that lossy transformed storage is a supported AM pattern:
  `contrib/bloom`.

## 4. Milestones

- M0: scratch-DB prototype of the support function alone against a plain
  btree on a bytea column (no jsonb): prove derived Index Cond appears in
  EXPLAIN for `substring(col,1,N)=c`, N != index anything. Includes the
  ALTER-builtin-SUPPORT feasibility test.
- M1: extend matching to expression indexes (indexed expr = substring(...,7))
  and the full decode/jsonb chain; edge cases (all-0xFF, len(B)<N, NULL).
- M2: package into pg_algorand 2.1 (PGXS: add object + upgrade script
  `pg_algorand--2.0--2.1.sql`), regression tests (REGRESS harness exists).
- M3: build via the existing image pipeline (-> urtho/pg18an; NOTE: a stale
  image with the old 13MB Go .so once deadlocked PG18 AIO during REINDEX —
  always verify image freshness), deploy to one host first, `CREATE INDEX
  CONCURRENTLY` (hours on multi-TB), watch the
  `canceling statement due to statement timeout` rate in the PG logs drop,
  then mirror to the other hosts.

## 5. Acceptance

- EXPLAIN of the verbatim killed query (all observed N) shows Index Cond on
  the prefix index + Filter recheck; no seq scan of txn.
- Kill-log rate for API note-searches drops from ~1,650/day to ~0.
- Index size on mainnet <= ~60 GB; insert overhead acceptable (conduit
  write path unaffected beyond one small index maintenance).

## 6. Environment notes for the next session

- Repo: PGXS, pure C since 2.0 (no Go/cgo).
- Prod: PG 18.6 in urtho/pg18an, one compose stack per network per host.
- Kill-log evidence + length distribution: the PG container log (STATEMENT
  lines carry full SQL; canceled queries never appear in pg_stat_statements —
  the log is the only source).
- Temp-table planner-matching rig (reusable):
  `CREATE TEMP TABLE scratch_txn(round bigint, typeenum smallint, txn jsonb)`
  + generate_series + expression index + `SET enable_seqscan=off` + EXPLAIN.

## 7. Implementation notes (2026-09-01, supersedes 3a/3b where they differ)

- **3a as written does not work.** `match_opclause_to_indexcol()` only calls
  a support function when the indexed expression is a *direct* operand of the
  operator. In `substring(<expr>,1,N) = $3` the indexed expression is nested
  inside `substring()`, so a support function on `byteaeq` (or any opclass,
  GiST included) is never consulted. Same for the shadow-operator route, which
  would additionally break btree/hash matching for every bytea `=`.
- **What was built instead:** a `planner_hook` (`note_prefix.c`) that rewrites
  the Query before planning. For each `substring(x,1,N) = B` (either operand
  order, `substr()` too, `FROM s FOR l` with s <= 1) it looks up the valid
  indexes of x's relation for expression columns `substring(x,1,K)` and adds
  conditions on that expression. With P = substring(x,1,K):
  N > K: `P = substring(B,1,K)` (lossy, original kept; works for Params);
  N = K spelled differently: `P = B`; N < K, len(B) = N: `P >= B AND
  P < successor(B)` (no upper bound for all-0xFF B); N < K, len(B) < N:
  `P = B`. For N <= K the derived form is an exact three-valued equivalent
  and *replaces* the clause (keeping it would multiply a default 0.005
  selectivity into the estimate, 200x too low). N < K needs B's value: Const,
  or bound Param in a custom plan; generic plans get nothing for N < K, so the
  plancache keeps choosing custom plans (LIKE-prefix behaviour). Derived
  clauses are built from the query's own expression, so Vars keep their
  nulling rels and LEFT JOIN shapes work. Kill switch:
  `SET pg_algorand.prefix_rewrite = off`. Requires
  `shared_preload_libraries = 'pg_algorand'` (or `session_preload_libraries`
  on the API role); if the library is not loaded nothing happens.
- **Index shape (differs from 3b):** `(prefix7, round, intra, typeenum)`
  partial `WHERE prefix7 IS NOT NULL`. Prefix first + round/intra next gives
  round-ordered streaming into the LIMIT with and without a `typeenum`
  filter; typeenum-first would need a skip scan and a full sort for the
  no-tx-type variant. `intra` and `typeenum` are free (MAXALIGN: 8+8+8+4+2 ->
  32 bytes either way). Size: ~36 B/entry incl. line pointer, no dedup
  (keys are unique) => ~75 GB on mainnet at 1.86B noted rows, not the
  40-60 GB in section 2; dropping both trailing columns gives ~58 GB.
- **Statistics:** the planner never uses expression stats from a *partial*
  index (`examine_variable`, selfuncs.c). Without them every prefix is
  estimated at 0.5%. `CREATE STATISTICS ... ON (substring(...) from 1 for 7)
  FROM txn` fixes it (spam prefix estimated 60,053 vs 60k actual in the rig).
  Mandatory part of the DDL.
- **Observed plans (rig, correct stats):** hot 7-byte prefix -> ordered Index
  Scan on the prefix index, merge/nested-loop join, LIMIT stops after 1000
  rows, no sort. Hot 3-byte family -> round-ordered PK scan with the derived
  range as filter (finds 1000 rows after ~5k). Rare prefixes -> index scan.
  N > 7 within a hot 7-byte family -> inherently scans the family (7 bytes is
  all the index knows); no single-index plan can avoid that.
- **Verification:** 71 on/off result-equivalence cases (all observed N, short
  and long B, all-0xFF, empty/NULL B, NOT / IS NOT TRUE / OR / CTE /
  subquery / LEFT JOIN both sides / B from another rel / Params in custom and
  generic plans) all identical. `make installcheck` passes (2 tests).
- **Remaining (M3):** build image, `shared_preload_libraries`, deploy to one
  host, `CREATE INDEX CONCURRENTLY` + `CREATE STATISTICS` + `ANALYZE`, watch
  kill rate, mirror to the rest. Possible later lever if size matters: exclude the top
  spam prefixes with a partial predicate (planner can prove `P = B` implies
  `P <> 'spam'` for literal B).

## 8. Deployment and production observations (2026-09-02, first mainnet host)

- **Deployed:** `urtho/pg18an` digest `640c1b8d…` (pg_algorand 2.1 `.so` built
  08:19 UTC). Added `pg_algorand` to `shared_preload_libraries` in the stack's
  `postgresql.conf` and recreated only the postgres service
  (`docker compose up -d --no-deps postgres`). Clean fast shutdown (the
  postgres image's STOPSIGNAL is SIGINT), 3 s downtime,
  `ALTER EXTENSION pg_algorand UPDATE TO '2.1'`. `txn_note_prefix7_idx`
  (71 GB, built earlier with CONCURRENTLY in 43 min) valid,
  `txn_note_prefix7_stats` present.
- **Caveat found:** the stack's config template used by its regeneration
  script predates PG 18 and has no `shared_preload_libraries` line, so
  regenerating the config would silently drop the preload. Fix the template
  before using the regeneration path.
- **API SQL shape** (pg_stat_statements, API role):
  `SELECT t.round, t.intra, t.txn, root.txn, t.extra, t.asset, h.realtime FROM txn t
  JOIN block_header h ON t.round = h.round LEFT OUTER JOIN txn root ON t.round =
  root.round AND (t.extra->>'root-intra')::int = root.intra WHERE
  substring(decode(t.txn -> 'txn' ->> 'note','base64') from 1 for N) = $1
  ORDER BY t.round, t.intra LIMIT n`. pgx named prepared statements (`lrupsc_*`).
- **Measured (cold cache unless noted), rewrite on:**

  | case | family size | result |
  |---|---|---|
  | N=7 `algotea` (hot) | ~35k / 3000 rounds | Index Scan, 100 rows, 58 ms (same plan with rewrite off: N=K is native) |
  | N=7 `bingoma` (rare) | | 31 ms |
  | N=4 `zzqq` (miss) | 0 | 0.06 ms; rewrite off plans a PK crawl over the table |
  | N=12 `x402-payment` in hot 7-family `x402-pa` | 723k | 5 ms for 10 rows: `P = 'x402-pa'` + filter, round-ordered |
  | N=4 `algo` | 665k | 34.5 s cold / 1.1 s warm |
  | N=3 `DQY` (mostly inner txns) | 292k | 22 s cold / 13 s warm |

  The two slow cases are the inherent limit: a round-ordered LIMIT across
  several 7-byte values reads the whole family, and PostgreSQL cannot push the
  sort/LIMIT below the joins to `block_header` and `txn root`, so every family
  row is joined before the top-N sort. The public API role has a 5 s
  statement timeout, so these time out there. Before the rewrite they were PK crawls
  (unbounded for recent-only families), so this is not a regression, but hot
  N<7 remains proportional to family size.
- **Planning time** is 15-17 ms for the indexer query with the rewrite on or
  off (10 indexes incl. partial/expression ones, plus the self-join).
- **Plan cache finding (blocker for N<7 on the API):** after five executions
  of a prepared statement, plancache builds a generic plan. With no parameter
  value nothing can be derived for N<K, and the unindexed plan (PK crawl under
  LIMIT at default selectivity) is *estimated* cheap (cost 11934), so plancache
  adopts it and the index is never used again for that N. Verified with
  `PREPARE`/`EXPLAIN EXECUTE` x7 on the deployed host: executions 1-5 use the
  index range, 6+ show `Filter: substring(... FOR 3) = $1` on `txn_pkey`. N=7
  generic plans are fine (`P = $1`).
  **Fix (commit 4faf1f5):** the hook adds 1e10 to the total cost of any plan
  built with an unbound external Param on a N<K prefix clause, so plancache
  keeps custom plans for those statements (`PREFIX_UNBOUND_PARAM_PENALTY` in
  `note_prefix.c`, regression test `p3_generic_penalized`/`p3c`). Extension
  version stays 2.1 (no SQL change), so a rollout is image rebuild + pull +
  restart of the postgres service, no ALTER EXTENSION. Deployed to the first
  host the same day (digest `269905b2…`); executions 6 and 7 now keep the
  index range. Alternative without a rebuild: `plan_cache_mode =
  force_custom_plan` on the API role (it runs ~47 statements/s, planning is
  15 ms for this query).
- **Rollout to the other six mainnet hosts** started 2026-09-02 09:00 UTC:
  `CREATE INDEX CONCURRENTLY` + `CREATE STATISTICS` + `ANALYZE txn` run
  detached on each host, holding the stack's maintenance lock so the nightly
  vacuum/reindex jobs skip instead of queueing behind the build. Image,
  preload and `ALTER EXTENSION` on those hosts are still to do.
