# AlgoRand Postgres extension by AlgoNode

## About pg_algorand

A set of utility functions to convert between binary arrays and various Algorand textual object encodings.

Since version 2.0 the extension is pure C: the NFD LSIG functions no longer
pull in a cgo/Go runtime, so no Go toolchain is needed to build and the
library does not spawn threads or install signal handlers inside PostgreSQL
backends. All functions are `PARALLEL SAFE`. Version 2.1 adds planner support
for byte-prefix searches (below). Upgrade with
`ALTER EXTENSION pg_algorand UPDATE TO '2.1';` after installing the new build.

## Byte-prefix searches on bytea expressions (2.1)

The Algorand indexer API searches transaction notes by prefix with

```sql
WHERE substring(decode(txn -> 'txn' ->> 'note', 'base64') from 1 for 7) = $3
```

where the prefix length is a literal that varies per request (7 is the common
case, 3 and 6 are frequent, anything from 1 to 34 shows up). PostgreSQL can
only use an index for such a clause when the indexed expression is a direct
operand of the operator, so one expression index per length would be needed.

Since 2.1 the library installs a planner hook that derives conditions on any
existing `substring(<bytea expr> from 1 for K)` btree expression index for
every N:

| clause                     | derived condition on P = substring(x,1,K)                 |
|----------------------------|-----------------------------------------------------------|
| N > K                      | `P = substring(B,1,K)`, original kept as recheck filter   |
| N = K (other spelling)     | `P = B`                                                   |
| N < K, len(B) = N          | `P >= B AND P < successor(B)` (no upper bound if B is all 0xFF) |
| N < K, len(B) < N          | `P = B`                                                   |

For N <= K the derived form is an exact equivalent and replaces the clause;
for N > K it is a lossy pre-filter and the original clause stays. The K to use
is read from the indexes that exist on the table, so nothing has to be
configured. For N < K the value of B must be known at plan time, which is the
case for literals and for bound parameters in custom plans (the normal path
for `$n` parameters, the same behaviour as `LIKE 'abc%'`).

With server-side prepared statements (pgx, JDBC, `PREPARE`) the plan cache
normally switches to a generic plan after five executions. A generic plan for
N < K cannot use the prefix index, and because the planner has no value to
estimate with, the unindexed plan looks cheap (LIMIT over a primary-key scan).
The hook therefore marks such generic plans as prohibitively expensive, so the
plan cache keeps building custom plans for those statements; the price is a
few milliseconds of planning per execution. Statements with N >= K are
unaffected and may use generic plans.

### Setup

The hook lives in the shared library and needs no SQL objects, but the
library must be loaded before planning:

```
shared_preload_libraries = 'pg_algorand'      # postgresql.conf, restart
```

or, for a single role without restart:

```sql
ALTER ROLE readonly SET session_preload_libraries = 'pg_algorand';
```

Index and statistics for the indexer's `txn` table (the statistics object is
required: the planner never uses expression stats from a partial index):

```sql
CREATE INDEX CONCURRENTLY txn_note_prefix7_idx
    ON txn USING btree (
        substring(decode(txn -> 'txn' ->> 'note', 'base64') from 1 for 7),
        round,
        intra,
        typeenum
    )
    WHERE substring(decode(txn -> 'txn' ->> 'note', 'base64') from 1 for 7) IS NOT NULL;

CREATE STATISTICS txn_note_prefix7_stats
    ON (substring(decode(txn -> 'txn' ->> 'note', 'base64') from 1 for 7)) FROM txn;
ANALYZE txn;
```

Column order matters: with the prefix first and `round, intra` next, the
indexer's `ORDER BY round, intra LIMIT n` is served in index order without a
sort, whether or not a `typeenum` filter is present. Runtime switch:

```sql
SET pg_algorand.prefix_rewrite = off;
```

## Range conditions across join equalities (2.2)

PostgreSQL derives equalities through equivalence classes (`a = b AND a = 5`
gives `b = 5`) but never inequalities. The indexer's transaction pages look
like

```sql
FROM txn t JOIN block_header h ON t.round = h.round
WHERE t.round >= $1 ... ORDER BY t.round, t.intra LIMIT 1000
```

and nothing tells the planner that `h.round >= $1`. A plan that drives the
join from `block_header` scans that index from its first key and probes `txn`
for every round below `$1`, finding nothing; once the per-round probe is costed
accurately (a correct `n_distinct` on `round`) that plan is the cheapest LIMIT
plan on paper and by far the slowest one in practice (seconds instead of
milliseconds).

The same planner hook therefore adds, before planning, every condition
`column OP value` (`OP` one of `<`, `<=`, `>=`, `>`) to all columns joined to
it with `=` of the same type and operator family in the WHERE clause or an
inner join. Only conditions that hold for every output row are used and
produced: nothing at or below the nullable side of an outer join is touched,
so results never change. The value side must be safe to evaluate twice (no
volatile or set-returning functions); an uncorrelated sub-select is allowed
and becomes a second init plan. Runtime switch:

```sql
SET pg_algorand.propagate_inequalities = off;
```

## About AlgoNode

We operate a free algod and algorand-indexer valilla API service. 
Check us out at https://algonode.io

## Install 
```bash
sudo apt-get install postgresql-server-dev-X.Y  #Replace X.Y with your version of Postgres`
```

```bash
git clone https://github.com/algonode/pg_algorand
cd pg_algorand
sh ./build.sh
```
```sql
CREATE EXTENSION pg_algorand;
```

Regression tests (`make installcheck`) need a running server the current OS
user can reach as a superuser, e.g. `make installcheck PGPORT=5432 PGUSER=postgres`.

## Usage

```sql
SELECT 
  COUNT(*) FROM account 
WHERE 
  addr = AddressTxt2Bin('ALGONODEIBJTET5OSEAXIHDSIEG7C2DOFB2WDYLRZTXN3NXVJ3NJD26L4E');
```    

```sql
SELECT 
  addr, AddressBin2Txt(addr) 
FROM 
  account 
LIMIT 1;
```

## Example views

```sql
CREATE OR REPLACE VIEW v_asset AS
SELECT
  index as asset_id
  ,creator_addr 
  ,AddressBin2Txt(creator_addr) creator
  ,deleted 
  ,created_at
  ,closed_at
  ,AddressBin2Txt(decode(params ->> 'c', 'base64')) clawback
  ,AddressBin2Txt(decode(params ->> 'f', 'base64')) freeze
  ,AddressBin2Txt(decode(params ->> 'm', 'base64')) manager
  ,AddressBin2Txt(decode(params ->> 'r', 'base64')) reserve
  ,CAST(params ->> 't' as NUMERIC(20,0)) total
  ,params ->> 'dc' as decimals
  ,params ->> 'am' as metadata
  ,params ->> 'au' as url
  ,params ->> 'an' as name
  ,params ->> 'un' as unit
  ,params ->> 'df' as frozen
FROM 
  asset
```



## Support AlgoNode

If you like what we do feel free to support us by sending some microAlgos to

**AlgoNode wallet**: `ALGONODEIBJTET5OSEAXIHDSIEG7C2DOFB2WDYLRZTXN3NXVJ3NJD26L4E`
