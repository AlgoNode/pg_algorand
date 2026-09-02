-- Range-condition propagation across join equalities (ineq_propagation.c).
-- The hook only needs the library loaded; it creates no SQL objects.
LOAD 'pg_algorand';
SET max_parallel_workers_per_gather = 0;
-- Plain seq scans keep the plans stable: one Filter line per relation.
SET enable_indexscan = off;
SET enable_indexonlyscan = off;
SET enable_bitmapscan = off;

CREATE TABLE ip_hdr (round bigint PRIMARY KEY, realtime bigint NOT NULL);
CREATE TABLE ip_txn (
    round    bigint   NOT NULL,
    intra    integer  NOT NULL,
    typeenum smallint NOT NULL,
    PRIMARY KEY (round, intra)
);
CREATE TABLE ip_part (
    addr  bytea   NOT NULL,
    round bigint  NOT NULL,
    intra integer NOT NULL,
    PRIMARY KEY (addr, round, intra)
);
INSERT INTO ip_hdr SELECT r, 1000 + r * 4 FROM generate_series(1, 200) r;
INSERT INTO ip_txn SELECT r, i, 1 + (r + i) % 3 FROM generate_series(1, 200) r, generate_series(0, 2) i;
INSERT INTO ip_part SELECT decode(lpad(((r + i) % 5)::text, 2, '0'), 'hex'), r, i
  FROM generate_series(1, 200) r, generate_series(0, 2) i;
-- a round with transactions but no header, so LEFT JOINs have a NULL side
DELETE FROM ip_hdr WHERE round = 170;
ANALYZE ip_hdr;
ANALYZE ip_txn;
ANALYZE ip_part;

-- Number of plan lines (Filter / Index Cond) carrying a given condition text.
CREATE FUNCTION ip_qual_count(q text, qual text) RETURNS int LANGUAGE plpgsql AS $$
DECLARE
    line text;
    n    int := 0;
BEGIN
    FOR line IN EXECUTE 'EXPLAIN (COSTS OFF) ' || q LOOP
        IF position(qual IN line) > 0 THEN n := n + 1; END IF;
    END LOOP;
    RETURN n;
END $$;

-- 1. Inner join, condition in WHERE: both sides get it (2), none without the hook (1).
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 ORDER BY t.round, t.intra LIMIT 10$$, '(round >= 150)') AS on_hook;
SET pg_algorand.propagate_inequalities = off;
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 ORDER BY t.round, t.intra LIMIT 10$$, '(round >= 150)') AS off_hook;
RESET pg_algorand.propagate_inequalities;

-- 2. Condition on the other side, other operators, value on the left.
SELECT ip_qual_count($$SELECT h.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE h.round < 20$$, '(round < 20)') AS lt_from_h;
SELECT ip_qual_count($$SELECT h.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE 150 <= t.round$$, '(150 <= round)') AS commuted;
SELECT ip_qual_count($$SELECT h.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round > 150 AND t.round <= 160$$, '(round > 150)') +
       ip_qual_count($$SELECT h.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round > 150 AND t.round <= 160$$, '(round <= 160)') AS two_bounds;

-- 3. Condition inside an inner-join ON clause, and comma joins.
SELECT ip_qual_count($$SELECT h.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round AND t.round >= 150$$, '(round >= 150)') AS in_on_clause;
SELECT ip_qual_count($$SELECT h.round FROM ip_txn t, ip_hdr h WHERE t.round = h.round AND t.round >= 150$$, '(round >= 150)') AS comma_join;

-- 4. Transitive: t = h and t = p gives all three sides the condition.
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round JOIN ip_part p ON t.round = p.round AND t.intra = p.intra WHERE p.addr = '\x00' AND t.round >= 150$$, '(round >= 150)') AS transitive;

-- 5. Outer joins: the nullable side never gets the condition ...
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t LEFT JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150$$, '(round >= 150)') AS left_nullable;
SELECT ip_qual_count($$SELECT t.round FROM ip_hdr h RIGHT JOIN ip_txn t ON t.round = h.round WHERE t.round >= 150$$, '(round >= 150)') AS right_nullable;
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t FULL JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150$$, '(round >= 150)') AS full_join;
-- ... but an inner join on the non-nullable side of a LEFT JOIN does (t and h, not root).
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round LEFT JOIN ip_txn root ON t.round = root.round AND root.intra = 0 WHERE t.round >= 150 ORDER BY t.round, t.intra LIMIT 10$$, '(round >= 150)') AS left_outer_side;
-- A condition that only holds inside an outer join's ON clause is not a source.
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t LEFT JOIN ip_hdr h ON t.round = h.round AND h.round >= 150$$, '(round >= 150)') AS on_of_outer;

-- 6. Results are identical with and without the hook, including NULL-extended rows.
SELECT count(*) AS n_on, count(h.round) AS matched
  FROM ip_txn t LEFT JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150;
SET pg_algorand.propagate_inequalities = off;
SELECT count(*) AS n_off, count(h.round) AS matched
  FROM ip_txn t LEFT JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150;
RESET pg_algorand.propagate_inequalities;
SELECT count(*) AS diff FROM (
    (SELECT t.round, t.intra, h.realtime FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 AND t.typeenum = 1 ORDER BY t.round, t.intra LIMIT 30)
    EXCEPT ALL
    (SELECT * FROM (SELECT t.round, t.intra, h.realtime FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 AND t.typeenum = 1 ORDER BY t.round, t.intra LIMIT 30) s)
) d;

-- 7. Parameters: a generic plan carries the condition on both sides.
PREPARE ip_page(bigint, smallint) AS
    SELECT t.round, t.intra, h.realtime FROM ip_txn t JOIN ip_hdr h ON t.round = h.round
     WHERE t.round >= $1 AND t.typeenum = $2 ORDER BY t.round, t.intra LIMIT 10;
SET plan_cache_mode = force_generic_plan;
SELECT ip_qual_count($$EXECUTE ip_page(150, 1)$$, '(round >= $1)') AS generic_plan;
SET plan_cache_mode = force_custom_plan;
SELECT ip_qual_count($$EXECUTE ip_page(150, 1)$$, '(round >= ''150''::bigint)') AS custom_plan;
RESET plan_cache_mode;
EXECUTE ip_page(198, 1);

-- 8. Right-hand expressions: an uncorrelated sub-select is duplicated as a
--    second init plan; correlated sub-selects and volatile functions are not
--    propagated; mixed-type equalities are left alone.
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= (SELECT round FROM ip_hdr WHERE realtime > 1600 ORDER BY realtime LIMIT 1)$$, 'round >= (InitPlan') AS uncorrelated_subselect;
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= (SELECT min(p.round) FROM ip_part p WHERE p.intra = t.intra)$$, 'round >= (SubPlan') AS correlated_subselect;
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= (random() * 100)::bigint$$, 'round >= ((random()') AS volatile_rhs;
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.intra = h.round WHERE t.intra >= 1$$, '(intra >= 1)') +
       ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.intra = h.round WHERE t.intra >= 1$$, '(round >= 1)') AS mixed_types;

-- 9. Nothing is added twice when the condition is already spelled out.
SELECT ip_qual_count($$SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 AND h.round >= 150$$, '(round >= 150)') AS already_present;

-- 10. Sub-queries are handled at their own level.
SELECT ip_qual_count($$SELECT * FROM (SELECT t.round FROM ip_txn t JOIN ip_hdr h ON t.round = h.round WHERE t.round >= 150 OFFSET 0) s$$, '(round >= 150)') AS in_subquery;

DEALLOCATE ip_page;
DROP FUNCTION ip_qual_count(text, text);
DROP TABLE ip_part, ip_txn, ip_hdr;
