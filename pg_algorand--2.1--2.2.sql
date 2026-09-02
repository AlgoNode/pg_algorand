-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_algorand UPDATE TO '2.2'" to load this file. \quit

-- 2.2 adds range-condition propagation across join equalities to the
-- planner hook (ineq_propagation.c): with  t.round = h.round  in an inner
-- join and  t.round >= $1  in WHERE, the planner also sees  h.round >= $1,
-- so a plan that drives the join from h no longer scans h from its first
-- key.  Lives entirely in the shared library, creates no SQL objects; it is
-- active once the new library is loaded (restart with
-- shared_preload_libraries = 'pg_algorand').
-- Runtime switch: SET pg_algorand.propagate_inequalities = off.
