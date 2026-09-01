-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_algorand UPDATE TO '2.1'" to load this file. \quit

-- 2.1 adds a planner hook (note_prefix.c) that lets
--   substring(<bytea expr> from 1 for N) = <value>
-- use a btree expression index on substring(<bytea expr> from 1 for K) for
-- any N.  It lives entirely in the shared library and creates no SQL
-- objects; load it with shared_preload_libraries = 'pg_algorand' (or
-- session_preload_libraries for a single role) and restart / reconnect.
-- Runtime switch: SET pg_algorand.prefix_rewrite = off.
