-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_algorand UPDATE TO '2.0'" to load this file. \quit

-- 2.0 reimplements the NFD LSIG functions in pure C: the module no longer
-- embeds a Go runtime (which spun up threads and signal handlers inside
-- every backend that loaded the library). The C symbols and function
-- signatures are unchanged, so existing dependents are unaffected; the
-- functions are now also safe to run in parallel workers.
ALTER FUNCTION GetNFDSigNameLSIG(text, int8) PARALLEL SAFE;
ALTER FUNCTION GetNFDSigRevAddressLSIG(text, int8) PARALLEL SAFE;
ALTER FUNCTION GetNFDSigRevAddressBinLSIG(bytea, int8) PARALLEL SAFE;
