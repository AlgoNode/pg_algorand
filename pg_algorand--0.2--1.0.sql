-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_algorand UPDATE TO '1.0'" to load this file. \quit

-- Same signatures and parameter names as 0.2 -> CREATE OR REPLACE is allowed.
-- (These two have dependents: views, functional indexes. Identity is preserved.)
CREATE OR REPLACE FUNCTION AddressTxt2Bin(
    data text
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'AddressTxt2Bin'
    LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION AddressBin2Txt(
    data bytea
)
    RETURNS text
    AS 'MODULE_PATHNAME', 'AddressBin2Txt'
    LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- 1.0 renamed these functions' parameters, which CREATE OR REPLACE forbids.
-- They had no dependents in production, so drop + recreate.
DROP FUNCTION GetNFDSigNameLSIG(text, bigint);
DROP FUNCTION GetNFDSigRevAddressLSIG(text, bigint);
DROP FUNCTION GetNFDSigRevAddressBinLSIG(bytea, bigint);

CREATE FUNCTION GetNFDSigNameLSIG(
    name text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigNameLSIG'
    LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION GetNFDSigRevAddressLSIG(
    pointed_to_address text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigRevAddressLSIG'
    LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION GetNFDSigRevAddressBinLSIG(
    pointed_to_address bytea,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigRevAddressBinLSIG'
    LANGUAGE C STRICT IMMUTABLE;

-- New in 1.0: the algoaddr type with I/O functions and casts
CREATE FUNCTION algoaddr_in(cstring) RETURNS algoaddr
    AS 'MODULE_PATHNAME', 'algoaddr_in'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_out(algoaddr) RETURNS cstring
    AS 'MODULE_PATHNAME', 'algoaddr_out'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_recv(internal) RETURNS algoaddr
    AS 'MODULE_PATHNAME', 'algoaddr_recv'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_send(algoaddr) RETURNS bytea
    AS 'MODULE_PATHNAME', 'algoaddr_send'
    LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE algoaddr (
    LIKE = bytea,
    INPUT = algoaddr_in,
    OUTPUT = algoaddr_out,
    RECEIVE = algoaddr_recv,
    SEND = algoaddr_send
);

CREATE CAST (bytea AS algoaddr) WITHOUT FUNCTION AS IMPLICIT;
CREATE CAST (algoaddr AS bytea) WITHOUT FUNCTION AS IMPLICIT;
