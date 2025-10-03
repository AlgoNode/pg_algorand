-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_algorand" to load this file. \quit


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

CREATE OR REPLACE FUNCTION GetNFDSigNameLSIG(
    name text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigNameLSIG'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION GetNFDSigRevAddressLSIG(
    pointed_to_address text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigRevAddressLSIG'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION GetNFDSigRevAddressBinLSIG(
    pointed_to_address bytea,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'GetNFDSigRevAddressBinLSIG'
    LANGUAGE C STRICT IMMUTABLE;

-- Create the functions
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

-- Create the type with I/O functions
CREATE TYPE algoaddr (
    LIKE = bytea,
    INPUT = algoaddr_in,
    OUTPUT = algoaddr_out,
    RECEIVE = algoaddr_recv,
    SEND = algoaddr_send
);

-- -- Create the casts
CREATE CAST (bytea AS algoaddr) WITHOUT FUNCTION AS IMPLICIT;
CREATE CAST (algoaddr AS bytea) WITHOUT FUNCTION AS IMPLICIT;        

-- CREATE CAST (text AS algoaddr) WITH FUNCTION text_to_algoaddr(text) AS IMPLICIT;
-- CREATE CAST (algoaddr AS text) WITH FUNCTION algoaddr_to_text(algoaddr) AS IMPLICIT;
