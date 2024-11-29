-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_algorand" to load this file. \quit


CREATE OR REPLACE FUNCTION AddressTxt2Bin(
    address text
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'address_txt_2_bin'
    LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION AddressBin2Txt(
    address bytea
)
    RETURNS text
    AS 'MODULE_PATHNAME', 'address_bin_2_txt'
    LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION GetNFDSigNameLSIG(
    name text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'get_nfd_sig_name_lsig'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION GetNFDSigRevAddressLSIG(
    pointed_to_address text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'get_nfd_sig_rev_address_lsig'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION GetNFDSigRevAddressBinLSIG(
    pointed_to_address bytea,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'get_nfd_sig_rev_address_bin_lsig'
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
    INTERNALLENGTH = 32,
    INPUT = algoaddr_in,
    OUTPUT = algoaddr_out,
    RECEIVE = algoaddr_recv,
    SEND = algoaddr_send,
    ALIGNMENT = char,
    STORAGE = plain
);

-- Create the operator functions
CREATE FUNCTION algoaddr_eq(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_eq'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_ne(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_ne'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_lt(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_lt'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_le(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_le'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_gt(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_gt'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_ge(algoaddr, algoaddr) RETURNS boolean
    AS 'MODULE_PATHNAME', 'algoaddr_ge'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_cmp(algoaddr, algoaddr) RETURNS integer
    AS 'MODULE_PATHNAME', 'algoaddr_cmp'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION algoaddr_hash(algoaddr) RETURNS integer
    AS 'MODULE_PATHNAME', 'algoaddr_hash'
    LANGUAGE C IMMUTABLE STRICT;

-- Create the operators
CREATE OPERATOR = (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_eq,
    COMMUTATOR = =,
    NEGATOR = <>,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);

CREATE OPERATOR <> (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_ne,
    COMMUTATOR = <>,
    NEGATOR = =,
    RESTRICT = neqsel,
    JOIN = neqjoinsel
);

CREATE OPERATOR < (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_lt,
    COMMUTATOR = >,
    NEGATOR = >=,
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_le,
    COMMUTATOR = >=,
    NEGATOR = >,
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_gt,
    COMMUTATOR = <,
    NEGATOR = <=,
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
    LEFTARG = algoaddr,
    RIGHTARG = algoaddr,
    PROCEDURE = algoaddr_ge,
    COMMUTATOR = <=,
    NEGATOR = <,
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

-- Create the operator class for btree index support
CREATE OPERATOR CLASS algoaddr_ops
    DEFAULT FOR TYPE algoaddr USING btree AS
        OPERATOR        1       < ,
        OPERATOR        2       <= ,
        OPERATOR        3       = ,
        OPERATOR        4       >= ,
        OPERATOR        5       > ,
        FUNCTION        1       algoaddr_cmp(algoaddr, algoaddr);

-- Create hash operator class
CREATE OPERATOR CLASS algoaddr_hash_ops
    DEFAULT FOR TYPE algoaddr USING hash AS
        OPERATOR        1       = ,
        FUNCTION        1       algoaddr_hash(algoaddr);