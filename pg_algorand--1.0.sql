-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_algorand" to load this file. \quit

CREATE OR REPLACE FUNCTION AddressTxt2Bin(
    address text
)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'address_txt_2_bin'
    LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION AddressBin2Txt(
    address bytea
)
    RETURNS text
    AS 'MODULE_PATHNAME', 'address_bin_2_txt'
    LANGUAGE C STRICT IMMUTABLE;

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