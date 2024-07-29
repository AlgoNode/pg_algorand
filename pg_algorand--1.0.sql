-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_algorand" to load this file. \quit

CREATE OR REPLACE FUNCTION address_txt_2_bin(
    address text
)
    RETURNS bytea
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION address_bin_2_txt(
    address bytea
)
    RETURNS text
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION get_nfd_sig_name_lsig(
    name text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION get_nfd_sig_rev_address_lsig(
    pointed_to_address text,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION get_nfd_sig_rev_address_bin_lsig(
    pointed_to_address bytea,
    registry_app_id int8
)
    RETURNS bytea
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;