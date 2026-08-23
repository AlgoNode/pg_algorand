#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "sha512_256.h"
#include "nfd_lsig.h"

PG_MODULE_MAGIC;

///////////////////////////////////////////////////////////////////////////////

static const int8 base32_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0-15
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 16-31
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 32-47
    -1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1, // 48-63
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 64-79
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 80-95
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 96-111
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1  // 112-127
};

PG_FUNCTION_INFO_V1(AddressTxt2Bin);

Datum
AddressTxt2Bin(PG_FUNCTION_ARGS)
{
    text *input = PG_GETARG_TEXT_PP(0);
    char *str = VARDATA_ANY(input);
    int str_len = VARSIZE_ANY_EXHDR(input);

    // Remove padding chars
    while (str_len > 0 && str[str_len - 1] == '=')
        str_len--;

    // Calculate output length (before truncation)
    int output_len = (str_len * 5) / 8;

    // Allocate output buffer
    bytea *result = (bytea *) palloc(VARHDRSZ + output_len);
    unsigned char *out = (unsigned char *) VARDATA(result);

    int buffer = 0;
    int bits_left = 0;
    int out_index = 0;

    // Decode base32
    for (int i = 0; i < str_len; i++) {
        unsigned char c = str[i];
        if (c >= sizeof(base32_decode_table) || base32_decode_table[c] == -1)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("invalid base32 character")));

        buffer = (buffer << 5) | base32_decode_table[c];
        bits_left += 5;

        if (bits_left >= 8) {
            if (out_index < output_len) {
                out[out_index++] = (buffer >> (bits_left - 8)) & 0xFF;
            }
            bits_left -= 8;
        }
    }

    // Truncate last 4 bytes
    output_len -= 4;

    // Check final length
    if (output_len != 32)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("decoded length must be exactly 32 bytes (got %d bytes)", output_len)));

    SET_VARSIZE(result, VARHDRSZ + output_len);
    PG_RETURN_BYTEA_P(result);
}


///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(AddressBin2Txt);

Datum
AddressBin2Txt(PG_FUNCTION_ARGS) {
    bytea *input = PG_GETARG_BYTEA_PP(0);
    uint8_t *pubkey = (uint8_t *) VARDATA_ANY(input);
    int input_len = VARSIZE_ANY_EXHDR(input);

    // Validate input length (must be 32 bytes)
    if (input_len != 32) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("input must be exactly 32 bytes")));
    }

    // Encode as base32 with checksum: 58 characters
    text *output = (text *) palloc(VARHDRSZ + ALGORAND_ADDRESS_TXT_LEN);
    algorand_address_encode(pubkey, VARDATA(output));
    SET_VARSIZE(output, VARHDRSZ + ALGORAND_ADDRESS_TXT_LEN);

    PG_RETURN_TEXT_P(output);
}



///////////////////////////////////////////////////////////////////////////////

// Compute the escrow address of the NFD lookup LogicSig for the given
// prefix + lookup data and registry app id, as a 32-byte bytea.
static bytea *
nfd_lookup_lsig_address(const char *prefix, size_t prefix_len,
                        const char *lookup, size_t lookup_len,
                        int64 registry_app_id)
{
    uint8_t *buf = (uint8_t *) palloc(NFD_LSIG_TOSIGN_MAX(prefix_len + lookup_len));
    size_t buf_len = nfd_lookup_program_to_sign(buf, prefix, prefix_len,
                                                lookup, lookup_len,
                                                (uint64_t) registry_app_id);

    // The address is sha512/256("Program" || bytecode)
    int32 bytea_size = ALGORAND_ADDRESS_BIN_LEN + VARHDRSZ;
    bytea *new_bytea = (bytea *) palloc(bytea_size);
    SET_VARSIZE(new_bytea, bytea_size);
    pg_sha512_256(buf, buf_len, (uint8_t *) VARDATA(new_bytea));

    pfree(buf);
    return new_bytea;
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(GetNFDSigNameLSIG);

Datum
GetNFDSigNameLSIG(PG_FUNCTION_ARGS) {

	// get the text and int64 params from function args
	text *name = PG_GETARG_TEXT_PP(0);
	int64 registry_app_id = PG_GETARG_INT64(1);

	PG_RETURN_BYTEA_P(nfd_lookup_lsig_address("name/", 5,
	                                          VARDATA_ANY(name),
	                                          VARSIZE_ANY_EXHDR(name),
	                                          registry_app_id));
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(GetNFDSigRevAddressLSIG);

Datum
GetNFDSigRevAddressLSIG(PG_FUNCTION_ARGS) {

	// get the text and int64 params from function args
	text *address = PG_GETARG_TEXT_PP(0);
	int64 registry_app_id = PG_GETARG_INT64(1);

	PG_RETURN_BYTEA_P(nfd_lookup_lsig_address("address/", 8,
	                                          VARDATA_ANY(address),
	                                          VARSIZE_ANY_EXHDR(address),
	                                          registry_app_id));
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(GetNFDSigRevAddressBinLSIG);

Datum
GetNFDSigRevAddressBinLSIG(PG_FUNCTION_ARGS) {

	// get the bytea value from function args
	bytea *address = PG_GETARG_BYTEA_PP(0);

	int32 address_size = VARSIZE_ANY_EXHDR(address);
	if (address_size != 32) {
		ereport(ERROR,
		        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
		         errmsg("binary address must be 32 bytes long")));
	}

	// get the int64 param from function args
	int64 registry_app_id = PG_GETARG_INT64(1);

	// the lookup key is the textual form of the address
	char address_txt[ALGORAND_ADDRESS_TXT_LEN];
	algorand_address_encode((uint8_t *) VARDATA_ANY(address), address_txt);

	PG_RETURN_BYTEA_P(nfd_lookup_lsig_address("address/", 8,
	                                          address_txt,
	                                          ALGORAND_ADDRESS_TXT_LEN,
	                                          registry_app_id));
}

////////////////////// FAKE
PG_FUNCTION_INFO_V1(TxnBin2Txt);

Datum
TxnBin2Txt(PG_FUNCTION_ARGS) {
    bytea *input = PG_GETARG_BYTEA_PP(0);
    uint8_t *pubkey = (uint8_t *) VARDATA_ANY(input);
    int input_len = VARSIZE_ANY_EXHDR(input);

    // Validate input length (must be 32 bytes)
    if (input_len != 32) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("input must be exactly 32 bytes")));
    }

    // Encode as base32 with checksum: 58 characters
    text *output = (text *) palloc(VARHDRSZ + ALGORAND_ADDRESS_TXT_LEN);
    algorand_address_encode(pubkey, VARDATA(output));
    SET_VARSIZE(output, VARHDRSZ + ALGORAND_ADDRESS_TXT_LEN);

    PG_RETURN_TEXT_P(output);
}

PG_FUNCTION_INFO_V1(TxnTxt2Bin);

Datum
TxnTxt2Bin(PG_FUNCTION_ARGS)
{
    text *input = PG_GETARG_TEXT_PP(0);
    char *str = VARDATA_ANY(input);
    int str_len = VARSIZE_ANY_EXHDR(input);

    // Remove padding chars
    while (str_len > 0 && str[str_len - 1] == '=')
        str_len--;

    // Calculate output length (before truncation)
    int output_len = (str_len * 5) / 8;

    // Allocate output buffer
    bytea *result = (bytea *) palloc(VARHDRSZ + output_len);
    unsigned char *out = (unsigned char *) VARDATA(result);

    int buffer = 0;
    int bits_left = 0;
    int out_index = 0;

    // Decode base32
    for (int i = 0; i < str_len; i++) {
        unsigned char c = str[i];
        if (c >= sizeof(base32_decode_table) || base32_decode_table[c] == -1)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("invalid base32 character")));

        buffer = (buffer << 5) | base32_decode_table[c];
        bits_left += 5;

        if (bits_left >= 8) {
            if (out_index < output_len) {
                out[out_index++] = (buffer >> (bits_left - 8)) & 0xFF;
            }
            bits_left -= 8;
        }
    }

    // Truncate last 4 bytes
    output_len -= 4;

    // Check final length
    if (output_len != 32)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("decoded length must be exactly 32 bytes (got %d bytes)", output_len)));

    SET_VARSIZE(result, VARHDRSZ + output_len);
    PG_RETURN_BYTEA_P(result);
}
