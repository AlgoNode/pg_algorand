#include "functions.h"
#include "algorand.h"

PG_MODULE_MAGIC;

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(address_txt_2_bin);

Datum
address_txt_2_bin(PG_FUNCTION_ARGS) {

	// get the C-string from function args
	text *address = PG_GETARG_TEXT_PP(0);
	int32 text_size = VARSIZE_ANY_EXHDR(address);
	// copy it into a zero-terminated buffer
	char *buf = (char*)palloc(text_size+1);
	memcpy(buf, VARDATA_ANY(address), text_size);
	buf[text_size] = 0;

	// call the cgo implementation of this function
	unsigned char out[32];
	AddressTxt2Bin(buf, out);

	// set the bytea-type return value
	int32 bytea_size = 32 + VARHDRSZ;
	bytea *new_bytea = (bytea*) palloc(bytea_size);
	SET_VARSIZE(new_bytea, bytea_size);
	memcpy(VARDATA(new_bytea), out, 32);
	PG_RETURN_BYTEA_P(new_bytea);
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(address_bin_2_txt);

Datum
address_bin_2_txt(PG_FUNCTION_ARGS) {
    bytea *input = PG_GETARG_BYTEA_PP(0);
    uint8_t *pubkey = (uint8_t *) VARDATA_ANY(input);
    int input_len = VARSIZE_ANY_EXHDR(input);
    
    // Validate input length (must be 32 bytes)
    if (input_len != 32) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("input must be exactly 32 bytes")));
    }
    
    // Calculate checksum (SHA512/256 truncated to 4 bytes)
    uint8_t checksum[32];
    uint8_t addr_data[36]; // 32 bytes public key + 4 bytes checksum
    
    // Copy public key to addr_data
    memcpy(addr_data, pubkey, 32);
    
    // Calculate SHA512/256 of the public key
    pg_sha512_256(addr_data, 32, checksum);
    
    // Append last 4 bytes of checksum to addr_data
    memcpy(addr_data + 32, checksum + 28, 4);
    
    // Encode in base32
    // Each 5 bits becomes one base32 character
    // 36 bytes * 8 = 288 bits
    // 288 bits / 5 = 58 characters (with padding)
    text *output = (text *) palloc(VARHDRSZ + 59); // 58 chars + null terminator
    char *result = VARDATA(output);
    
    int i, j = 0;
    uint64_t buffer = 0;
    int bits_in_buffer = 0;
    
    for (i = 0; i < 36; i++) {
        buffer = (buffer << 8) | addr_data[i];
        bits_in_buffer += 8;
        
        while (bits_in_buffer >= 5) {
            bits_in_buffer -= 5;
            result[j++] = base32_alphabet[(buffer >> bits_in_buffer) & 0x1F];
        }
    }
    
    // Handle remaining bits
    if (bits_in_buffer > 0) {
        buffer <<= (5 - bits_in_buffer);
        result[j++] = base32_alphabet[buffer & 0x1F];
    }
    
    result[j] = '\0';
    SET_VARSIZE(output, VARHDRSZ + j);
    
    PG_RETURN_TEXT_P(output);
}


///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(get_nfd_sig_name_lsig);

Datum
get_nfd_sig_name_lsig(PG_FUNCTION_ARGS) {

	// get the C-string from function args
	text *name = PG_GETARG_TEXT_PP(0);
	int32 text_size = VARSIZE_ANY_EXHDR(name);
	// copy it into a zero-terminated buffer
	char *buf = (char*)palloc(text_size+1);
	memcpy(buf, VARDATA_ANY(name), text_size);
	buf[text_size] = 0;

	// get the int64 param from function args
	int64 registry_app_id = PG_GETARG_INT64(1);

	// call the cgo implementation of this function
	unsigned char address[32];
	GetNFDSigNameLSIG(buf, registry_app_id, address);

	// set the bytea-type return value
	int32 bytea_size = 32 + VARHDRSZ;
	bytea *new_bytea = (bytea*) palloc(bytea_size);
	SET_VARSIZE(new_bytea, bytea_size);
	memcpy(VARDATA(new_bytea), address, 32);
	PG_RETURN_BYTEA_P(new_bytea);
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(get_nfd_sig_rev_address_lsig);

Datum
get_nfd_sig_rev_address_lsig(PG_FUNCTION_ARGS) {

	// get the C-string from function args
	text *name = PG_GETARG_TEXT_PP(0);
	int32 text_size = VARSIZE_ANY_EXHDR(name);
	// copy it into a zero-terminated buffer
	char *buf = (char*)palloc(text_size+1);
	memcpy(buf, VARDATA_ANY(name), text_size);
	buf[text_size] = 0;

	// get the int64 param from function args
	int64 registry_app_id = PG_GETARG_INT64(1);

	// call the cgo implementation of this function
	unsigned char address[32];
	GetNFDSigRevAddressLSIG(buf, registry_app_id, address);

	// set the bytea-type return value
	int32 bytea_size = 32 + VARHDRSZ;
	bytea *new_bytea = (bytea*) palloc(bytea_size);
	SET_VARSIZE(new_bytea, bytea_size);
	memcpy(VARDATA(new_bytea), address, 32);
	PG_RETURN_BYTEA_P(new_bytea);
}

///////////////////////////////////////////////////////////////////////////////

PG_FUNCTION_INFO_V1(get_nfd_sig_rev_address_bin_lsig);

Datum
get_nfd_sig_rev_address_bin_lsig(PG_FUNCTION_ARGS) {

	// get the bytea value from function args
	bytea *address = PG_GETARG_BYTEA_PP(0);

	int32 address_size = VARSIZE_ANY_EXHDR(address);
	if (address_size != 32) {
		elog_error("binary address must be 32 bytes long");
	}

	// get the int64 param from function args
	int64 registry_app_id = PG_GETARG_INT64(1);

	// call the cgo implementation of this function
	unsigned char output[32];
	GetNFDSigRevAddressBinLSIG((unsigned char*)(VARDATA(address)), registry_app_id, output);

	// set the bytea-type return value
	int32 bytea_size = 32 + VARHDRSZ;
	bytea *new_bytea = (bytea*) palloc(bytea_size);
	SET_VARSIZE(new_bytea, bytea_size);
	memcpy(VARDATA(new_bytea), output, 32);
	PG_RETURN_BYTEA_P(new_bytea);
}

///////////////////////////////////////////////////////////////////////////////

void elog_notice(char* string) {
    elog(NOTICE, string, "");
}

void elog_error(char* string) {
    elog(ERROR, string, "");
}