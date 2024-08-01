#include "functions.h"

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

	// get the bytea value from function args
	bytea *address = PG_GETARG_BYTEA_PP(0);

	int32 address_size = VARSIZE_ANY_EXHDR(address);
	if (address_size != 32) {
		elog_error("binary address must be 32 bytes long");
	}

	// allocate a char array for the result address
	unsigned char buf[59];

	// call the cgo implementation of this function
	AddressBin2Txt((unsigned char*)VARDATA(address), buf);

	// set the text-type return value
	int32 text_size = 58 + VARHDRSZ;
	text *new_text = (text*) palloc(text_size);
	SET_VARSIZE(new_text, text_size);
	memcpy(VARDATA(new_text), buf, 58);
	PG_RETURN_TEXT_P(new_text);
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