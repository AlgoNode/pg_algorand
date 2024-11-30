#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "libpq/pqformat.h"
#include "access/hash.h"
#include "utils/varlena.h"
#include "sha512_256.h"

#define ALGO_ADDR_SIZE 32

// Function declarations
PG_FUNCTION_INFO_V1(algoaddr_in);
PG_FUNCTION_INFO_V1(algoaddr_out);
PG_FUNCTION_INFO_V1(algoaddr_recv);
PG_FUNCTION_INFO_V1(algoaddr_send);

// Algorand Base32 alphabet
static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const int8 BASE32_DECODE_MAP[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1
};

// Base32 decode function
static int base32_decode(const char *input, int input_len, uint8 *output)
{
    int buffer = 0;
    int bits_in_buffer = 0;
    int output_len = 0;

    for (int i = 0; i < input_len; i++)
    {
        int val = BASE32_DECODE_MAP[(uint8)input[i]];
        if (val == -1)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                     errmsg("invalid base32 character: %c", input[i])));

        buffer = (buffer << 5) | val;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8)
        {
            output[output_len++] = (buffer >> (bits_in_buffer - 8)) & 0xFF;
            bits_in_buffer -= 8;
        }
    }

    return output_len;
}

// Base32 encode function
static int base32_encode(const uint8 *input, int input_len, char *output)
{
    int buffer = 0;
    int bits_in_buffer = 0;
    int output_len = 0;

    for (int i = 0; i < input_len; i++)
    {
        buffer = (buffer << 8) | input[i];
        bits_in_buffer += 8;

        while (bits_in_buffer >= 5)
        {
            output[output_len++] = BASE32_ALPHABET[(buffer >> (bits_in_buffer - 5)) & 0x1F];
            bits_in_buffer -= 5;
        }
    }

    if (bits_in_buffer > 0)
    {
        buffer <<= (5 - bits_in_buffer);
        output[output_len++] = BASE32_ALPHABET[buffer & 0x1F];
    }

    output[output_len] = '\0';
    return output_len;
}

// Input function
Datum
algoaddr_in(PG_FUNCTION_ARGS)
{
    char *str = PG_GETARG_CSTRING(0);
    int str_len = strlen(str);
    
    // Check for exact input length (58 chars for 36 bytes in base32)
    if (str_len != 58)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid address length: expected 58 characters, got %d", str_len)));
    
    // Allocate space for full decoded data including checksum
    uint8 temp_bytes[36];
    
    int byte_len = base32_decode(str, str_len, temp_bytes);
    
    // Verify decoded length
    if (byte_len != 36)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid decoded length: expected 36 bytes, got %d", byte_len)));
    
    // Create bytea with only first 32 bytes (excluding checksum)
    bytea *result = (bytea *) palloc(VARHDRSZ + ALGO_ADDR_SIZE);
    SET_VARSIZE(result, VARHDRSZ + ALGO_ADDR_SIZE);
    memcpy(VARDATA(result), temp_bytes, ALGO_ADDR_SIZE);
    
    PG_RETURN_BYTEA_P(result);
}

// Output function
Datum
algoaddr_out(PG_FUNCTION_ARGS)
{
    bytea *addr = PG_GETARG_BYTEA_PP(0);
    int addr_len = VARSIZE_ANY_EXHDR(addr);
    
    if (addr_len != ALGO_ADDR_SIZE)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid internal address length: expected %d bytes, got %d",
                        ALGO_ADDR_SIZE, addr_len)));
    
    uint8_t checksum[32];
    uint8 temp_bytes[36];
    // Copy address data
    memcpy(temp_bytes, VARDATA_ANY(addr), ALGO_ADDR_SIZE);
    
    // Calculate SHA512/256 of the public key
    pg_sha512_256((uint8_t*)VARDATA_ANY(addr), 32, checksum);
    memcpy(temp_bytes + ALGO_ADDR_SIZE, checksum + 28, 4);
    
    // Need space for base32 encoding of 36 bytes
    char *result = palloc(60);
    base32_encode(temp_bytes, 36, result);
    
    PG_RETURN_CSTRING(result);
}

// Binary input function
Datum
algoaddr_recv(PG_FUNCTION_ARGS)
{
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
    int nbytes = buf->len - buf->cursor;
    
    if (nbytes != ALGO_ADDR_SIZE)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
                 errmsg("invalid address length in binary format")));
    
    bytea *result = (bytea *) palloc(VARHDRSZ + ALGO_ADDR_SIZE);
    SET_VARSIZE(result, VARHDRSZ + ALGO_ADDR_SIZE);
    memcpy(VARDATA(result), &buf->data[buf->cursor], ALGO_ADDR_SIZE);
    buf->cursor += ALGO_ADDR_SIZE;
    
    PG_RETURN_BYTEA_P(result);
}

// Binary output function
Datum
algoaddr_send(PG_FUNCTION_ARGS)
{
    bytea *addr = PG_GETARG_BYTEA_PP(0);
    StringInfoData buf;
    
    if (VARSIZE_ANY_EXHDR(addr) != ALGO_ADDR_SIZE)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid internal address length")));
    
    pq_begintypsend(&buf);
    pq_sendbytes(&buf, VARDATA_ANY(addr), ALGO_ADDR_SIZE);
    
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

