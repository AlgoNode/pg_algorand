#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"
#include "access/hash.h"
#include "sha512_256.h"

#define ALGO_ADDR_SIZE 32

typedef struct AlgoAddr
{
    uint8_t data[ALGO_ADDR_SIZE];
} AlgoAddr;

// Function declarations
PG_FUNCTION_INFO_V1(algoaddr_in);
PG_FUNCTION_INFO_V1(algoaddr_out);
PG_FUNCTION_INFO_V1(algoaddr_recv);
PG_FUNCTION_INFO_V1(algoaddr_send);
PG_FUNCTION_INFO_V1(algoaddr_eq);
PG_FUNCTION_INFO_V1(algoaddr_ne);
PG_FUNCTION_INFO_V1(algoaddr_lt);
PG_FUNCTION_INFO_V1(algoaddr_le);
PG_FUNCTION_INFO_V1(algoaddr_gt);
PG_FUNCTION_INFO_V1(algoaddr_ge);
PG_FUNCTION_INFO_V1(algoaddr_cmp);
PG_FUNCTION_INFO_V1(algoaddr_hash);

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
            bits_in_buffer -= 5;
            output[output_len++] = BASE32_ALPHABET[(buffer >> bits_in_buffer) & 0x1F];
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
    
    // Allocate result
    AlgoAddr *result = (AlgoAddr *) palloc(sizeof(AlgoAddr));
    
    // Copy only the first 32 bytes (excluding checksum)
    memcpy(result->data, temp_bytes, ALGO_ADDR_SIZE);
    
    PG_RETURN_POINTER(result);
}

// Output function
Datum
algoaddr_out(PG_FUNCTION_ARGS)
{
    AlgoAddr *addr = (AlgoAddr *) PG_GETARG_POINTER(0);
    // Need space for base32 encoding of 32 bytes plus checksum (36 bytes total)
    char *result = palloc(60); // Safe size for base32 encoding of 36 bytes
    
    uint8_t checksum[32];
    uint8 temp_bytes[36];
    // Copy address data
    memcpy(temp_bytes, addr->data, ALGO_ADDR_SIZE);
    
    // Calculate SHA512/256 of the public key
    pg_sha512_256(addr->data, 32, checksum);

    // Append last 4 bytes of checksum to addr_data
    memcpy(temp_bytes + ALGO_ADDR_SIZE, checksum + 28, 4);
    
    base32_encode(temp_bytes, 36, result);
    
    PG_RETURN_CSTRING(result);
}

// Binary input function
Datum
algoaddr_recv(PG_FUNCTION_ARGS)
{
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
    
    if (buf->len - buf->cursor != ALGO_ADDR_SIZE)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
                 errmsg("invalid address length in binary format")));
    
    AlgoAddr *result = (AlgoAddr *) palloc(sizeof(AlgoAddr));
    memcpy(result->data, &buf->data[buf->cursor], ALGO_ADDR_SIZE);
    buf->cursor += ALGO_ADDR_SIZE;
    
    PG_RETURN_POINTER(result);
}

// Binary output function
Datum
algoaddr_send(PG_FUNCTION_ARGS)
{
    AlgoAddr *addr = (AlgoAddr *) PG_GETARG_POINTER(0);
    StringInfoData buf;
    
    pq_begintypsend(&buf);
    pq_sendbytes(&buf, addr->data, ALGO_ADDR_SIZE);
    
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

// Equality operator
Datum
algoaddr_eq(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) == 0);
}

// Inequality operator
Datum
algoaddr_ne(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) != 0);
}

// Less than operator
Datum
algoaddr_lt(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) < 0);
}

// Less than or equal operator
Datum
algoaddr_le(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) <= 0);
}

// Greater than operator
Datum
algoaddr_gt(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) > 0);
}

// Greater than or equal operator
Datum
algoaddr_ge(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    PG_RETURN_BOOL(memcmp(a->data, b->data, ALGO_ADDR_SIZE) >= 0);
}

// Comparison function
Datum
algoaddr_cmp(PG_FUNCTION_ARGS)
{
    AlgoAddr *a = (AlgoAddr *) PG_GETARG_POINTER(0);
    AlgoAddr *b = (AlgoAddr *) PG_GETARG_POINTER(1);
    
    return memcmp(a->data, b->data, ALGO_ADDR_SIZE);
}

// Hash function
Datum
algoaddr_hash(PG_FUNCTION_ARGS)
{
    AlgoAddr *addr = (AlgoAddr *) PG_GETARG_POINTER(0);
    return hash_any((unsigned char *)addr->data, ALGO_ADDR_SIZE);
}