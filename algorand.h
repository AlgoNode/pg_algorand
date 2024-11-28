#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

// Base32 alphabet used by Algorand (RFC 4648 with lowercase)

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void pg_sha512_256(const uint8_t *data, size_t len, uint8_t hash[32]);


