#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"



void pg_sha512_256(const uint8_t *data, size_t len, uint8_t hash[32]);


