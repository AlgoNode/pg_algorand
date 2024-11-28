#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "algorand.h"

#include <stdint.h>
#include <string.h>

// SHA-512/256 initial hash values (first 32 bytes of SHA-512/256 IV)
static const uint64_t H[8] = {
    0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL,
    0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL,
    0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL
};

// SHA-512 round constants
static const uint64_t K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
    0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
    0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
    0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
    0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
    0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
    0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
    0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
    0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
    0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
    0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
    0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
    0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
    0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

// Rotation and shift macros
#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))

// SHA-512 functions
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SIGMA1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define sigma1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

// Process a single 1024-bit block
static void sha512_256_process_block(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t temp1, temp2;
    int t;

    // Prepare message schedule
    for (t = 0; t < 16; t++) {
        W[t] = ((uint64_t)block[t * 8] << 56)
             | ((uint64_t)block[t * 8 + 1] << 48)
             | ((uint64_t)block[t * 8 + 2] << 40)
             | ((uint64_t)block[t * 8 + 3] << 32)
             | ((uint64_t)block[t * 8 + 4] << 24)
             | ((uint64_t)block[t * 8 + 5] << 16)
             | ((uint64_t)block[t * 8 + 6] << 8)
             | ((uint64_t)block[t * 8 + 7]);
    }

    for (t = 16; t < 80; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Main loop
    for (t = 0; t < 80; t++) {
        temp1 = h + SIGMA1(e) + CH(e, f, g) + K[t] + W[t];
        temp2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha512_256_init(uint64_t state[8]) {
    memcpy(state, H, 8 * sizeof(uint64_t));
}

static void sha512_256_update(uint64_t state[8], const uint8_t *data, size_t len) {
    static uint8_t buffer[128];
    static size_t buffer_len = 0;
    static uint64_t total_len = 0;
    size_t remaining;

    total_len += len;

    // Process any remaining data from previous update
    if (buffer_len > 0) {
        remaining = 128 - buffer_len;
        if (len < remaining) {
            memcpy(buffer + buffer_len, data, len);
            buffer_len += len;
            return;
        }
        memcpy(buffer + buffer_len, data, remaining);
        sha512_256_process_block(state, buffer);
        data += remaining;
        len -= remaining;
        buffer_len = 0;
    }

    // Process full blocks
    while (len >= 128) {
        sha512_256_process_block(state, data);
        data += 128;
        len -= 128;
    }

    // Store remaining data in buffer
    if (len > 0) {
        memcpy(buffer, data, len);
        buffer_len = len;
    }
}

static void sha512_256_final(uint64_t state[8], uint8_t hash[32], const uint8_t *data, size_t len) {
    static uint8_t padding[128] = { 0x80 };  // First byte is 0x80, rest are 0x00
    uint64_t total_bits;

    // Process remaining data
    sha512_256_update(state, data, len);

    // Pad the message
    total_bits = len * 8;
    if (len % 128 < 112) {
        sha512_256_update(state, padding, 112 - (len % 128));
    } else {
        sha512_256_update(state, padding, 128 - (len % 128) + 112);
    }

    // Append length
    uint8_t length_bytes[16];
    for (int i = 15; i >= 0; i--) {
        length_bytes[i] = total_bits & 0xFF;
        total_bits >>= 8;
    }
    sha512_256_update(state, length_bytes, 16);

    // Output hash (first 32 bytes of state)
    for (int i = 0; i < 4; i++) {
        hash[i * 8] = (state[i] >> 56) & 0xFF;
        hash[i * 8 + 1] = (state[i] >> 48) & 0xFF;
        hash[i * 8 + 2] = (state[i] >> 40) & 0xFF;
        hash[i * 8 + 3] = (state[i] >> 32) & 0xFF;
        hash[i * 8 + 4] = (state[i] >> 24) & 0xFF;
        hash[i * 8 + 5] = (state[i] >> 16) & 0xFF;
        hash[i * 8 + 6] = (state[i] >> 8) & 0xFF;
        hash[i * 8 + 7] = state[i] & 0xFF;
    }
}

void pg_sha512_256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint64_t state[8];
    sha512_256_init(state);
    sha512_256_final(state, hash, data, len);
}

