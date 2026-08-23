// NFD lookup LogicSig address computation, ported to plain C from the
// cgo/go-algorand-sdk implementation so the extension carries no Go runtime.
//
// The escrow address of a LogicSig is sha512/256("Program" || bytecode);
// the NFD lookup bytecode is a fixed TEAL template with the registry app id
// patched in, followed by uvarint-length-prefixed lookup data.

#include <string.h>

#include "nfd_lsig.h"

// NFD sig lookup TEAL bytecode template.
// Bytes [6..14) are a placeholder for the registry app id (big-endian uint64).
static const uint8_t nfd_sig_lookup_bytecode[47] = {
    0x05, 0x20, 0x01, 0x01, 0x80, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x17, 0x35, 0x00, 0x31, 0x18, 0x34, 0x00, 0x12, 0x31, 0x10,
    0x81, 0x06, 0x12, 0x10, 0x31, 0x19, 0x22, 0x12, 0x31, 0x19, 0x81, 0x00,
    0x12, 0x11, 0x10, 0x40, 0x00, 0x01, 0x00, 0x22, 0x43, 0x26, 0x01
};

#define NFD_REGISTRY_APP_ID_OFFSET 6

// Base32 alphabet used by Algorand
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void
algorand_address_encode(const uint8_t *pubkey, char *out)
{
    uint8_t checksum[32];
    uint8_t addr_data[36]; // 32 bytes public key + 4 bytes checksum

    memcpy(addr_data, pubkey, 32);

    // Checksum is the last 4 bytes of sha512/256 of the public key
    pg_sha512_256(addr_data, 32, checksum);
    memcpy(addr_data + 32, checksum + 28, 4);

    // Base32-encode: 36 bytes = 288 bits -> 58 characters
    int i, j = 0;
    uint64_t buffer = 0;
    int bits_in_buffer = 0;

    for (i = 0; i < 36; i++) {
        buffer = (buffer << 8) | addr_data[i];
        bits_in_buffer += 8;

        while (bits_in_buffer >= 5) {
            bits_in_buffer -= 5;
            out[j++] = base32_alphabet[(buffer >> bits_in_buffer) & 0x1F];
        }
    }

    // Handle remaining bits
    if (bits_in_buffer > 0) {
        buffer <<= (5 - bits_in_buffer);
        out[j++] = base32_alphabet[buffer & 0x1F];
    }
}

// Same encoding as Go's encoding/binary.PutUvarint: little-endian base-128
// with a continuation bit. Returns the number of bytes written (max 10).
static size_t
put_uvarint(uint8_t *buf, uint64_t v)
{
    size_t n = 0;

    while (v >= 0x80) {
        buf[n++] = (uint8_t) v | 0x80;
        v >>= 7;
    }
    buf[n++] = (uint8_t) v;
    return n;
}

size_t
nfd_lookup_program_to_sign(uint8_t *buf,
                           const char *prefix, size_t prefix_len,
                           const char *lookup, size_t lookup_len,
                           uint64_t registry_app_id)
{
    size_t off = 0;
    uint8_t *bytecode;
    int i;

    memcpy(buf + off, "Program", 7);
    off += 7;

    // Bytecode template with the registry app id patched in (big-endian)
    bytecode = buf + off;
    memcpy(bytecode, nfd_sig_lookup_bytecode, sizeof(nfd_sig_lookup_bytecode));
    for (i = 0; i < 8; i++)
        bytecode[NFD_REGISTRY_APP_ID_OFFSET + i] =
            (uint8_t) (registry_app_id >> (8 * (7 - i)));
    off += sizeof(nfd_sig_lookup_bytecode);

    // uvarint length prefix followed by the lookup data
    off += put_uvarint(buf + off, (uint64_t) (prefix_len + lookup_len));
    memcpy(buf + off, prefix, prefix_len);
    off += prefix_len;
    memcpy(buf + off, lookup, lookup_len);
    off += lookup_len;

    return off;
}
