#ifndef NFD_LSIG_H
#define NFD_LSIG_H

#include <stdint.h>
#include <stddef.h>

// from sha512_256.c
void pg_sha512_256(const uint8_t *data, size_t len, uint8_t hash[32]);

#define ALGORAND_ADDRESS_BIN_LEN 32
#define ALGORAND_ADDRESS_TXT_LEN 58

// Encode a 32-byte public key as a 58-character Algorand address
// (base32 of pubkey || 4-byte sha512/256 checksum). No NUL terminator.
void algorand_address_encode(const uint8_t *pubkey, char *out);

// Maximum size of the "Program" || bytecode buffer composed by
// nfd_lookup_program_to_sign for a given prefix+lookup data length:
// 7 ("Program") + 47 (bytecode template) + up to 10 (uvarint length).
#define NFD_LSIG_TOSIGN_MAX(data_len) (7 + 47 + 10 + (data_len))

// Compose the byte string whose sha512/256 is the escrow address of the
// NFD lookup LogicSig:
//   "Program" || bytecode(registry_app_id) || uvarint(prefix_len + lookup_len)
//             || prefix || lookup
// buf must have room for NFD_LSIG_TOSIGN_MAX(prefix_len + lookup_len) bytes.
// Returns the number of bytes written.
size_t nfd_lookup_program_to_sign(uint8_t *buf,
                                  const char *prefix, size_t prefix_len,
                                  const char *lookup, size_t lookup_len,
                                  uint64_t registry_app_id);

#endif
