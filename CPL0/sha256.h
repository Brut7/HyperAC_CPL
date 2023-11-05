// https://opensource.apple.com/source/clamav/clamav-158/clamav.Bin/clamav-0.98/libclamav/sha256.h.auto.html

#ifndef H_SHA256
#define H_SHA256

#include <stdint.h>

#define SHA256_HASH_SIZE 32
#define SHA256_HASH_WORDS 8

struct _SHA256Context {
    uint64_t totalLength;
    uint32_t hash[SHA256_HASH_WORDS];
    uint32_t bufferLength;
    union {
        uint32_t words[16];
        uint8_t bytes[64];
    } buffer;
};

typedef struct _SHA256Context SHA256_CTX;

void sha256_init(SHA256_CTX* sc);
void sha256_update(SHA256_CTX* sc, const void* data, uint32_t len);
void sha256_final(SHA256_CTX* sc, uint8_t hash[SHA256_HASH_SIZE]);

#endif // H_SHA256
