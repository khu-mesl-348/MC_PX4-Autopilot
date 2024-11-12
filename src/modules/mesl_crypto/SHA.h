#ifndef __SHA__
#define __SHA__

//#include <Arduino.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define FINAL 1
#define UPDATE 0

typedef struct {
    uint8_t data[64];
    uint8_t last_data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    unsigned long long last_bitlen;
    uint32_t state[8];
    uint32_t backup_state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX* ctx, uint8_t hash[]);

#endif
