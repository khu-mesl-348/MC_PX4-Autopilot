#include "SHA.h"

uint8_t hex[256];
//uint8_t data[256];
int start = 0;
int seconds = 0;
//uint8_t hash[32];
char* pin;
#define SHA256_BLOCK_SIZE 32

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX* ctx, const uint8_t data[], size_t check) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    
    if(check == UPDATE) {
        ctx->state[0] = ctx->backup_state[0];
        ctx->state[1] = ctx->backup_state[1];
        ctx->state[2] = ctx->backup_state[2];
        ctx->state[3] = ctx->backup_state[3];
        ctx->state[4] = ctx->backup_state[4];
        ctx->state[5] = ctx->backup_state[5];
        ctx->state[6] = ctx->backup_state[6];
        ctx->state[7] = ctx->backup_state[7];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    if(check == UPDATE) {
        ctx->backup_state[0] = ctx->state[0];
        ctx->backup_state[1] = ctx->state[1];
        ctx->backup_state[2] = ctx->state[2];
        ctx->backup_state[3] = ctx->state[3];
        ctx->backup_state[4] = ctx->state[4];
        ctx->backup_state[5] = ctx->state[5];
        ctx->backup_state[6] = ctx->state[6];
        ctx->backup_state[7] = ctx->state[7];
    }
}

void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->last_bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    ctx->backup_state[0] = 0x6a09e667;
    ctx->backup_state[1] = 0xbb67ae85;
    ctx->backup_state[2] = 0x3c6ef372;
    ctx->backup_state[3] = 0xa54ff53a;
    ctx->backup_state[4] = 0x510e527f;
    ctx->backup_state[5] = 0x9b05688c;
    ctx->backup_state[6] = 0x1f83d9ab;
    ctx->backup_state[7] = 0x5be0cd19;
}


void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len) {
    uint32_t i;

    //if(ctx->last_datalen != 0)
    //    ctx->datalen = ctx->last_datalen;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data, UPDATE);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }

    //ctx->last_datalen = 0;
}

void sha256_final(SHA256_CTX* ctx, uint8_t hash[]) {
    uint32_t i;

    i = ctx->datalen;
    ctx->last_bitlen = ctx->bitlen;
    memcpy(ctx->last_data, ctx->data, 64);

    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        ctx->last_data[i++] = 0x80;
        while (i < 56)
            ctx->last_data[i++] = 0x00;
    }
    else {
        ctx->last_data[i++] = 0x80;
        while (i < 64)
            ctx->last_data[i++] = 0x00;
        sha256_transform(ctx, ctx->last_data, FINAL);
        memset(ctx->last_data, 0, 56);
    }

    // Append to the padding the total message's length in bits and transform.
    ctx->last_bitlen += ctx->datalen * 8;
    ctx->last_data[63] = ctx->last_bitlen;
    ctx->last_data[62] = ctx->last_bitlen >> 8;
    ctx->last_data[61] = ctx->last_bitlen >> 16;
    ctx->last_data[60] = ctx->last_bitlen >> 24;
    ctx->last_data[59] = ctx->last_bitlen >> 32;
    ctx->last_data[58] = ctx->last_bitlen >> 40;
    ctx->last_data[57] = ctx->last_bitlen >> 48;
    ctx->last_data[56] = ctx->last_bitlen >> 56;
    sha256_transform(ctx, ctx->last_data, FINAL);

    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }

    for(int j = 0; j< 32; j++)
       printf("%02x ", hash[j]);
    printf("\n");
}

uint8_t* btoh(uint8_t* dest, uint8_t* src, int len) {
    uint8_t* d = dest;
    // while (len--) sprintf(d, "%02x", (unsigned char)*src++), d += 2;
    while (len--) printf((char*)d, "%02x", (uint8_t)*src++), d += 2;
    return dest;
}

uint8_t* SHA256(uint8_t* data) {

    uint8_t hash[32];

    uint8_t* data_buffer = (uint8_t*)malloc(sizeof(uint8_t) * strlen((char *)data));

    memmove(data_buffer, data, sizeof(uint8_t) * strlen((char*)data));

    SHA256_CTX ctx;
    ctx.datalen = 0;
    ctx.bitlen = 512;

    sha256_init(&ctx);
    sha256_update(&ctx, data_buffer, strlen((char*)data));
    sha256_final(&ctx, hash);
    return(btoh(hex, hash, 32));
}

