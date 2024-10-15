#ifndef __SARDUINO__
#define __SARDUINO__

#include "AES.h"
#include "RSA.h"
#include "SHA.h"

#include <stdlib.h>

#define PRIVATE 0
#define PUBLIC 1

#define MAX_AES_KEY_IDX 1
#define MAX_AES_KEY_SIZE 16

typedef uint8_t byte;

void Is_Initialized_MC();

void Encrypt_AES128(int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len);
void Decrypt_AES128(int keyNum, uint8_t* enc_data, int enc_len, uint8_t* dec_data, int* dec_len);
void Encrypt_AES128_CTR(int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data);
void Decrypt_AES128_CTR(int keyNum, uint8_t* enc_data, int plain_len, uint8_t* plain_data);
void Initialize_AES128_CTR();

void Encrypt_RSA1024(int key_num, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len);
void Decrypt_RSA1024(int key_num, uint8_t* enc_data, int enc_len, uint8_t* plain_data, int* plain_len);

void SHA256_Init(SHA256_CTX* ctx);
void SHA256_Update(SHA256_CTX* ctx, uint8_t* plain_data, int plain_len);
void SHA256_Final(SHA256_CTX* ctx, uint8_t* digest);

void HMAC_Init(SHA256_CTX* ctx, uint8_t* key);
void HMAC_Update(SHA256_CTX* ctx, uint8_t* plain_data, int plain_len);
void HMAC_Final(SHA256_CTX* ctx, uint8_t* digest);

#endif
