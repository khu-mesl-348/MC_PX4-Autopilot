#ifndef __SARDUINO__
#define __SARDUINO__

#include "AES.h"
#include "RSA.h"
#include "SHA.h"

#include <stdlib.h>

typedef uint8_t byte;


void dump(byte* buf, int len);

int Init_MC();

int Encrypt_AES128(int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len);
int Decrypt_AES128(int keyNum, uint8_t* enc_data, int enc_len, uint8_t* dec_data, int* dec_len);

int Generate_RSA1024Key(int keyNum);
int Encrypt_RSA1024(int key_num, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len);
int Decrypt_RSA1024(int key_num, uint8_t* enc_data, int enc_len, uint8_t* plain_data, int* plain_len);

int Sign_RSA1024(int key_num, uint8_t* plain_data, int plain_len, uint8_t* sign_data, int* sign_len);
int Verify_RSA1024(int key_num, uint8_t* sign_data, int sign_len, uint8_t* org_data, int* org_len);

int SHA_256(uint8_t* plain_data, int plain_len, uint8_t* digest, int* digest_len);
#endif
