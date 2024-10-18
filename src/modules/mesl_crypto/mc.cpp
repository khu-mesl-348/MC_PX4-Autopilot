/****************************************************************************
 *
 *   Copyright (c) 2012-2022 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * @file mc.cpp
 * Minimal application example for PX4 autopilot
 *
 * @author Example User <mail@example.com>
 */

#include "mc.h"

int publicKey[2] = { 14351, 11 };
int privateKey[2] = { 14351, 1283 };
byte AES_key[MAX_AES_KEY_IDX][16] = {};

extern int key_flag;
AES aes_ctr;

void Is_Initialized_MC() {
	while(key_flag != 1);
}

//AES128_CBC
void Encrypt_AES128(int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len) {
	AES aes;

	plain_data[plain_len++] = 0x00;
	aes.do_aes_encrypt(plain_data, plain_len, enc_data, AES_key[keyNum], 128);
	*enc_len = (plain_len) % 16 ? ((plain_len / 16) + 1) * 16: plain_len;

}

//AES128_CBC
void Decrypt_AES128(int keyNum, uint8_t* enc_data, int enc_len, uint8_t* dec_data, int* dec_len) {
	AES aes;

	aes.do_aes_decrypt(enc_data, enc_len, dec_data, AES_key[keyNum], 128);
	*dec_len = strlen((char *)dec_data);

}

void Initialize_AES128_CTR() {

	aes_ctr.ctr_initialize();

}

void Encrypt_AES128_CTR(int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data) {
	aes_ctr.ctr_encrypt(plain_data, plain_len, enc_data, AES_key[keyNum], 128);

}

void Decrypt_AES128_CTR(int keyNum, uint8_t* enc_data, int plain_len, uint8_t* plain_data) {
	aes_ctr.ctr_decrypt(enc_data, plain_len, plain_data, AES_key[keyNum], 128);

}

// int Generate_RSA1024Key(int keyNum) {
// 	return 1;
// }

void Encrypt_RSA1024(int key_num, uint8_t* plain_data, int plain_len, uint8_t* enc_data, int* enc_len) {
	rsa.encrypt(plain_data, plain_len, enc_data, enc_len, privateKey);
}

void Decrypt_RSA1024(int key_num, uint8_t* enc_data, int enc_len, uint8_t* plain_data, int* plain_len) {
	rsa.decrypt(plain_data, plain_len, enc_data, enc_len, publicKey);
}

// int Sign_RSA1024(int key_num, uint8_t* plain_data, int plain_len, uint8_t* sign_data, int* sign_len) {
// 	uint8_t hash[32];
// 	int hashlen = 32;

// 	SHA_256(plain_data, plain_len, hash, &hashlen);

// 	rsa.encrypt(hash, hashlen, sign_data, sign_len, privateKey);
// 	return 1;
// }

// int Verify_RSA1024(int key_num, uint8_t* sign_data, int sign_len, uint8_t* org_data, int* org_len) {
// 	uint8_t dec_data[32];
// 	int dec_datalen;
// 	rsa.decrypt(dec_data, &dec_datalen, sign_data, sign_len, publicKey);

// 	uint8_t hash[32];
// 	int hashlen = 32;
// 	SHA_256(org_data, *org_len, hash, &hashlen);

// 	for (int i = 0; i < 32; i++) {
// 		if (hash[i] != dec_data[i])
// 			return 0;
// 	}

// 	return 1;
// }


// SHA256_Init
//  int Sign_RSA1024_Init(SHA256_CTX* ctx) {
// 	ctx->datalen = 0;
// 	ctx->bitlen = 512;
// 	sha256_init(ctx);

// 	return 1;
// }

//SHA256_Update
// int Sign_RSA1024_Update(SHA256_CTX* ctx, uint8_t* plain_data, int plain_len, uint8_t* sign_data) {
// 	uint8_t hash[32];
// 	sha256_update(ctx, plain_data, plain_len);
// 	sha256_final(ctx, hash);

// 	int sign_len;
// 	rsa.encrypt(hash, 32, sign_data, &sign_len, privateKey);

// 	return 1;
// }

//SHA256_Final


// int SHA_256(uint8_t* plain_data, int plain_len, uint8_t* digest, int* digest_len) {
// 	SHA256_CTX ctx;
// 	ctx.datalen = 0;
// 	ctx.bitlen = 512;

// 	sha256_init(&ctx);
// 	sha256_update(&ctx, (uint8_t*)plain_data, plain_len);
// 	sha256_final(&ctx, (uint8_t*)digest);

// 	*digest_len = 32;

// 	return 1;
// }

void SHA256_Init(SHA256_CTX* ctx){
	sha256_init(ctx);
}

void SHA256_Update(SHA256_CTX* ctx, uint8_t* plain_data, int plain_len){
	sha256_update(ctx, plain_data, plain_len);
}

void SHA256_Final(SHA256_CTX* ctx, uint8_t* digest){
	sha256_final(ctx, digest);
}

void HMAC_Init(SHA256_CTX* ctx, uint8_t* key) {
	sha256_init(ctx);
	sha256_update(ctx, key, 16);
}

void HMAC_Update(SHA256_CTX* ctx, uint8_t* plain_data, int plain_len) {
	sha256_update(ctx, plain_data, plain_len);
}

void HMAC_Final(SHA256_CTX* ctx, uint8_t* digest){
	sha256_final(ctx, digest);
}
