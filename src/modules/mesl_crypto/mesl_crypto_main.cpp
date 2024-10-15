#include "mesl_crypto_main.h"
#include "SHA.h"

//#include <nuttx/config.h>
#include <px4_platform_common/log.h>

#include <stdio.h>
#include <errno.h>

extern uint8_t AES_key[1][16];

void dump(byte* buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		printf("%d", (int)buf[i]);
		printf(" ");
	}
	printf("\n");
}

extern "C" __EXPORT int mesl_crypto_main(int argc, char *argv[]) {

	// PX4_INFO("Successful: Executed MESL CRYPTO MODULE");

	Is_Initialized_MC();

	uint8_t s_plain_data[] = "HELLO MESL Crypto";
	uint8_t v_plain_data[] = "BYE MESL Crypto";
	int s_plain_len = strlen((char *)s_plain_data);
	int v_plain_len = strlen((char *)v_plain_data);

	//Test HMAC
	SHA256_CTX s_ctx;
	SHA256_CTX v_ctx;
	uint8_t s_hash[32];
	uint8_t v_hash[32];

	// Singing with HMAC
	HMAC_Init(&s_ctx, AES_key[0]);
	HMAC_Update(&s_ctx, s_plain_data, s_plain_len);
	HMAC_Final(&s_ctx, s_hash);

	//Verifying with HMAC
	HMAC_Init(&v_ctx, AES_key[0]);
	HMAC_Update(&v_ctx, v_plain_data, v_plain_len);
	HMAC_Final(&v_ctx, v_hash);

	for(int i = 0; i < 32; i++){
		if(s_hash[i] != v_hash[i]){
			PX4_INFO("HAMC Verifying Failed. \n");
			break;
		}
	}

	//Test AES-128

	uint8_t AES_enc_data[64];
	int AES_enc_len;

	uint8_t AES_dec_data[64];
	int AES_dec_len;

	int AES_key_num = 0x0;

	Encrypt_AES128(AES_key_num, s_plain_data, s_plain_len, AES_enc_data, &AES_enc_len);
	printf("AES enc_data : ");
	dump(AES_enc_data, AES_enc_len);

	Decrypt_AES128(AES_key_num, AES_enc_data, AES_enc_len, AES_dec_data, &AES_dec_len);
	printf("AES dec_data : ");
	dump(AES_dec_data, AES_dec_len);


	// Test RSA-1024 (Encryption)

	int RSA_key_num = 0x0;

	uint8_t RSA_enc_data[128];
	int RSA_enc_len;

	uint8_t RSA_dec_data[64];
	int RSA_dec_len;

	Encrypt_RSA1024(RSA_key_num, s_plain_data, s_plain_len, RSA_enc_data, &RSA_enc_len);
	printf("enc_data: ");

	Decrypt_RSA1024(RSA_key_num, RSA_enc_data, RSA_enc_len, RSA_dec_data, &RSA_dec_len);
	printf("dec_data: ");
	dump(RSA_dec_data, RSA_dec_len);

	return 0;
}
