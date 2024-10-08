#include "mesl_crypto_main.h"

#include <nuttx/config.h>
#include <px4_platform_common/log.h>

#include <stdio.h>
#include <errno.h>

//__EXPORT void mesl_crypto_main(int argc, char *argv[]);

extern "C" __EXPORT int mesl_crypto_main(int argc, char *argv[]) {

	PX4_INFO("Successful: Executed MESL CRYPTO MODULE");

	Init_MC();

	uint8_t plain_data[] = "HELLO MESL Crypto";
	int plain_len = strlen((char *)plain_data);

	printf("plain_data: ");
	dump(plain_data, plain_len);

	//Test SHA256

	uint8_t digest[32];
	int digest_len = 32;

	if (SHA_256(plain_data, plain_len, digest, &digest_len)) {
		printf("SHA256_digest: ");
		dump(digest, digest_len);
	}

	else {
		printf("SHA256 Failure");
	}

	//Test AES-128

	int AES_key_num = 0x0;

	uint8_t AES_enc_data[64];
	int AES_enc_len;

	uint8_t AES_dec_data[64];
	int AES_dec_len;

	// if (!Generate_AES128Key(AES_key_num))
	// 	printf("Set AES128 Key Generation Failure\n");

	if (Encrypt_AES128(AES_key_num, plain_data, plain_len, AES_enc_data, &AES_enc_len)) {
		printf("AES enc_data : ");
		dump(AES_enc_data, AES_enc_len);
	}
	else
		printf("AES Encrypt plain_data Failure\n");

	if (Decrypt_AES128(AES_key_num, AES_enc_data, AES_enc_len, AES_dec_data, &AES_dec_len)) {
		printf("AES dec_data : ");
		dump(AES_dec_data, AES_dec_len);
	}
	else
		printf("AES Decrypt enc_data Failure\n");


	// Test RSA-1024 (Encryption)

	int RSA_key_num = 0x0;

	uint8_t RSA_enc_data[128];
	int RSA_enc_len;

	uint8_t RSA_dec_data[64];
	int RSA_dec_len;

	if (!Generate_RSA1024Key(RSA_key_num))
		printf("Set RSA1024 Key Generation Failure\n");

	if (Encrypt_RSA1024(RSA_key_num, plain_data, plain_len, RSA_enc_data, &RSA_enc_len)) {
		printf("enc_data: ");
		dump(RSA_enc_data, RSA_enc_len);
	}
	else
		printf("Encrypt plain_data Failure\n");
	if (Decrypt_RSA1024(RSA_key_num, RSA_enc_data, RSA_enc_len, RSA_dec_data, &RSA_dec_len)) {
		printf("dec_data: ");
		dump(RSA_dec_data, RSA_dec_len);
	}
	else
		printf("Decrypt enc_data Failure\n");


	// Test RSA-1024 (Verification)

	int RSA_key = 0x01;
	uint8_t RSA_sign_data[128];
	int RSA_sign_len;

	if (!Generate_RSA1024Key(RSA_key)) {
		printf("Key Generation err\n");
	}

	if (!Sign_RSA1024(RSA_key, plain_data, plain_len, RSA_sign_data, &RSA_sign_len)) {
		printf("Signing err\n");
	}

	printf("sign_data: ");
	dump(RSA_sign_data, 128);

	if (Verify_RSA1024(RSA_key, RSA_sign_data, RSA_sign_len, plain_data, &plain_len)){
		printf("Verify Success\n");
	}
	else
	{
		printf("RSA 1024 Failure");
	}

	return 0;
}
