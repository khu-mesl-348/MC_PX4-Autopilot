#include <px4_platform_common/posix.h>
#include <modules/dataman/dataman.h>
#include "modules/mesl_crypto/mc.h"

//#define INTEGRITY_MODE
#define CIPHER_MODE

//#define DM_RSA_MODE
//#define DM_HMAC_MODE

extern unsigned dm_size;
byte dm_sign_data[128];

void mesl_sign_dataman(int offset) {
	if(offset == 0) {
		int ret;
#if defined(DM_RSA_MODE)
		byte dm_hash[32];
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, dm_operations_data.ram.data, (int)dm_size);
		SHA256_Final(&ctx, dm_hash);	

		int dm_sign_len = 128;
		Encrypt_RSA1024(0, dm_hash, 32, dm_sign_data, &dm_sign_len);

		lseek(dm_operations_data.ram.sign_fd, 0, SEEK_SET);
		ret = write(dm_operations_data.ram.sign_fd, dm_sign_data, dm_sign_len);
		if(ret < 0) {
			PX4_ERR("Write dataman sign data error!");
		} else {
			fsync(dm_operations_data.ram.sign_fd);
		}
#endif

#if defined(DM_HMAC_MODE)
		byte dm_hash[32];
		SHA256_CTX ctx;
		byte key[16] = {0};
		HMAC_Init(&ctx, key);
		HMAC_Update(&ctx, dm_operations_data.ram.data, (int)dm_size);
		HMAC_Final(&ctx, dm_hash);

		lseek(dm_operations_data.ram.sign_fd, 0, SEEK_SET);
		ret = write(dm_operations_data.ram.sign_fd, dm_hash, 32);
		if(ret < 0) {
			PX4_ERR("Write dataman sign data error!");
		} else {
			fsync(dm_operations_data.ram.sign_fd);
		}
#endif

		lseek(dm_operations_data.ram.backup_fd, 0, SEEK_SET);
		ret = write(dm_operations_data.ram.backup_fd, dm_operations_data.ram.data, (int)dm_size);
		if(ret < 0) {
			PX4_ERR("Dataman save error!");
		} else {
			fsync(dm_operations_data.ram.backup_fd);
		}
	}
}

void mesl_enc_dataman(int dm_offset) {
	if(dm_offset == 0) {
		lseek(dm_operations_data.ram.backup_fd, 0, SEEK_SET);
		int block_size = 1600, delete_len = 0, length;

		for(int i = 0; i < (int)dm_size; i += block_size) {
			if(i > (int)dm_size - block_size)
				delete_len = block_size - (int)dm_size % block_size;

			Encrypt_AES128(0, &dm_operations_data.ram.data[i], block_size - delete_len, dm_operations_data.ram.enc_data, &length);

			int ret = write(dm_operations_data.ram.backup_fd, dm_operations_data.ram.enc_data, block_size - delete_len);
			if(ret < 0)
				PX4_ERR("Write encrypted data to dataman backup file error!");
		}
		fsync(dm_operations_data.ram.backup_fd);
	}
}

int mesl_signcheck_dataman(const char *k_data_manager_device_path, int max_offset) {
	char sign_filename[30] = "/fs/microsd/sign_dataman";
	dm_operations_data.ram.sign_fd = open(sign_filename, O_RDWR | O_CREAT, PX4_O_MODE_666);
	
	dm_operations_data.ram.backup_fd = open(k_data_manager_device_path, O_RDWR | O_CREAT, PX4_O_MODE_666);
	if(dm_operations_data.ram.backup_fd < 0) {
		PX4_ERR("Open dataman backup file error!");
		return -1;
	}

	int ret = read(dm_operations_data.ram.backup_fd, dm_operations_data.ram.data, max_offset);
	if(ret < 0) {
		PX4_ERR("Read data from dataman backup file error!");
		return -1;
	}

#if defined(LOG_RSA_MODE)
	SHA256_CTX ctx;
	byte dm_hash[32];
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, dm_operations_data.ram.data, max_offset);
	SHA256_Final(&ctx, dm_hash);

	if(dm_operations_data.ram.sign_fd < 0) {
		PX4_ERR("Open dataman sign file error!");
		return -1;
	}

	ret = read(dm_operations_data.ram.sign_fd, dm_sign_data, 128);
	if(ret < 0) {
		PX4_ERR("Read sign data error!");
		return -1;
	}

	int dm_hash_len = 32;
	byte last_dm_hash[32];
	Decrypt_RSA1024(0, dm_sign_data, 128, last_dm_hash, &dm_hash_len);

	if(memcmp(dm_hash, last_dm_hash, 32) == 0) {
		PX4_INFO("Dataman sign check success!");
	} else {
		PX4_ERR("Dataman sign check error!");
	}
#endif

#if defined(LOG_HMAC_MODE)
	SHA256_CTX ctx;
	byte dm_hash[32];
	byte key[16] = {0};
	HMAC_Init(&ctx, key);
	HMAC_Update(&ctx, dm_operations_data.ram.data, max_offset);
	HMAC_Final(&ctx, dm_hash);

	if(dm_operations_data.ram.sign_fd < 0) {
		PX4_ERR("Open dataman sign file error!");
		return -1;
	}

	ret = read(dm_operations_data.ram.sign_fd, dm_hash, 32);
	if(ret < 0) {
		PX4_ERR("Read sign data error!");
	}
#endif
	
	return 0;
}

int mesl_dec_dataman(const char *k_data_manager_device_path, int max_offset) {
	dm_operations_data.ram.backup_fd = open(k_data_manager_device_path, O_RDWR | O_CREAT, PX4_O_MODE_666);
	if(dm_operations_data.ram.backup_fd < 0) {
		PX4_ERR("open dataman backup file error!");
		return -1;
	}

	byte ver_buf[4];
	int ret = read(dm_operations_data.ram.backup_fd, ver_buf, 4);
	if(ret < 0) {
		PX4_ERR("Verify data read error!");
		return -1;
	}
			
	if(!(ver_buf[1] == 0x00 && ver_buf[2] == 0x00 && ver_buf[3] == 0x00)) {
		int block_size = 1600, delete_len = 0, length;
		lseek(dm_operations_data.ram.backup_fd, 0, SEEK_SET);

		for(int i = 0; i < max_offset; i += block_size) {
			if(i > max_offset - block_size)
				delete_len = block_size - max_offset % block_size;

			ret = read(dm_operations_data.ram.backup_fd, dm_operations_data.ram.enc_data, block_size - delete_len);
			if(ret < 0) {
				PX4_ERR("Read data from dataman backup file error!");
				return -1;
			}

			Decrypt_AES128(0, dm_operations_data.ram.enc_data, block_size - delete_len, &dm_operations_data.ram.data[i], &length);
		}
	}
	
	return 0;
}
