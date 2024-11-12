#include "modules/mesl_crypto/mc.h"

//#define INTEGRITY_MODE
#define CIPHER_MODE

byte pm_sign_data[128];
const char mtd_param_filename[15] = "/fs/mtd_params";
const char backup_param_filename[36] = "/fs/microsd/parameters_backup.bson";

int mtd_pm_sign_fd;
int backup_pm_sign_fd;
int fp;

int mesl_signcheck_param(int fd, const char *filename) {
	char mtd_sign_filename[23] = "/fs/microsd/mtd_pm_sig";
	char backup_sign_filename[26] = "/fs/microsd/backup_pm_sig";

	if(strcmp(mtd_param_filename, filename) == 0) {
		mtd_pm_sign_fd = ::open(mtd_sign_filename, O_RDWR | O_CREAT, PX4_O_MODE_666); 
		int ret = read(mtd_pm_sign_fd, pm_sign_data, 128);
		if(ret < 0) {
			PX4_ERR("Read mtd sign data error!");
			return -1;
		} else if(ret == 0) {
			PX4_ERR("No sign data in mtd sign file!");
			return -1;
		}
	} else if(strcmp(backup_param_filename, filename) == 0) {
		backup_pm_sign_fd = ::open(backup_sign_filename, O_RDWR | O_CREAT, PX4_O_MODE_666); 
		int ret = read(backup_pm_sign_fd, pm_sign_data, 128);
		if(ret < 0) {
			PX4_ERR("Read backup sign data error!");
			return -1;
		} else if(ret == 0) {
			PX4_ERR("No sign data in backup sign file!");
			return -1;
		}
	} else {
		return -1;
	}

	byte last_pm_hash[32];
	int last_pm_hash_len = 32;
	Decrypt_RSA1024(0, pm_sign_data, 128, last_pm_hash, &last_pm_hash_len);
	
	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	byte pm_buf[64];
	byte pm_hash[32];
	int block_size = 64, delete_len = 0;
	int file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0 ,SEEK_SET);
	for(int i = 0; i < file_size; i += block_size) {
		if(i > file_size - block_size || file_size < block_size)
			delete_len = block_size - file_size % block_size;
		
		int ret = ::read(fd, pm_buf, block_size - delete_len);
		if(ret < 0) {
			PX4_ERR("Read param data error!");
			return -1;
		}

		SHA256_Update(&ctx, pm_buf, block_size - delete_len);
	}
	SHA256_Final(&ctx, pm_hash);

	if(memcmp(pm_hash, last_pm_hash, 32) == 0) {
        PX4_INFO("Param sign check success!");
    } else {
		PX4_ERR("Param sign check error!");
		return -1;
	}
	lseek(fd, 0, SEEK_SET);

	return 0;
}

int mesl_dec_param(int fd, const char *filename) {
	if(strcmp(mtd_param_filename, filename) == 0 || strcmp(backup_param_filename, filename) == 0) {
		byte ver_buf[4];
		int ret = ::read(fd, ver_buf, 4);
		if(ret < 0) {
			PX4_ERR("Param verify data read error!");
			return -1;
		}

		if(!((ver_buf[2] == 0x00 && ver_buf[3] == 0x00) || (ver_buf[2] == 0xff && ver_buf[3] == 0xff))) {
			int file_size = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
		
			byte pm_buf[64];
			int block_size = 64, delete_len = 0, j = 0, k = 0, length;
			for(int i = 0; i < file_size; i += block_size) {
				if(i > file_size - block_size || file_size < block_size)
					delete_len = block_size - (file_size % block_size);
					
				ret = ::read(fd, pm_buf, block_size - delete_len);
				if(ret < 0) {
					PX4_ERR("Parameter read error!");
					return -1;
				}

				if(j == 0) {
					for(k = 0; k < 64 - 2; k++) {
						if(pm_buf[k] == 0xff && pm_buf[k + 1] == 0xff && pm_buf[k + 2] == 0xff) {
							j = 1;
							break;
						}
					}
				}

				if(j == 0) {
					Decrypt_AES128(0, pm_buf, block_size - delete_len, pm_buf, &length);
				} 
				else if(j == 1) {
					Decrypt_AES128(0, pm_buf, i, pm_buf, &length);
					j = 2;
				}
					
				lseek(fd, i, SEEK_SET);
				ret = ::write(fd, pm_buf, block_size - delete_len);
				if(ret < 0) {
					PX4_ERR("Decrypted parameter write error!");
					return -1;
				}
			}
		}
		lseek(fd, 0, SEEK_SET);
		fsync(fd);
	}
	
	return 0;
}

int mesl_sign_param(const char *filename) {
	if(strcmp(mtd_param_filename, filename) == 0 || strcmp(backup_param_filename, filename) == 0) {
		int fd = ::open(filename, O_RDWR | O_CREAT, PX4_O_MODE_666);

		SHA256_CTX ctx;
		SHA256_Init(&ctx);

		byte pm_buf[64];
		byte pm_hash[32];
		int block_size = 64, delete_len = 0, pm_sign_len = 128, ret;
		int file_size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0 ,SEEK_SET);
		for(int i = 0; i < file_size; i += block_size) {
			if(i > file_size - block_size || file_size < block_size)
				delete_len = block_size - file_size % block_size;
		
			ret = ::read(fd, pm_buf, block_size - delete_len);
			if(ret < 0) {
				PX4_ERR("Read param data error!");
				return -1;
			}

			SHA256_Update(&ctx, pm_buf, block_size - delete_len);
		}
		SHA256_Final(&ctx, pm_hash);
		Encrypt_RSA1024(0, pm_hash, 32, pm_sign_data, &pm_sign_len);

		if(strcmp(mtd_param_filename, filename) == 0) {
			lseek(mtd_pm_sign_fd, 0, SEEK_SET);
			ret = ::write(mtd_pm_sign_fd, pm_sign_data, pm_sign_len);
			fsync(mtd_pm_sign_fd);
			::close(mtd_pm_sign_fd);

			int size = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
			byte *buf = (byte*)malloc(size);
			ret = ::read(fd, buf, size);
			::close(fd);
				
			char new_filename[20] = "/fs/microsd/mtd_pm";
			int new_fd = ::open(new_filename, O_WRONLY | O_CREAT, PX4_O_MODE_666);
				
			ret = ::write(new_fd, buf, size);
			fsync(new_fd);
			::close(new_fd);
			free(buf);
		} else {
			lseek(backup_pm_sign_fd, 0, SEEK_SET);
			ret = ::write(backup_pm_sign_fd, pm_sign_data, pm_sign_len);
			fsync(backup_pm_sign_fd);
			::close(backup_pm_sign_fd);
			::close(fd);
		}
	}

	return 0;
}

int mesl_enc_param(const char *filename) {
	if(fp == 0) {
		fp = 1;
		return 0;
	}
	
	if(strcmp(mtd_param_filename, filename) == 0 || strcmp(backup_param_filename, filename) == 0) {
		int fd = ::open(filename, O_RDWR | O_CREAT, PX4_O_MODE_666);
		int buf_size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);

		byte pm_buf[64];
		int block_size = 64, delete_len = 0, ret, length;
		for(int i = 0; i < buf_size; i += block_size) {
			if(i > buf_size - block_size || buf_size < block_size)
				delete_len = block_size - buf_size % block_size;
							
			ret = ::read(fd, pm_buf, block_size - delete_len);
			if(ret < 0) {
				PX4_ERR("Parameter read error!");
				return -1;
			}
							
			lseek(fd, i, SEEK_SET);
			Encrypt_AES128(0, pm_buf, block_size - delete_len, pm_buf, &length);

			ret = ::write(fd, pm_buf, block_size - delete_len);
			if(ret < 0) {
				PX4_ERR("Encrypted parameter write error!\n");
				return -1;
			}
		}
		fsync(fd);
	
		if(strcmp(mtd_param_filename, filename) == 0) {
			int size = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
			byte *buf = (byte*)malloc(size);
			ret = ::read(fd, buf, size);
			::close(fd);
				
			char new_filename[20] = "/fs/microsd/mtd_pm";
			int new_fd = ::open(new_filename, O_WRONLY | O_CREAT, PX4_O_MODE_666);
				
			ret = ::write(new_fd, buf, size);
			fsync(new_fd);
			::close(new_fd);
			free(buf);
		} else {
			::close(fd);
		}
		fp = 1;
	}

	return 0;
}
