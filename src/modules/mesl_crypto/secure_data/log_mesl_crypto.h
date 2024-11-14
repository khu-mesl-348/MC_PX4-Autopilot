#include "modules/mesl_crypto/mc.h"
#include <px4_platform_common/posix.h>
#include <fcntl.h>

//#define INTEGRITY_MODE
#define CIPHER_MODE

//#define LOG_RSA_MODE
//#define LOG_HMAC_MODE

char log_sign_filename[50];
byte log_sign_data[128];
SHA256_CTX log_ctx;
int log_sign_fd;

void mesl_set_sign_filename(const char *filename) {
    int i;
    for(i = 0; i < 35; i++) {
        log_sign_filename[i] = filename[i];
    }
    log_sign_filename[i] = '_';
    log_sign_filename[i + 1] = 's';
    log_sign_filename[i + 2] = 'i';
    log_sign_filename[i + 3] = 'g';
    log_sign_filename[i + 4] = 'n';
}

void Initialize_mesl_crypto() {
#if defined(LOG_INTEGRITY_MODE)
    log_sign_fd = open(log_sign_filename, O_RDWR | O_CREAT, PX4_O_MODE_666);
#if defined(LOG_RSA_MODE)
    SHA256_Init(&log_ctx);
#endif
#if defined(LOG_HMAC_MODE)
    byte key[16] = {0};
    HMAC_Init(&log_ctx, key);
#endif
#endif

#if defined(LOG_CIPER_MODE)
    Initialize_AES128_CTR();
#endif
}

void mesl_sign_log(byte *buffer, int size) {
#if defined(LOG_RSA_MODE)
    byte log_hash[32];
    SHA256_Update(&log_ctx, buffer, size);
    SHA256_Final(&log_ctx, log_hash);

    int log_sign_len = 128;
    Encrypt_RSA1024(0, log_hash, 32, log_sign_data, &log_sign_len);

    lseek(log_sign_fd, 0, SEEK_SET);
    int ret = write(log_sign_fd, log_sign_data, log_sign_len);
    if(ret < 0) {
        PX4_ERR("Write log sign data to log file error!");
    } else {
        fsync(log_sign_fd);
    }
#endif
#if defined(LOG_HMAC_MODE)
    byte log_hash[32];
    HMAC_Update(&log_ctx, buffer, size);
    HMAC_Final(&log_ctx, log_hash);

    lseek(log_sign_fd, 0, SEEK_SET);
    int ret = write(log_sign_fd, log_hash, 32);
    if(ret < 0) {
        PX4_ERR("Write log sign data to log file error!");
    } else {
        fsync(log_sign_fd);
    }
#endif
}

void mesl_enc_log(byte *buffer, int size) {
    //Encrypt_AES128_CTR(AES* aes_ctr, int keyNum, uint8_t* plain_data, int plain_len, uint8_t* enc_data)
    AES aes_ctr;
    Encrypt_AES128_CTR(&aes_ctr, 0, buffer, size, buffer);
}

void mesl_close_sign_file() {
    close(log_sign_fd);
    log_sign_fd = -1;
}
