#include <stdio.h>
#include <fstream>
#include <sys/types.h>
#include "AES.h"
#include "mc.h"
#define _CRT_SECURE_NO_WARNINGS 
#pragma warning(disable:4996)
const int block_size = 64;


int get_size_decrypt(FILE* file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int decrypt(void)
{
    int i = 0, j = 0;
    FILE* org_file = fopen("dataman", "rb");
    if (!org_file) {
        printf("Original file open error!\n");
        return 1;
    }

    int sign_len = 124;
    int size = get_size_decrypt(org_file);
    byte* data = (byte*)malloc(size * sizeof(byte));
    byte* sign_data = (byte*)malloc(sign_len * sizeof(byte));

    while (!feof(org_file)) {
        data[i] = getc(org_file);
        i++;
    }
    fclose(org_file);

    FILE* sig_file = fopen("dm_sig", "rb");
    if (!sig_file) {
        printf("Signature file open error!\n");
        return 1;
    }

    while (!feof(org_file)) {
        sign_data[j] = getc(org_file);
        j++;
    }
    fclose(sig_file);

    if (!Verify_RSA1024(124, sign_data, sign_len, data, &size))
        printf("Hash error");

    return 0;
}

int get_size(FILE* file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}
int make_sign(void) {
    int i = 0, j = 0;
    FILE *org_file = fopen("dataman", "rb");
    if (!org_file) {
        printf("Original file open error!\n");
        return 1;
    }

  
    int plain_len = get_size_decrypt(org_file);
    byte* plain_data =  (byte*)malloc(plain_len);

    while(!feof(org_file)) {
        plain_data[i] = getc(org_file);
        i++;
    }
    fclose(org_file);







    /*plain_len = 10;
    plain_data[0] = 'h';
    plain_data[1] = 'e';
    plain_data[2] = 'l';
    plain_data[3] = 'l';
    plain_data[4] = 'o';
    plain_data[5] = 'w';
    plain_data[6] = 'o';
    plain_data[7] = 'r';
    plain_data[8] = 'l';
    plain_data[9] = 'd';
    plain_data[10] = '\0';*/

    uint8_t digest[32];
    int digest_len = 32;

    if (SHA_256(plain_data, plain_len, digest, &digest_len)) {
        printf("SHA256_digest: ");
        dump(digest, digest_len);
    }

    else {
        printf("SHA256 Failure");
    }

    uint8_t RSA_enc_data[128];
    int RSA_enc_len;


    if (Encrypt_RSA1024(1, digest, digest_len, RSA_enc_data, &RSA_enc_len)) {
        printf("enc_data: ");
        dump(RSA_enc_data, RSA_enc_len);
    }
    else
        printf("Encrypt plain_data Failure\n");
    FILE* sign_file = fopen("dm_sig", "wb");

    fwrite(RSA_enc_data, sizeof(byte), RSA_enc_len, sign_file);

    return 0;
}
int encrypt(void)
{
    
    const char* param_backup_file = "mtd_params";

    FILE* file = fopen(param_backup_file, "rb");
    fseek(file, 0, SEEK_SET);
    FILE* enc_file = fopen("enc_mtd_params", "wb");

    int buf_size = get_size(file);
    const int block_num = buf_size / block_size + 1;
    byte org_buf[64];
    byte enc_buf[64];
    //byte** org_buf = (byte**)malloc(block_num * sizeof(byte*));
    //for (int i = 0; i < block_num; ++i) {
    //    org_buf[i] = (byte*)malloc(block_size * sizeof(byte));
    //    if (org_buf[i] == NULL) {
    //        perror("Failed to allocate memory for dec_buf[i]");
    //        // 이미 할당된 메모리 해제
    //        for (int j = 0; j < i; ++j) {
    //            free(org_buf[j]);
    //        }
    //        free(org_buf);
    //        free(enc_buf);
    //        return EXIT_FAILURE;
    //    }
    //}
    int enc_data_len = 0, delete_len = 0, pad = 0, length;
    if (buf_size % 16 != 0)
        pad = 16 - buf_size % 16;

    while (enc_data_len + 64 < buf_size) {

        fseek(file, enc_data_len, SEEK_SET);
        size_t pm_read = ::fread(org_buf, sizeof(unsigned char), block_size ,file);
        if (pm_read == -1)
            printf("Written parameter read error!");

        Encrypt_AES128(1, org_buf, block_size, enc_buf, &length);
        printf("%s, %s", org_buf, enc_buf);

        size_t pm_write = ::fwrite(enc_buf, sizeof(unsigned char), block_size, enc_file);
        
        if (pm_write == -1)
            printf("Encryption parameter write error!");

        enc_data_len += block_size;
    }
    delete_len = buf_size % block_size;
    fseek(file, enc_data_len, SEEK_SET);
    size_t pm_read = ::fread(org_buf, sizeof(unsigned char), delete_len, file);
    Encrypt_AES128(1, org_buf, delete_len, enc_buf, &length);
    printf("%s, %s", org_buf, enc_buf);

   size_t pm_write = ::fwrite(enc_buf, sizeof(unsigned char), delete_len+pad, enc_file);

    if (pm_write == -1)
        printf("Encryption parameter write error!");


    ::fclose(enc_file);
    ::fclose(file);
    printf("Encryption complete!");
    return 0;
}
int decrypt_file(void)
{
    int i = 0, j = 0;
    FILE* enc_file = fopen("11_04_19.ulg", "rb");
    if (!enc_file) {
        printf("Encryption file open error!\n");
        return 1;
    }

    int block_size = 64, length;
    int size = get_size(enc_file);
    int block_num = size / block_size + 1;

    //byte enc_buf[block_size] = { 0x00 };
    //byte dec_buf[block_num][block_size] = { 0x00 };

    byte enc_buf[64] = { 0x00 };
    // 2차원 배열 할당
    byte** dec_buf = (byte**)malloc(block_num * sizeof(byte *));
    if (dec_buf == NULL) {
        perror("Failed to allocate memory for dec_buf");
        //free(enc_buf); // 이미 할당된 메모리 해제
        return EXIT_FAILURE;
    }

    for (int i = 0; i < block_num; ++i) {
        dec_buf[i] = (byte*)malloc(block_size * sizeof(byte));
        if (dec_buf[i] == NULL) {
            perror("Failed to allocate memory for dec_buf[i]");
            // 이미 할당된 메모리 해제
            for (int j = 0; j < i; ++j) {
                free(dec_buf[j]);
            }
            free(dec_buf);
            //free(enc_buf);
            return EXIT_FAILURE;
        }
    }

    int delete_len = 0;
    while (!feof(enc_file)) {
        if (j == block_num - 1) {
            delete_len = block_size - size % block_size;
        }

        while (i < block_size) {
            enc_buf[i] = getc(enc_file);
            i++;
        }
        i = 0;

        Decrypt_AES128(0, enc_buf, block_size - delete_len, dec_buf[j], &length);
        j++;
    }
    fclose(enc_file);

    FILE* dec_file = fopen("dec_11_04_19.ulg", "wb");
    if (!dec_file) {
        printf("Decryption file open error!\n");
        return 1;
    }

    for (i = 0; i < j; i++) {
        if (i == j - 1) {
            fwrite(dec_buf[i], sizeof(byte), block_size - delete_len, dec_file);
        }
        else {
            fwrite(dec_buf[i], sizeof(byte), block_size, dec_file);
        }

    }
    fclose(dec_file);

    return 0;
}

int main(void) {
    //encrypt();
    decrypt_file();
}