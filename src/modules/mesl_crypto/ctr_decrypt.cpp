#include <stdio.h>
#include <fstream>
#include "AES.h"
#include "mc.h"

int get_size(FILE *file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(void)
{
    int i = 0, j = 0;
    FILE *enc_file = fopen("05_27_25.ulg", "rb");
    if (!enc_file) {
        printf("Encryption file open error!\n");
        return 1;
    }

    int length;
    int size = get_size(enc_file);

    byte buf[size];
    //byte iv[16] = { 0xB3, 0xBA, 0xD6, 0x1A, 0xEA, 0xDA, 0x40, 0x90, 0x8F, 0x53, 0xEA, 0x02, 0x61, 0x42, 0x49, 0xA9 };
    //byte key[16] = { 0x7C, 0x85, 0x20, 0x89, 0xFF, 0xDB, 0x16, 0x12, 0x6D, 0xBE, 0xE7, 0xC9, 0x68, 0xA7, 0x51, 0xB5 };

    while(!feof(enc_file)) {
        buf[i] = getc(enc_file);
        if(i == size - 1)
            break;
        i++;
    }

    Encrypt_AES128_CTR(0, buf, size, buf);

    FILE * dec_file = fopen("dec_05_27_25.ulg", "wb");
    if (!dec_file) {
        printf("Decryption file open error!\n");
        return 1;
    }

    fwrite(buf, sizeof(byte), size, dec_file);
    fclose(dec_file);

    return 0;
}
