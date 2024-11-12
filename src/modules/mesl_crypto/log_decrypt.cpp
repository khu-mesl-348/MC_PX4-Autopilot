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
    FILE *enc_file = fopen("dataman", "rb");
    if (!enc_file) {
        printf("Encryption file open error!\n");
        return 1;
    }
    printf("1!\n");

    int length;
    const int block_size = 64;
    int size = get_size(enc_file);
    const int block_num = size / block_size + 1;
    printf("%d\n", block_num);


    byte enc_buf[block_size];
    byte dec_buf[block_num][block_size];
    printf("1!\n");
    
    int delete_len = 0;
    while(!feof(enc_file)) {
        if(j == block_num - 1) {
			delete_len = block_size - size % block_size;
		}

        while(i < block_size) {
            enc_buf[i] = getc(enc_file);
            i++;
        }
        i = 0;
    
        Decrypt_AES128(0, enc_buf, block_size - delete_len, dec_buf[j], &length);
        j++;
    }
    /*while(!feof(enc_file)) {
        enc_buf[i] = getc(enc_file);
        //printf("%02x ", data[i]);
        if(i == size - 1)
            break;
        i++;
    }
    Decrypt_AES128(0, enc_buf, size, enc_buf, &length);
    fclose(enc_file);*/

    FILE * dec_file = fopen("dec_dataman", "wb");
    if (!dec_file) {
        printf("Decryption file open error!\n");
        return 1;
    }

    //fwrite(enc_buf, sizeof(byte), size, dec_file);

    for(i = 0; i < j; i++) {
        if(i == j - 1) {
            fwrite(dec_buf[i], sizeof(byte), block_size - delete_len, dec_file);
        } else {
            fwrite(dec_buf[i], sizeof(byte), block_size, dec_file);
        }
        
    }
    fclose(dec_file);

    return 0;
}
