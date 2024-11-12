#include <stdio.h>
#include <fstream>
#include "AES.h"
#include "mc.h"

int get_size(FILE *file) {
    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(void)
{
    int i = 0, j = 0;
    FILE *org_file = fopen("parameters_backup.bson", "rb");
    if (!org_file) {
        printf("Original file open error!\n");
        return 1;
    }

    int sign_len = 128;
    int size = get_size(org_file);
    byte data[size];
    byte sign_data[128];
    printf("\n%d\n", size);
    
    while(!feof(org_file)) {
        data[i] = getc(org_file);
        printf("%02x ", data[i]);
        if(i == size - 1)
            break;
        i++;
    }
    printf("\n%d\n", i);
    fclose(org_file);

    FILE *sig_file = fopen("pm_sig", "rb");
    if (!sig_file) {
        printf("Signature file open error!\n");
        return 1;
    }

    while(!feof(sig_file)) {
        sign_data[j] = getc(sig_file);
        j++;
    }
    fclose(sig_file);

    if(!Verify_RSA1024(0, sign_data, sign_len, data, &size))
        printf("\nHash error\n");
    printf("\n%d\n", size);

    return 0;
}
