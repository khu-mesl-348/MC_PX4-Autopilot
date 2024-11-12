#ifndef __RSA__
#define __RSA__

#define DEBUG 0

#define SMS_SIZE            160
#define PLAINTEXT_SIZE      (SMS_SIZE / sizeof(int))
#define CIPHERTEXT_SIZE     (SMS_SIZE)

//#include "Arduino.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

class RSA {
    private:

    public:
        RSA();
        ~RSA();
        void encrypt(uint8_t *plainText, int plainLen, uint8_t*cipherText, int* cipherLen, int *publicKey);
        void decrypt(uint8_t* plainText, int* plainLen, uint8_t* cipherText, int cipherLen, int* privateKey);
        bool compare(uint8_t*arr1, uint8_t*arr2, int len);
};
extern RSA rsa;
#endif
