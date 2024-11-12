#include "RSA.h"

RSA rsa;

RSA::RSA()
{

}

RSA::~RSA()
{

}

void RSA::encrypt(uint8_t* plainText, int plainLen, uint8_t* cipherText, int* cipherLen, int* publicKey)
{
    long m = 1;
    int n = publicKey[0];
    int e = publicKey[1];
    int ctr = 0;

    for (int i = 0; i < plainLen; i++) {
        for (int j = 0; j < e; j++) {
            m = (m * plainText[i]) % n;
        }

        ctr = i * sizeof(int);

        cipherText[ctr] = (char)(m & 0x00ff);
        cipherText[ctr + 1] = (char)((m & 0xff00) >> 8);

        m = 1;
    }

#if DEBUG
    printf("\n==========BEGIN CIPHERTEXT==========");
    for (int i = 0; i < CIPHERTEXT_SIZE; i++) {
        printf((unsigned char)cipherText[i], DEC); Serial.print(" ");
    }
    printf("\n===========END CIPHERTEXT===========\n");
#endif
    ctr += 4;
    * cipherLen = ctr;
    
}

void RSA::decrypt(uint8_t* plainText, int* plainLen, uint8_t* cipherText, int cipherLen, int* privateKey)
{
    long M = 1;
    int n = privateKey[0];
    int d = privateKey[1];
    int temp = 0;
    int ctr = 0;

    //re-assemble char array to array of int
    unsigned int i = 0;
    for (i = 0; i < cipherLen / sizeof(int); i++) {
        ctr = i * sizeof(int);
        temp = (((unsigned char)cipherText[ctr + 1] << 8) | (unsigned char)cipherText[ctr]);

        for (int j = 0; j < d; j++) {
            M = (M * temp) % n;
        }

        plainText[i] = (unsigned char)(M & 0xFF);
        M = 1;
    }

#if DEBUG
    printf("\n==========BEGIN PLAINTEXT==========");
    for (int i = 0; i < PLAINTEXT_SIZE; i++)
        printf(plainText[i]);
    printf("\n===========END PLAINTEXT===========\n");
#endif
    * plainLen = i;
}

bool RSA::compare(uint8_t*arr1, uint8_t*arr2, int len)
{
    return !memcmp(arr1, arr2, len);
}
