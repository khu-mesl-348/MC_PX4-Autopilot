
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../mc.h"


void mesl_px4_read(ssize_t* nread, uint8_t* buf, uint8_t* packet_buf, int* packet_buf_index, int* next_index, int* new_nread);
void mesl_px4_encrypt(uint8_t* buf, unsigned* len);
void mesl_px4_encrypt_len(int* len);
void mesl_px4_decrypt(ssize_t* nread, uint8_t* buf, uint8_t* packet_buf, int* packet_buf_index, int* next_index, int* new_nread, int* check_flag);
void mesl_px4_integrity_gen(uint8_t* buf, unsigned* len);
void mesl_px4_integrity_len(int* len);
void mesl_px4_integrity_check(ssize_t* nread, uint8_t* buf, uint8_t* packet_buf, int* packet_buf_index, int* next_index, int* new_nread, int* check_flag);
