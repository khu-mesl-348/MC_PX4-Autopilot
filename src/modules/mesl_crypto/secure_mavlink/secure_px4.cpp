#include "secure_px4.h"




void mesl_px4_encrypt(uint8_t* _buf, unsigned* _buf_fill){
	uint8_t _Bck[2] {};
	uint8_t	_Ebuf[256] {};
	unsigned _Ebuf_c{0};

	if(_buf[0]==253){
		memcpy(&_Bck[0], &_buf[(*_buf_fill) - 2], 2);
		Encrypt_AES128(0, &_buf[10], (*_buf_fill) - 12, _Ebuf, (int*)&_Ebuf_c);
		memcpy(&_buf[10], &_Ebuf[0], _Ebuf_c);
		memcpy(&_buf[_Ebuf_c + 10], &_Bck[0], 2);
		(*_buf_fill) = 10 + _Ebuf_c + 2;
	}
}


void mesl_px4_encrypt_len(int* length){
	uint8_t n_length = 0;
	if (((*length) % 16) == 0) {
		n_length = (*length);
	}
	else {
		n_length = (((*length) / 16) + 1) * 16;
	}
	(*length)=n_length;
}


void mesl_px4_decrypt(ssize_t* nread, uint8_t* buf, uint8_t* mesl_packet_buf, int* mesl_packet_buf_index, int* mesl_next_index, int* mesl_nread, int* mesl_check_flag){

	static int d_length = 0;
	static int e_length = 0;


	for(int position=0; position<(*nread); position++){
		mesl_packet_buf[position+(*mesl_packet_buf_index)]=buf[position];
	}
	(*mesl_packet_buf_index) = (*mesl_packet_buf_index) + (*nread);
	int delete_flag=1;

	while(delete_flag){

		if((*mesl_packet_buf_index)==0){
			delete_flag=0;
		}

		if(mesl_packet_buf[0]==253){
			if ((mesl_packet_buf[1]) % 16 == 0){
		    	e_length = mesl_packet_buf[1];
    		}

			else{
    	    	e_length = ((mesl_packet_buf[1] / 16) + 1) * 16;
   			}

			if(7<=(*mesl_packet_buf_index)){
				if(mesl_packet_buf[6]==68){
					if(mesl_packet_buf[1]+12<=(*mesl_packet_buf_index)){

						(*mesl_nread)=mesl_packet_buf[1]+12;
						(*mesl_next_index)=mesl_packet_buf[1]+12;
						(*mesl_packet_buf_index)=(*mesl_packet_buf_index) - (*mesl_next_index);
						(*mesl_check_flag)=1;
						printf("radio_packet\n");
					}
				}
				else{
					if(e_length+12<=(*mesl_packet_buf_index)){
						Decrypt_AES128(0,&mesl_packet_buf[10],e_length,&mesl_packet_buf[10],&d_length);
						mesl_packet_buf[10+mesl_packet_buf[1]] = mesl_packet_buf[10+e_length];
						mesl_packet_buf[11+mesl_packet_buf[1]] = mesl_packet_buf[11+e_length];
						(*mesl_nread) = mesl_packet_buf[1]+12;
						(*mesl_next_index) = e_length+12;
						(*mesl_packet_buf_index) = (*mesl_packet_buf_index) - (*mesl_next_index);
						(*mesl_check_flag) = 1;
						printf("decrypt_packet\n");
					}
				}
			}

			delete_flag=0;
		}
		else if(mesl_packet_buf[0]==254){
			if(mesl_packet_buf[1]+8<=(*mesl_packet_buf_index)){
				(*mesl_nread)=mesl_packet_buf[1]+8;
				(*mesl_next_index)=mesl_packet_buf[1]+8;
				(*mesl_packet_buf_index)=(*mesl_packet_buf_index) - (*mesl_next_index);
				(*mesl_check_flag)=1;
				printf("11_packet\n");
			}

			delete_flag=0;
		}
		else{
			for(int position=0; position<(*mesl_packet_buf_index)-1; position++){
				mesl_packet_buf[position]=mesl_packet_buf[position+1];
			}
			//mesl_packet_buf[mesl_packet_buf_index-1]=0;
			(*mesl_packet_buf_index)=(*mesl_packet_buf_index)-1;
			printf("!!!!!!!!!packet erase!!!!!!!!!!!!!\n");
		}
	}
}



void mesl_px4_read(ssize_t* nread, uint8_t* buf, uint8_t* mesl_packet_buf, int* mesl_packet_buf_index, int* mesl_next_index, int* mesl_nread){
	for(int position = 0; position < (*mesl_nread); position++){
		buf[position]=mesl_packet_buf[position];
	}


	if(mesl_packet_buf[0]==253 || mesl_packet_buf[0]==254){
		for(int position = 0; position < (*mesl_packet_buf_index); position++){
			mesl_packet_buf[position]=mesl_packet_buf[position+(*mesl_next_index)];
		}
	}
}



void mesl_px4_integrity_gen(uint8_t* _buf, unsigned* _buf_fill){
	extern uint8_t AES_key[1][16];


	if(_buf[0]==253){
		SHA256_CTX s_ctx;

		uint8_t s_hash[32];

		HMAC_Init(&s_ctx, AES_key[0]);
		HMAC_Update(&s_ctx, &_buf[0], _buf[1]+12);
		HMAC_Final(&s_ctx, s_hash);


		memcpy(&_buf[_buf[1]+12],&s_hash[0],13);
		(*_buf_fill)=(*_buf_fill)+13;

	}
}



void mesl_px4_integrity_len(int* length){
	*length = (*length)+13;
}


void mesl_px4_integrity_check(ssize_t* nread, uint8_t* buf, uint8_t* mesl_packet_buf, int* mesl_packet_buf_index, int* mesl_next_index, int* mesl_nread, int* mesl_check_flag){

				int _buf_len;




				for(int position=0; position<(*nread); position++){
					mesl_packet_buf[position+(*mesl_packet_buf_index)]=buf[position];
				}
				(*mesl_packet_buf_index) = (*mesl_packet_buf_index) + (*nread);

				int delete_flag=1;
				while(delete_flag){

					if((*mesl_packet_buf_index)==0){
						delete_flag=0;
					}

					if(mesl_packet_buf[0]==253){

						if(7<=(*mesl_packet_buf_index)){
							if(mesl_packet_buf[6]==68){
								if(mesl_packet_buf[1]+12<=(*mesl_packet_buf_index)){

								(*mesl_nread)=mesl_packet_buf[1]+12;
								(*mesl_next_index)=mesl_packet_buf[1]+12;
								(*mesl_packet_buf_index)=(*mesl_packet_buf_index) - (*mesl_next_index);
								(*mesl_check_flag)=1;
								printf("radio_packet\n");
								}
							}
							else{

								if(mesl_packet_buf[1]+12+32<=(*mesl_packet_buf_index)){
									_buf_len=mesl_packet_buf[1]+12;

									extern uint8_t AES_key[1][16];

									SHA256_CTX v_ctx;

									uint8_t v_hash[32];

									HMAC_Init(&v_ctx, AES_key[0]);
									HMAC_Update(&v_ctx, &mesl_packet_buf[0], mesl_packet_buf[1]+12);
									HMAC_Final(&v_ctx, v_hash);

									if(memcmp(&mesl_packet_buf[_buf_len],&v_hash[0],13)==0){
										(*mesl_nread)=mesl_packet_buf[1]+12;
										(*mesl_next_index)=_buf_len+13;
										(*mesl_packet_buf_index)=(*mesl_packet_buf_index)-(*mesl_next_index);

										(*mesl_check_flag)=1;
									}




									else{
										//printf("signature error\n");
										(*mesl_next_index)=_buf_len+13;
										(*mesl_packet_buf_index)=(*mesl_packet_buf_index)-(*mesl_next_index);

										for(int position = 0; position < (*mesl_packet_buf_index); position++){
											mesl_packet_buf[position]=mesl_packet_buf[position+(*mesl_next_index)];
										}
									}

								}
							}

						}

						delete_flag=0;
					}
					else if(mesl_packet_buf[0]==254){
						if(mesl_packet_buf[1]+8<=(*mesl_packet_buf_index)){

							(*mesl_nread)=mesl_packet_buf[1]+8;
							(*mesl_next_index)=mesl_packet_buf[1]+8;
							(*mesl_packet_buf_index)=(*mesl_packet_buf_index) - (*mesl_next_index);
							(*mesl_check_flag)=1;
							printf("11_packet\n");
						}

						delete_flag=0;
					}
					else{
						for(int position=0; position<(*mesl_packet_buf_index)-1; position++){
							mesl_packet_buf[position]=mesl_packet_buf[position+1];
						}
						//mesl_packet_buf[mesl_packet_buf_index-1]=0;
						(*mesl_packet_buf_index)=(*mesl_packet_buf_index)-1;
						printf("!!!!!!!!!packet erase!!!!!!!!!!!!!\n");
					}
				}
}
