/**
 * @file se.cpp
 * Driver for the SE on a serial port
 */

#include <nuttx/config.h>
#include <px4_platform_common/log.h>

#include <nuttx/clock.h>
#include <nuttx/arch.h>

#include <stdlib.h>
#include <px4_platform_common/module.h>
#include <px4_platform_common/time.h>
#include <px4_platform_common/Serial.hpp> //UART
#include <px4_arch/micro_hal.h> //GPIO

#include "se.h"

/* LOG */
// #define DEBUG

/*Class Identifier*/
#define CRYPTO_CLASS 0x80
#define CHAINING_CRYPTO_CLASS 0x90

/*Crypto Spplet Commands*/
#define INS_SHA 0x50
#define INS_AES_SETKEY 0x80
#define INS_AES_ENCRYPT 0x81
#define INS_AES_DECRYPT 0x82

#define INS_GET_RANDOM 0x84

#define INS_RSA_KEY_GENERATE 0x88
#define INS_ECC_KEY_GENERATE 0xA0
#define INS_RSA_ENCRYPT 0x89
#define INS_RSA_DECRYPT 0x8A
#define INS_RSA_GETKEY 0x8F

#define INS_ECC_GEN 0xA0
#define INS_ECDSA_SIGN 0xA1
#define INS_ECDSA_VERIFY 0xA2

#define INS_PUT_DATA 0xDA

/*Configurations*/
#define RXBUFSIZE   1024

#define RESET_PIN PB7
#define ISO7816_RESET_TIME 1000
#define ISO7816_MAX_WTX_DELAY 300
#define ISO7816_MAX_WTX_RESPONSES 300

#define MAX_C_APDU_SIZE 256
#define MAX_R_APDU_SIZE 256

#define RSP_BUF_SIZE 270
#define MAX_ATR_SIZE 100
#define APDU_BUF_SIZE 270
#define MAX_R_APDU_SIZE 256
#define MAX_FRAME_SIZE 254
#define MAX_DATA_BLOCK_SIZE 249
#define MAX_AES_DATA_BLOCK_SIZE 240

enum RST {RST_ON, RST_OFF};
enum APDU_POS {APDU_CLA, APDU_INS, APDU_P1, APDU_P2, APDU_LC, APDU_DATA};

typedef union SW {
	uint16_t SW1SW2;
	struct{
		uint8_t SW2;
		uint8_t SW1;
	};
} SW;

/*---------------------------------------------------------------------------------------------------------*/
/* Global variables                                                                                        */
/*---------------------------------------------------------------------------------------------------------*/

uint8_t C_APDU[MAX_C_APDU_SIZE]; // Array reserved for Command APDU
uint8_t R_APDU[MAX_C_APDU_SIZE]; // Array reserved for response APDU

static uint8_t T1_IFSC = MAX_FRAME_SIZE;    // 254 or 32-4 = frame size acceptable by the card (including NAD+PCB+LEN+LRC)
static uint8_t T1_IFSD = MAX_FRAME_SIZE;    // frame size acceptable by the host
static uint8_t Current_PCB = 0;
static uint8_t Receive_PCB = 0;
static int T1_NumRetries = 2;
SW statuswords;
uint16_t expectedSW1SW2 = 0x9000;

uint8_t ResponseBuffer[RSP_BUF_SIZE];
int NumberOfResponseBytes = 0;
int DataChunkSize = 0;

uint8_t _AES_key[16] = {0,};
int key_flag = 0;

extern uint8_t AES_key[1][16];

void dump(uint8_t* buf, int len);

//extern void UART_setTimeout(int time);

/*
 * Driver 'main' command.
 */
extern "C" __EXPORT int se_main(int argc, char *argv[]);

// SE Driver test code
int se_main(int argc, char *argv[]){

	if (key_flag == 0){
		SE_HW *set_se = SE_HW::Instance();

		if(!set_se->Init_SE()){
			SE_HW::Exit_SE();
			return 0;
		}
		set_se->Get_AES128Key(_AES_key, 0, 16);
		PX4_INFO("Get key from SE. Done.\n");

		for(int i = 0; i < 16; i++)
			AES_key[0][i] = _AES_key[i];

		key_flag = 1;
	}

	// for(int j=0; j<16; j++){
	// 	PX4_INFO("key_buf[%d]: %02x\n", j, _AES_key[j]);
	// }

	return 1;
}

SE_HW* SE_HW::Instance(){
	if(_instance == nullptr){
		_instance = new SE_HW();
	}
	return _instance;
}

void SE_HW::Exit_SE(){
	delete _instance;
	_instance = nullptr;
}

SE_HW::SE_HW(){

	const char path[] = "/dev/ttyS6"; //GPS2 Port

	strncpy(_gps_port, path, sizeof(_gps_port) - 1);
	_gps_port[sizeof(_gps_port) - 1] = '\0';
	_baudrate = 9600;

	/* Set GPS 2 UART. This port used to communicate with SE. */

	//Configure UART port
	if(!_gps_uart.setPort(_gps_port)){
		PX4_INFO("Error) configuring serial device on port %s\n", _gps_port);
		px4_sleep(1);
	}

	//Configure the default baudrate
	if(!_gps_uart.setBaudrate(_baudrate)){
		PX4_INFO("Error) setting baudrate to %u on %s\n", _baudrate, _gps_port);
		px4_sleep(1);
	}

	//Serial element configuration
	if(!_gps_uart.setParity(Parity::Even)){
		PX4_INFO("Error) setting Parity to Even, but..\n");
		px4_sleep(1);
	}

	if(!_gps_uart.setStopbits(StopBits::Two)){
		PX4_INFO("Error) setting Stopbits to 2, but..\n");
		px4_sleep(1);
	}

	//Open the UART. If this is successful then the UART is ready to use
	if(!_gps_uart.open()){
		PX4_INFO("Error) opening serial device %s\n", _gps_port);
		px4_sleep(1);
	}
}

SE_HW::~SE_HW(){
	_gps_uart.close();
}

int SE_HW::Init_SE(){

	if(OpenCard() && Connect_Applet()){
		PX4_INFO("SE Connection Success\n");
		return 1;
	}
	PX4_INFO("SE Connection Failed\n");

	return 0;
}

void SE_HW::SE_Reset(){

	/* Set FMU Debug UART. This port used to communicate with Arduino. */
	/* Send the command to Arduino that resets SE module. */

	const char fmu_path[] = "/dev/ttyS2"; //FMU Debug Port

	strncpy(_fmu_port, fmu_path, sizeof(_fmu_port) - 1);
	_fmu_port[sizeof(_fmu_port) - 1] = '\0';

	//Configure UART port
	if(!_fmu_uart.setPort(_fmu_port)){
		PX4_INFO("Error) configuring serial device on port %s\n", _fmu_port);
		px4_sleep(1);
	}

	//Configure the default baudrate
	if(!_fmu_uart.setBaudrate(_baudrate)){
		PX4_INFO("Error) setting baudrate to %u on %s\n", _baudrate, _fmu_port);
		px4_sleep(1);
	}

	//Open the UART. If this is successful then the UART is ready to use
	if(!_fmu_uart.open()){
		PX4_INFO("Error) opening serial device %s\n", _fmu_port);
		px4_sleep(1);
	}

	// Reset SE (Arduino Trigger)
	const char buffer[6] = "mesl\n";
	int buffer_size = 6;

	if(!_fmu_uart.write(buffer, buffer_size)){
		PX4_INFO("Error) fmu uart write Failed\n");
		px4_sleep(1);
	};

	// uint8_t read_buffer[50];
	// int length;
	// length = fmu_uart.read(read_buffer, 50);

	// for(int i = 0; i <50; i++)
	// 	PX4_INFO("fmu_uart test) readbuffer: %u", read_buffer[i]);

	// PX4_INFO("fmu_uart test) length %d", length);

	_fmu_uart.close();

	PX4_INFO("SE reset succeeded\n");


}

int SE_HW::OpenCard(){

	const int sizeof_pps = 4;
	const int sizeof_ifs = 5;

	uint8_t COMBuffer[10];

	//uint8_t cmdPPS_T1[]    = { 0xFF, 0x11, 0x18, 0xF6 };	/* Max. bit rate (DF=31) */
	uint8_t cmdPPS_T1[] = { 0xFF, 0x11, 0x11, 0xFF }; /* Default bit rate */
	uint8_t cmd_S_IFS_T1[] = { 0x00, 0xC1, 0x01, 0x00, 0x00 };

	int numberOfComBytes;

	cmd_S_IFS_T1[3] = T1_IFSD;
	cmd_S_IFS_T1[4] = cmd_S_IFS_T1[0] ^ cmd_S_IFS_T1[1] ^ cmd_S_IFS_T1[2] ^ cmd_S_IFS_T1[3];

	SE_Reset();

	px4_sleep(1);

	for(int i = 0; i < 5; i++){
		if(ReadBlock_UART(ResponseBuffer, 1, NULL) <= 0){
			PX4_INFO("Error) UART read failed\n");
			return 0;
		}
		if(ResponseBuffer[0] == 0x3B){
			ReadBlock_UART(ResponseBuffer + 1, MAX_ATR_SIZE, &NumberOfResponseBytes);
			NumberOfResponseBytes++;
			break;
		}
	}

	px4_usleep(200000);
	_gps_uart.flush(); // purge output buffer

	if(!Transmit_UART(cmdPPS_T1, sizeof_pps, COMBuffer, &numberOfComBytes)){
        	PX4_INFO("Error) PPS failed\n");
		return 0;
	}

	if(numberOfComBytes != sizeof_pps){
		PX4_INFO("Error) numberOfComBytes != sizeof_pps \n");
		PX4_INFO("numberOfComBytes: %d \n", numberOfComBytes);
		return 0;
	}


	if(!Transmit_UART(cmd_S_IFS_T1, sizeof_ifs, COMBuffer, &numberOfComBytes)){
		PX4_INFO("Error) IFS failed\n");
		return 0;
	}


	if(numberOfComBytes != sizeof_ifs){
		PX4_INFO("Error) numberOfComBytes != sizeof_ifs \n");
		return 0;
	}

	T1_IFSC = COMBuffer[3];
	DataChunkSize = T1_IFSC - 6;
	if(DataChunkSize <= 0){
		PX4_INFO("Error) IFSC too small, should be greater than 6");
		return 0;
	}

	PX4_INFO("OpenCard succeeded\n");

	return 1;

}

int SE_HW::Connect_Applet(){
	uint8_t cmd_SelectCryptoApplet[6] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0x01 };

	C_APDU[APDU_CLA] = 0x00;
	C_APDU[APDU_INS] = 0xA4;
	C_APDU[APDU_P1] = 0x04;
	C_APDU[APDU_P2] = 0x00;
	C_APDU[APDU_LC] = 0x06;

	memcpy(C_APDU + APDU_DATA, cmd_SelectCryptoApplet, 6);

	if (TransmitAPDU(C_APDU, 11, NULL, NULL) && statuswords.SW1SW2 == 0x9000)
		return 1;

	return 0;
}

int SE_HW::TransmitAPDU(uint8_t* pbInBuf, int lInBufLen, uint8_t* pbOutBuf, int* plOutBufLen){
	static uint8_t cmd_GetResponse[] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };
	int   i, lResult = 0;
	int   offset = 0;
	int   saveLeflag = 0;
	uint8_t  saveLe;
	int   lenr;

	if(pbOutBuf == NULL) pbOutBuf = ResponseBuffer;
	if(plOutBufLen) *plOutBufLen = 0;

	statuswords.SW1SW2 = 0;
	for(i = 0; i < 256; i++){
		//PX4_INFO("lInBufLen(numBytesToSend): %d", lInBufLen);
		lResult = Transmit_T1(pbInBuf, lInBufLen, pbOutBuf + offset, &lenr);

		if(saveLeflag)
			pbInBuf[lInBufLen - 1] = saveLe;
		saveLeflag = 0;
		if(lResult != TRUE && expectedSW1SW2 != 0x0000)
			return FALSE;

		if(lenr < 2)
			return FALSE;

		offset += lenr;
		statuswords.SW1SW2 = pbOutBuf[offset-2] * 256 + pbOutBuf[offset - 1];

		if(pbOutBuf[offset - 2] == 0x6C){
			saveLe = pbInBuf[lInBufLen - 1];
			saveLeflag = 1;
			pbInBuf[lInBufLen - 1] = pbOutBuf[offset - 1];
			continue;
		}
		else if (pbOutBuf[offset - 2] == 0x61){
			pbInBuf = cmd_GetResponse;
			cmd_GetResponse[APDU_LC] = pbOutBuf[offset - 1];
			offset += lenr - 2;
			lInBufLen = sizeof(cmd_GetResponse);
			continue;
		}
		break;
	}
	lenr -= 2;
	if(plOutBufLen)
		*plOutBufLen = offset - 2;

	return lResult;
}

int SE_HW::ReadBlock_UART(uint8_t* pbRecvBuf, int length, int* pRecvLength){
	int NumberOfBytesRead = 0;

	if(pRecvLength)
		*pRecvLength = 0;

	NumberOfBytesRead = _gps_uart.read(pbRecvBuf, 1);

	// #ifdef DEBUG
	// PX4_INFO("ReadBlock_UART(): Recieved data: ");
	// for(int i=0; i<length; i++){
	// 	PX4_INFO("pbRecvBuf[%d]: %02x\n", i, pbRecvBuf[i]);
	// }
	// #endif

	if(NumberOfBytesRead == 0){
		PX4_INFO("Error) ReadBlock_UART(): Nothing recieved\n");
		//return 0;
	}

	if(length > 1){

		/* Send 1 byte at a time */
		/*
		for(int i = 1; i <= length; i++){
			_fmu_uart.read(pbRecvBuf + i, 1);
		}
		NumberOfBytesRead = length;
		*/

		NumberOfBytesRead = 0;
		NumberOfBytesRead = _gps_uart.read(pbRecvBuf + 1, length - 1);
		NumberOfBytesRead++;
		#ifdef DEBUG
		PX4_INFO("ReadBlock_UART(): Recieved data: ");
		for(int i=0; i<NumberOfBytesRead; i++){
			PX4_INFO("pbRecvBuf[%d]: %02x\n", i, pbRecvBuf[i]);
		}
		#endif

	}
	if(pRecvLength)
		*pRecvLength = NumberOfBytesRead;

	return NumberOfBytesRead;
}

int SE_HW::WriteBlock_UART(uint8_t* pbSendBuf, int length){
	uint8_t buf[APDU_BUF_SIZE];
	int NumberOfBytesRead = 0;

	_gps_uart.flush();

	if(_gps_uart.write(pbSendBuf, length) <= 0){
		//PX4_INFO("Error) WriteBlock_UART(): Writing failed\n");
		return 0;
	}

	px4_usleep(100000);

	int test_read = _gps_uart.read(buf, length); // return -1
	if(test_read){
		//PX4_INFO("TEST READ) ret: %d, length: %d", test_read, length);
		NumberOfBytesRead = test_read;
	}

	if(NumberOfBytesRead > 0){
		// for (int i = 0; i < length; i++){
		// 	// if(buf[i] != pbSendBuf[i]){
		// 	// 	PX4_INFO("Error) Sent: %02X  Recv: %02X\n", pbSendBuf[i], buf[i]);
		// 	// 	return 0;
		// 	// }
		// 	PX4_INFO("Sent: %02X  Recv: %02X\n", pbSendBuf[i], buf[i]);
		// }
	}
	return 1;
}

int SE_HW::Transmit_UART(uint8_t* pbSendbuf, int sendLength, uint8_t* recvBuf, int* pRecvBuf){
	_gps_uart.flush();

	if(!WriteBlock_UART(pbSendbuf, sendLength))
		return 0;


	if(ReadBlock_UART(recvBuf, MAX_R_APDU_SIZE, pRecvBuf) == 0){
		PX4_INFO("Error) response timeout.\n");
		return 0;
	}

	return 1;
}

int SE_HW::Transmit_T1(uint8_t* pbSendBuf, int sendLength, uint8_t* pbRecvBuf, int *pRecvLength){
	int numBytesSent = 0, dataBlockLength;
	int numBytesRead, numBytesRead1 = 0;
	uint8_t PCB;
	int result;

	do{
		dataBlockLength = sendLength;
		if(sendLength > T1_IFSC){
			PCB = Current_PCB | 0x20;
			dataBlockLength = T1_IFSC;
			PX4_INFO("dataBlockLength = T1_IFSC: %d", dataBlockLength);
			PX4_INFO("PCB = %u", PCB);
		}
		else
			PCB = Current_PCB & 0xDF;

		if((result = Transmit_T1_packet(0, PCB, pbSendBuf + numBytesSent, dataBlockLength, pbRecvBuf, &numBytesRead1)) == FALSE)
			return FALSE;

		sendLength -= T1_IFSC;
		numBytesSent += T1_IFSC;

	}while(sendLength > 0);

	while(result == 0x20){
		PCB = 0x80 | ((Receive_PCB != 0) ? 0x10 : 0);
		if((result = Transmit_T1_packet(0, PCB, NULL, 0, pbRecvBuf + numBytesRead1, &numBytesRead)) == FALSE)
			return FALSE;

		numBytesRead1 += numBytesRead;
	}
	if(pRecvLength)
		*pRecvLength = numBytesRead1;

	return TRUE;
}

int SE_HW::Transmit_T1_packet(uint8_t NAD, uint8_t PCB, uint8_t* pbData, int iDataLen, uint8_t* pbRecvBuf, int *pRecvLength){
	//uint8_t tempBuf[100];
	//int tempLen;
	int a = 3;
	int whole_cnt = 0;

	uint8_t sendBuf[4];
	uint8_t respBuf[4];
	uint8_t recvPCB, EDC;
	int headerLen = 3, recvLen, dataLen, cnt = 0;

	EDC = NAD ^ PCB ^ (uint8_t)iDataLen;

    	PX4_INFO("EDC: %u, NAD: %u, PCB: %u, iDataLength: %u", EDC, NAD, PCB, (uint8_t)iDataLen);

	sendBuf[0] = NAD;
	sendBuf[1] = PCB;
	sendBuf[2] = (uint8_t)iDataLen;

	for(int i = 0; i < iDataLen; i++)
		EDC ^= pbData[i];

	if((PCB & 0x80) == 0x00)
		Current_PCB ^= 0x40;

	while(1){
		_gps_uart.flush();

		uint8_t wholeBuf[15];

		for(int j = 0; j < headerLen; j++){
			wholeBuf[whole_cnt] = sendBuf[j];
			whole_cnt++;
		}
		for(int z = 0; z < iDataLen; z++){
			wholeBuf[whole_cnt] = pbData[z];
			whole_cnt++;
		}
		wholeBuf[whole_cnt] = EDC;

		if(WriteBlock_UART(wholeBuf, 15) != TRUE)
			return FALSE;

		PX4_INFO("Send all\n");

		if(ReadBlock_UART(respBuf, 4, &recvLen) == 0)
			return FALSE;

		if(recvLen >= 4){
			dataLen = (int)respBuf[2];
			recvLen = 0;
			if(dataLen){
				pbRecvBuf[0] = respBuf[3];
				if((a=ReadBlock_UART(pbRecvBuf + 1, dataLen, &recvLen) == 0) || dataLen != recvLen)
					return FALSE;
			}

			#ifdef DEBUG
			PX4_INFO("\n\tresult data\n");
			PX4_INFO("\tread data: ");
			for(int i = 0; i < recvLen; i++){
				PX4_INFO("%02x ", pbRecvBuf[i]);
			}
			PX4_INFO("\n");
			#endif
		}
		else
			return FALSE;

		recvPCB = respBuf[1] & 0xEF;
		if(recvPCB == 0x81 || recvPCB == 0x82){
			if(cnt++ < T1_NumRetries)
				continue;
			else
				return FALSE;
		}
		else if(recvPCB == 0xC3){
			sendBuf[1] = 0xE3;
			sendBuf[2] = 1;
			sendBuf[3] = 1;
			EDC = 0xE3;
			headerLen = 4;
			iDataLen = 0;
			px4_usleep(3000000);
			if(cnt++ < ISO7816_MAX_WTX_RESPONSES)
				continue;
			else
				return FALSE;
		}
		if(dataLen < recvLen)
			recvLen = dataLen;
		break;
	}

	if(pRecvLength)
		*pRecvLength = recvLen;

	if((recvPCB & 0x80) == 0x00)
		Receive_PCB ^= 0x40;

	if((recvPCB & 0x20) != 0)
		return 0x20;

	return TRUE;
}

int SE_HW::GetKey_TransmitAPDU(uint8_t* pbInBuf, int lInBufLen, uint8_t* pbOutBuf, int* plOutBufLen, uint8_t* key_buf, int key_len){
	static uint8_t cmd_GetResponse[] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };
	int   i, lResult = 0;
	int   offset = 0;
	int   saveLeflag = 0;
	uint8_t  saveLe;
	int   lenr;

	if(pbOutBuf == NULL) pbOutBuf = ResponseBuffer;
	if(plOutBufLen) *plOutBufLen = 0;

	statuswords.SW1SW2 = 0;
	for(i = 0; i < 256; i++){

		lResult = Transmit_T1(pbInBuf, lInBufLen, pbOutBuf + offset, &lenr);

		if(saveLeflag)
			pbInBuf[lInBufLen - 1] = saveLe;
		saveLeflag = 0;
		if(lResult != TRUE && expectedSW1SW2 != 0x0000)
			return FALSE;

		if(lenr < 2)
			return FALSE;

		offset += lenr;
		statuswords.SW1SW2 = pbOutBuf[offset-2] * 256 + pbOutBuf[offset - 1];

		for(int j=0; j<key_len; j++){
			key_buf[j] = pbOutBuf[j];
		}

		if(pbOutBuf[offset - 2] == 0x6C){
			saveLe = pbInBuf[lInBufLen - 1];
			saveLeflag = 1;
			pbInBuf[lInBufLen - 1] = pbOutBuf[offset - 1];
			continue;
		}
		else if (pbOutBuf[offset - 2] == 0x61){
			pbInBuf = cmd_GetResponse;
			cmd_GetResponse[APDU_LC] = pbOutBuf[offset - 1];
			offset += lenr - 2;
			lInBufLen = sizeof(cmd_GetResponse);
			continue;
		}
		break;
	}
	lenr -= 2;
	if(plOutBufLen)
		*plOutBufLen = offset - 2;

	return lResult;
}

//Get Key.
//key num == 0x00
//key_len: n bytes. In a case of using AES-128, put 16 in.
int SE_HW::Get_AES128Key(uint8_t* buffer, int key_num, int key_len) {

	C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x83;
	C_APDU[APDU_P1] = 0x09;
	C_APDU[APDU_P2] = (uint8_t)key_num;
	C_APDU[APDU_LC] = 0x00;

	if (GetKey_TransmitAPDU(C_APDU, 5, NULL, NULL, buffer, key_len) && statuswords.SW1SW2 == 0x9000){
		px4_usleep(200000);

		return TRUE;
	}

	return FALSE;
}
