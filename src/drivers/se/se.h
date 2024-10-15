#ifndef SE
#define SE

//SHA algorithm
#define SHA_1 0x01
#define SHA_256 0x04
#define SHA_384 0x05
#define SHA_512 0x06

#define RSA_1024 0x06
#define RSA_2048 0x07

#define AES_ECB_128 0x08
#define AES_CBC_128 0x09
#define AES_ECB_192 0x0A
#define AES_CBC_192 0x0B
#define AES_ECB_256 0x0C
#define AES_CBC_256 0x0D

#define ECC_P_192 0x00
#define ECC_P_224 0x0E
#define ECC_P_256 0x11
#define ECC_P_384 0x14
#define ECC_P_521 0x15

#define RSA_PADD_ISO14888 0x09
#define RSA_PADD_PCKS1 0x0A
#define RSA_PADD_ISO9796 0x0B
#define RSA_PADD_NO 0x0C
#define RSA_PADD_PKCS_OAEP 0x0D

using namespace std;

class SE_HW {
public:
	static SE_HW* Instance();

	int Init_SE();
	static void Exit_SE();

	int Get_AES128Key(uint8_t* buffer, int key_num, int key_len); // AES-128 cbc or HMAC
	void Initialize_MC();

private:

	SE_HW();
	~SE_HW();

	static SE_HW* _instance;

	// UART interface
	device::Serial 		_gps_uart {};
	device::Serial          _fmu_uart {};				///< UART interface
	unsigned		_baudrate {0};
	char			_gps_port[20] {};
	char			_fmu_port[20] {};

	void SE_Reset();
	int OpenCard();
	int Connect_Applet();

	int ReadBlock_UART(uint8_t* pbRecvBuf, int length, int* pRecvLength);
	int WriteBlock_UART(uint8_t* pbSendBuf, int length);
	int Transmit_UART(uint8_t* pbSendBuf, int sendLength, uint8_t* recvBuf, int* pRecvLength);
	int TransmitAPDU(uint8_t* pbInBuf, int lInBufLen, uint8_t* pbOutBuf, int* plOutBufLen);

	int Transmit_T1(uint8_t* pbSendBuf, int sendLength, uint8_t* pbRecvBuf, int *pRecvLength);
	int Transmit_T1_packet(uint8_t NAD, uint8_t PCB, uint8_t* pbData, int iDataLen, uint8_t* pbRecvBuf, int *pRecvLength);
	int GetKey_TransmitAPDU(uint8_t* pbInBuf, int lInBufLen, uint8_t* pbOutBuf, int* plOutBufLen, uint8_t* key_buf, int key_len);

	int readBytes_UART(uint8_t* pbRecvBuf, int bufLength);
	int writeBytes_UART(uint8_t* pbSendBuf, int sendLength);
	void purge_UART();

	void error_ctl();

};

SE_HW* SE_HW::_instance = nullptr;

#endif
