#include "pch.h"
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <fstream>

#include <string>
#include <time.h>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)



#ifdef __alpha
	typedef unsigned int UINT4;
#else
	typedef unsigned long int UINT4;
#endif

#define MD5_INIT_STATE_0 0x67452301
#define MD5_INIT_STATE_1 0xefcdab89
#define MD5_INIT_STATE_2 0x98badcfe
#define MD5_INIT_STATE_3 0x10325476

	void MD5Init(void);
	void MD5Update(unsigned char *bug, unsigned int len);
	void MD5Final(char* cReturnStr);
	void Transform(UINT4 *buf, UINT4 *in);

	unsigned char  m_lpszBuffer[64];
	unsigned long m_nCount[2];
	unsigned long m_lMD5[4];

	static unsigned char PADDING[64] = {
	 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) \
 {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define GG(a, b, c, d, x, s, ac) \
 {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define HH(a, b, c, d, x, s, ac) \
 {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define II(a, b, c, d, x, s, ac) \
 {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }

	void ByteToDWord(DWORD* Output, ULONG* Input, UINT nLength) {
		UINT i = 0;
		UINT j = 0;
		for (; j < nLength; i++, j += 4)
		{
			Output[i] = (ULONG)Input[j] |
				(ULONG)Input[j + 1] << 8 |
				(ULONG)Input[j + 2] << 16 |
				(ULONG)Input[j + 3] << 24;
		}
	}

	void DWordToByte(unsigned char* Output, DWORD* Input, UINT nLength) {
		UINT i = 0;
		UINT j = 0;
		for (; j < nLength; i++, j += 4)
		{
			Output[j] = (UCHAR)(Input[i] & 0xff);
			Output[j + 1] = (UCHAR)((Input[i] >> 8) & 0xff);
			Output[j + 2] = (UCHAR)((Input[i] >> 16) & 0xff);
			Output[j + 3] = (UCHAR)((Input[i] >> 24) & 0xff);
		}
	}

	void MD5Init(void)
	{
		memset(m_lpszBuffer, 0, 64);
		m_nCount[0] = m_nCount[1] = 0;

		m_lMD5[0] = MD5_INIT_STATE_0;
		m_lMD5[1] = MD5_INIT_STATE_1;
		m_lMD5[2] = MD5_INIT_STATE_2;
		m_lMD5[3] = MD5_INIT_STATE_3;
	}

	void MD5Update(unsigned char *inBuf, unsigned int inLen)
	{
		register int i, ii;
		int mdi;
		UINT4 in[16];

		mdi = (int)((m_nCount[0] >> 3) & 0x3F);

		if ((m_nCount[0] + ((UINT4)inLen << 3)) < m_nCount[0])
			m_nCount[1]++;
		m_nCount[0] += ((UINT4)inLen << 3);
		m_nCount[1] += ((UINT4)inLen >> 29);

		while (inLen--) {
			m_lpszBuffer[mdi++] = *inBuf++;

			if (mdi == 0x40) {
				for (i = 0, ii = 0; i < 16; i++, ii += 4)
					in[i] = (((UINT4)m_lpszBuffer[ii + 3]) << 24) |
					(((UINT4)m_lpszBuffer[ii + 2]) << 16) |
					(((UINT4)m_lpszBuffer[ii + 1]) << 8) |
					((UINT4)m_lpszBuffer[ii]);
				Transform(m_lMD5, in);
				mdi = 0;
			}
		}
	}

	void MD5Final(char* cReturnStr)
	{
		unsigned char bits[8];
		int nIndex;
		unsigned int nPadLen;
		const int nMD5Size = 16;
		unsigned char lpszMD5[16];
		char temp[3];
		int i;

		cReturnStr[0] = '\0';

		DWordToByte(bits, m_nCount, 8);

		nIndex = (int)((m_nCount[0] >> 3) & 0x3f);
		nPadLen = (nIndex < 56) ? (56 - nIndex) : (120 - nIndex);
		MD5Update(PADDING, nPadLen);

		MD5Update(bits, 8);

		DWordToByte(lpszMD5, m_lMD5, nMD5Size);

		for (i = 0; i < nMD5Size; i++)
		{

			if (lpszMD5[i] == 0) {
				temp[0] = '0';
				temp[1] = '0';
			}
			else if (lpszMD5[i] <= 15) {
				sprintf(temp, "0%x", lpszMD5[i]);
			}
			else {
				sprintf(temp, "%x", lpszMD5[i]);
			}
			strcat(cReturnStr, temp);
		}
		lpszMD5[0] = '\0';
	}

	void Transform(register UINT4 *buf, register UINT4 *in)
	{
		register UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

#define S11 7
#define S12 12
#define S13 17
#define S14 22
		FF(a, b, c, d, in[0], S11, 0xD76AA478L);
		FF(d, a, b, c, in[1], S12, 0xE8C7B756L);
		FF(c, d, a, b, in[2], S13, 0x242070DBL);
		FF(b, c, d, a, in[3], S14, 0xC1BDCEEEL);
		FF(a, b, c, d, in[4], S11, 0xF57C0FAFL);
		FF(d, a, b, c, in[5], S12, 0x4787C62AL);
		FF(c, d, a, b, in[6], S13, 0xA8304613L);
		FF(b, c, d, a, in[7], S14, 0xFD469501L);
		FF(a, b, c, d, in[8], S11, 0x698098D8L);
		FF(d, a, b, c, in[9], S12, 0x8B44F7AFL);
		FF(c, d, a, b, in[10], S13, 0xFFFF5BB1L);
		FF(b, c, d, a, in[11], S14, 0x895CD7BEL);
		FF(a, b, c, d, in[12], S11, 0x6B901122L);
		FF(d, a, b, c, in[13], S12, 0xFD987193L);
		FF(c, d, a, b, in[14], S13, 0xA679438EL);
		FF(b, c, d, a, in[15], S14, 0x49B40821L);

#define S21 5
#define S22 9
#define S23 14
#define S24 20
		GG(a, b, c, d, in[1], S21, 0xF61E2562L);
		GG(d, a, b, c, in[6], S22, 0xC040B340L);
		GG(c, d, a, b, in[11], S23, 0x265E5A51L);
		GG(b, c, d, a, in[0], S24, 0xE9B6C7AAL);
		GG(a, b, c, d, in[5], S21, 0xD62F105DL);
		GG(d, a, b, c, in[10], S22, 0x02441453L);
		GG(c, d, a, b, in[15], S23, 0xD8A1E681L);
		GG(b, c, d, a, in[4], S24, 0xE7D3FBC8L);
		GG(a, b, c, d, in[9], S21, 0x21E1CDE6L);
		GG(d, a, b, c, in[14], S22, 0xC33707D6L);
		GG(c, d, a, b, in[3], S23, 0xF4D50D87L);
		GG(b, c, d, a, in[8], S24, 0x455A14EDL);
		GG(a, b, c, d, in[13], S21, 0xA9E3E905L);
		GG(d, a, b, c, in[2], S22, 0xFCEFA3F8L);
		GG(c, d, a, b, in[7], S23, 0x676F02D9L);
		GG(b, c, d, a, in[12], S24, 0x8D2A4C8AL);

#define S31 4
#define S32 11
#define S33 16
#define S34 23
		HH(a, b, c, d, in[5], S31, 0xFFFA3942L);
		HH(d, a, b, c, in[8], S32, 0x8771F681L);
		HH(c, d, a, b, in[11], S33, 0x6D9D6122L);
		HH(b, c, d, a, in[14], S34, 0xFDE5380CL);
		HH(a, b, c, d, in[1], S31, 0xA4BEEA44L);
		HH(d, a, b, c, in[4], S32, 0x4BDECFA9L);
		HH(c, d, a, b, in[7], S33, 0xF6BB4B60L);
		HH(b, c, d, a, in[10], S34, 0xBEBFBC70L);
		HH(a, b, c, d, in[13], S31, 0x289B7EC6L);
		HH(d, a, b, c, in[0], S32, 0xEAA127FAL);
		HH(c, d, a, b, in[3], S33, 0xD4EF3085L);
		HH(b, c, d, a, in[6], S34, 0x04881D05L);
		HH(a, b, c, d, in[9], S31, 0xD9D4D039L);
		HH(d, a, b, c, in[12], S32, 0xE6DB99E5L);
		HH(c, d, a, b, in[15], S33, 0x1FA27CF8L);
		HH(b, c, d, a, in[2], S34, 0xC4AC5665L);

#define S41 6
#define S42 10
#define S43 15
#define S44 21
		II(a, b, c, d, in[0], S41, 0xF4292244L);
		II(d, a, b, c, in[7], S42, 0x432AFF97L);
		II(c, d, a, b, in[14], S43, 0xAB9423A7L);
		II(b, c, d, a, in[5], S44, 0xFC93A039L);
		II(a, b, c, d, in[12], S41, 0x655B59C3L);
		II(d, a, b, c, in[3], S42, 0x8F0CCC92L);
		II(c, d, a, b, in[10], S43, 0xFFEFF47DL);
		II(b, c, d, a, in[1], S44, 0x85845DD1L);
		II(a, b, c, d, in[8], S41, 0x6FA87E4FL);
		II(d, a, b, c, in[15], S42, 0xFE2CE6E0L);
		II(c, d, a, b, in[6], S43, 0xA3014314L);
		II(b, c, d, a, in[13], S44, 0x4E0811A1L);
		II(a, b, c, d, in[4], S41, 0xF7537E82L);
		II(d, a, b, c, in[11], S42, 0xBD3AF235L);
		II(c, d, a, b, in[2], S43, 0x2AD7D2BBL);
		II(b, c, d, a, in[9], S44, 0xEB86D391L);

		buf[0] += a;
		buf[1] += b;
		buf[2] += c;
		buf[3] += d;
	}

	void GetMD5(char* pBuf, UINT nLength, char* cReturnStr) {
		MD5Init();
		MD5Update((unsigned char *)pBuf, nLength);
		MD5Final(cReturnStr);
	}

	/////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////


	void trapFlag() {
		BOOL isDebugged = TRUE;
		__try
		{
			__asm
			{
				pushfd
				or dword ptr[esp], 0x100 
				popfd                   
				nop
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			isDebugged = FALSE;
		}
		if (isDebugged)
		{
			exit(-1);
		}
	}


	void CheckRemoteDebuggerPresent() {
		BOOL isDebuggerPresent = FALSE;
		if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent))
		{
			if (isDebuggerPresent)
			{
				exit(-1);
			}
		}
	}



	int checkLicense() {
		int zq=0;
		string trueLicense = "6294955740b844bd44711fa4c684f353";
		ifstream file("License.txt");
		string s="ss";
		getline(file, s);
		char *mmm = new char[s.size()+1];
		mmm[s.size()] = '\0';
		for (int i = 0; i < s.size(); i++) {
			mmm[i] = s[i];
		}
		char *out = new char[33];
		out[33] = '\0';
		GetMD5(mmm, s.size()-1, out);
		string out1 = out;
		if (trueLicense == out1) {
			return 1;
		}
		else {
			return 0;
		}
	}


	int checkPass(char* pass) {
		time_t start, end;
		start = clock();
		char truePass1[] = { 'c','7','0','f','0','5','b','3','3'};
		char truePass2[] = {'1','4','8','4','7','a','1','c','9','2'};
		char truePass3[] = { '8','1','a','a','6','7' };
		char truePass4[] = { '1','1','4','5','3','4','a' };

		char qqq[9];
		char www[10];
		char eee[6];
		char rrr[7];

		for (int i = 0; i < 9; i++) {
			qqq[i] = pass[i];
		}


		int qwe = 8;
		int qwr = 28;

		int z = 0;
		int d = 40;
		for (int i = 0; i < 9; i++) {
			if (qqq[i] == truePass1[i]) {
				z=z+2;
			}
		}

		if (d - z == 22) {                        //true
			for (int i = 0; i < 10; i++) {
				www[i] = truePass2[i];
				z--;
			}
		}
		else  {                                      //фейк
			for (int i = 0; i < 9; i++) {
				qqq[i] = truePass1[3];
				z++;
			}
		}

		if (z == 29)
		{                                          //fake
			for (int i = 5; i >= 0; i--) {
				eee[i] = truePass3[i];
				z = z + 3;
			
			}
		}
		else if (z == 8) {                      //true
			for (int i = 0; i < 6; i++) {
				eee[i] = truePass3[i];
			}
		}
		  
		if (z == 8) {                           //true
			for (int i = 0; i < 7; i++) {
				rrr[i] = truePass4[i];
				z = z + 5;
			}
		}

		if (z == 34) {
			for (int i = 0; i < 7; i++) {
				www[i] = truePass4[i];
			}
		}
		end = clock();
		double time = (double)(end - start) / CLOCKS_PER_SEC;
		if (time > 10) {
			exit(-1);
		}

		return(z);
	}
	





SOCKET Connection;
void ClientHandler() {				//функция для принятия отправленного сервером сообщения, работает в отдельном потоке
	int msg_size;						//хранение размера строки
	while (true) {                  //принимаем сообщения от сервера и выводим их на экран
		int error = recv(Connection, (char*)&msg_size, sizeof(int), NULL);    //принимаем размер сообщения
		if (error == SOCKET_ERROR) {
			cout << "Lost connecting with the server" << endl;
			Sleep(3000);
			exit(-1);
		}
		char *msg = new char[msg_size + 1];					//создаем динамический массив
		msg[msg_size] = '\0';
		recv(Connection, msg, msg_size, NULL);					//принимаем сообщение
		cout << msg << endl;
		delete[] msg;													//освобождаем память
	}
}


int main(int argc, char* argv[]) {
	setlocale(LC_ALL, "Russian");
	int qa =  checkLicense();

	if (IsDebuggerPresent()) {
		exit(-1);
	}

	CheckRemoteDebuggerPresent();
	trapFlag();
	
	if (qa != 1) {
		cout << "Лицензионный файл неверен или отсутствует" << endl;
		Sleep(3000);
		exit(-1);
	}

	bool pass = false;

	for (int i = 4; i > 0; i--) {
		time_t start, end;
		start = clock();
		cout << "Введите пароль, у вас есть на это 30 секунд" << endl;
		char *in = new char[5];
		cin >> in;
		end = clock();
		double ztime = (double)(end - start) / CLOCKS_PER_SEC;
		if (ztime > 30) {
			cout << "Вы вводили пароль слишком долго, программа будет закрыта." << endl;
			Sleep(10000);
			exit(-1);
		}
		char out[33];
		GetMD5(in, strlen(in), out);

		int qw = checkPass(out);
		if (qw == 43) {
			cout << "Пароль введен верно" << endl;
			pass = true;
			break;
		}
		else {
			cout << "Пароль введен неверно, у вас есть еще: " << i - 1 << " попытки" << endl;
		}

	}
	if (pass == false) {
		exit(-1);
	}
	else {

		WSAData wsaData;
		WORD DLLVersion = MAKEWORD(2, 1);
		if (WSAStartup(DLLVersion, &wsaData) != 0) {
			cout << "Error" << endl;
			exit(1);
		}

		SOCKADDR_IN addr;										//
		int sizeofaddr = sizeof(addr);                         //
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");          //   Информация об адресе сокета, копируется из сервера
		addr.sin_port = htons(1234);                            //
		addr.sin_family = AF_INET;                              //



		//создаем новый сокет для соединения с сервером
		Connection = socket(AF_INET, SOCK_STREAM, NULL);             //создаем новый сокет для соединения с сервером
		if (connect(Connection, (SOCKADDR*)&addr, sizeof(addr)) != 0) {     //пытаемся присоединиться к серверу и проверка, удалось ли клиенту соединиться с сервом
			cout << "Error: failed connect to server.\n";
			Sleep(3000);
			return 1;
		}


		
			while (true) {

				string nick;
				cout << "Enter nickname" << endl;

				getline(cin, nick);

				int nick_size = nick.size();
				send(Connection, (char*)&nick_size, sizeof(int), NULL);
				send(Connection, nick.c_str(), nick_size, NULL);

				CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ClientHandler, NULL, NULL, NULL); //создаем поток для принятия сообщений от сервера

				while (true) {
					string msg1;  	//считываем написанные пользователем символы, записываем в переменную

					getline(cin, msg1);

					int msg_size = msg1.size();								//записываем размер сообщения
					send(Connection, (char*)&msg_size, sizeof(int), NULL);   //отправляем размер сообщения на сервер.
					send(Connection, msg1.c_str(), msg_size, NULL);				//отправляем сообщение			
					Sleep(10);
				}
			}
			system("pause");
			return 0;
		}
	}

