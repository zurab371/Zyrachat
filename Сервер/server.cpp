#include "pch.h"
#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <string>


using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)


SOCKET sockets[100];   // массив сокетов для хранения всех соединений
string nicknames[100];
int numberOfSocket = 0;           // переменная, которая хранит индекс соединения


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


void ClientHandler(int index) {          //принимаем индекс соединения в сокет массиве(индекс клиента)
	cout << "User with nickname: " << nicknames[index] << " connect to the server" << endl;
	int msg_size;							//переменная для хранения размера сообщения, которое будет отправлено от клиента
	while (true) {							//бесконечный цикл, в котором принимаются и отправляются сообщения клиентов
		int error = recv(sockets[index], (char*)&msg_size, sizeof(int), NULL);   //принимаем размер сообщения, которое поступит от клиента
		if (error == SOCKET_ERROR) {
			cout << "User with nickname: "<<nicknames[index]<< " disconnect from the server" << endl;
			break;
		}
		char *msg = new char[msg_size + 1];							//динамическое выделение памяти
		msg[msg_size] = '\0';

		recv(sockets[index], msg, msg_size, NULL);			//принимаем сообщение от клиента, отправившего его

		string out = nicknames[index] + ": " + msg;

		cout << out << endl;

		msg_size = out.size();

		for (int i = 0; i < numberOfSocket; i++) {					//рассылаем сообщение всем, кроме отправителя
			if (i == index) {
				continue;
			}
			send(sockets[i], (char*)&msg_size, sizeof(int), NULL);			//отправляем размер сообщения
			send(sockets[i], out.c_str(), msg_size, NULL);							//отправляем сообщение
		}
		delete[] msg;											//освобождение памяти после динамического выделения
	}
	closesocket(sockets[index]);
}


int main(int argc, char* argv[])
{

	if (IsDebuggerPresent()) {
		exit(-1);
	}

	CheckRemoteDebuggerPresent();
	trapFlag();

	WSAData wsaData;                     //структура
	WORD DLLVersion = MAKEWORD(2, 1);    // запрашиваемая версия библиотеки winsock

	if (WSAStartup(DLLVersion, &wsaData) != 0) {     //функция загрузки сетевой библиотеки(1-й параметр - запрашиваемая версия библиотеки
		cout << "Error" << endl;					//2-й - ссылка на структура wsaData. Далее делаем проверку на удачную загрузку библиотеки
		exit(1);									//выход из программы, если библиотека не загрузилась
	}


	//заполнение информации об адресе сокета

	SOCKADDR_IN addr;								//структура для хранения адреса
	int sizeofaddr = sizeof(addr);                  //размер структуры SOCKADDR_IN
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");    //структура для хранения ип-адреса
	addr.sin_port = htons(1234);                      // порт для идентификации программы поступающими данными
	addr.sin_family = AF_INET;						// семейство протоколов, для инет протоколов константа AF_INET


	//Чтобы 2 компа могли установить соединение, нужно прослушивание на определенном порту

	SOCKET sListen = socket(AF_INET, SOCK_STREAM, NULL);    //создаем сокет
	bind(sListen, (SOCKADDR*)&addr, sizeof(addr));       //привязываем адрес сокету(в параметрах сокет, указатель на структуру,размер структуры
	listen(sListen, SOMAXCONN);

	cout << "Server started successfully" << endl;
	cout << "IP for connecting is 127.0.0.1" << endl;
	cout << "Port for connecting is 1234" << endl;


	SOCKET newConnection;


	for(int i = 0;i<100;i++)
	{
		newConnection = accept(sListen, (SOCKADDR*)&addr, &sizeofaddr);
		sockets[i] = newConnection;
		int nick_size;

		int empty_size;
		recv(newConnection, (char*)&empty_size, sizeof(int), NULL);   //принимаем размер сообщения, которое поступит от клиента
		char *empty = new char[empty_size + 1];							//динамическое выделение памяти
		empty[empty_size] = '\0';
		recv(newConnection, empty, empty_size, NULL);			//принимаем сообщение от клиента, отправившего его


		int zzz = recv(newConnection, (char*)&nick_size, sizeof(int), NULL);   //принимаем размер сообщения, которое поступит от клиента
		if (zzz == SOCKET_ERROR) {
			continue;
		}
		char *nick = new char[nick_size + 1];							//динамическое выделение памяти
		nick[nick_size] = '\0';
		recv(newConnection, nick, nick_size, NULL);			//принимаем сообщение от клиента, отправившего его

		nicknames[i] = nick;
		delete[] nick;
		numberOfSocket++;
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ClientHandler, (LPVOID)(i), NULL, NULL);
	}
}