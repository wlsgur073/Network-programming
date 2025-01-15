#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")

DWORD WINAPI ThreadReceive(LPVOID pParam)
{
	SOCKET hSocket = (SOCKET)pParam;
	char szBuffer[128] = { 0 };
	while (::recv(hSocket, szBuffer, sizeof(szBuffer), 0) > 0)
	{
		printf("-> %s\n", szBuffer);
		memset(szBuffer, 0, sizeof(szBuffer));
	}

	puts("수신 스레드가 끝났습니다.");
	return 0;
}

int main()
{
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		puts("ERROR: Failed to initialize WinSock.");
		return 0;
	}

	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET)
	{
		puts("ERROR: Failed to create socket.");
		return 0;
	}

	SOCKADDR_IN	svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	svraddr.sin_port = htons(25000);
	inet_pton(AF_INET, "192.168.81.128", // setup VMware IP
		&svraddr.sin_addr.S_un.S_addr);
	//svraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	if (::connect(hSocket,
		(SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR)
	{
		puts("ERROR: Failed to connect server");
		return 0;
	}

	DWORD dwThreadID = 0;
	HANDLE hThread = ::CreateThread(NULL,
		0,
		ThreadReceive,
		(LPVOID)hSocket,
		0,
		&dwThreadID);
	::CloseHandle(hThread);

	//채팅 메시지 송신
	char szBuffer[128];
	puts("채팅을 시작합니다. 메시지를 입력하세요.");
	while (1)
	{
		//사용자로부터 문자열을 입력 받는다.
		memset(szBuffer, 0, sizeof(szBuffer));
		gets_s(szBuffer);
		if (strcmp(szBuffer, "EXIT") == 0)		break;

		//사용자가 입력한 문자열을 서버에 전송한다.
		::send(hSocket, szBuffer, (int)strlen(szBuffer) + 1, 0);
	}

	::closesocket(hSocket);
	::Sleep(100);
	::WSACleanup();
}
