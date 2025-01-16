#include <stdio.h>
#include <ws2tcpip.h>

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

void ErrorHandler(const char* pszMessage)
{
	printf("ERROR: %s\n", pszMessage);
	::WSACleanup();
	exit(1);
}

int main()
{
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		ErrorHandler("Failed to initialize Winsock.");

	SOCKET hSocket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (hSocket == INVALID_SOCKET)
		ErrorHandler("Failed to create UDP socket.");

	char szBuffer[128];
	SOCKADDR_IN	remoteaddr = { 0 };
	remoteaddr.sin_family = AF_INET;
	remoteaddr.sin_port = htons(26001);
	inet_pton(AF_INET, "192.168.81.128", &remoteaddr.sin_addr.S_un.S_addr);

	while (1)
	{
		memset(szBuffer, 0, sizeof(szBuffer));
		gets_s(szBuffer, sizeof(szBuffer));
		if (strcmp(szBuffer, "exit") == 0)
			break;

		::sendto(hSocket, szBuffer, (int)strlen(szBuffer) + 1, 0,
			(sockaddr*)&remoteaddr, sizeof(remoteaddr));
	}

	::closesocket(hSocket);
	::WSACleanup();
	return 0;
}
