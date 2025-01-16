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

	// create a UDP socket
	SOCKET hSocket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (hSocket == INVALID_SOCKET)
		ErrorHandler("Failed to create UDP socket.");

	char szBuffer[128] = { 0 };
	SOCKADDR_IN	addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = htons(26001);
	addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	if (::bind(hSocket,
		(SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
		ErrorHandler("Failed to bind.");

	char szIp[128];
	SOCKADDR_IN	remoteaddr;
	int nLenSock = sizeof(remoteaddr), nResult;

	// wait for incoming data
	while ((nResult = ::recvfrom(hSocket, szBuffer, sizeof(szBuffer), 0,
		(sockaddr*)&remoteaddr, &nLenSock)) > 0)
	{
		inet_ntop(AF_INET, &remoteaddr.sin_addr, szIp, sizeof(szIp));
		printf("%s: %s\n", szIp, szBuffer);
		memset(szBuffer, 0, sizeof(szBuffer));
	}

	::closesocket(hSocket);
	::WSACleanup();
	return 0;
}
