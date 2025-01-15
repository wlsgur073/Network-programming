#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")

#include <windows.h>
#include <list>
#include <iterator>

/////////////////////////////////////////////////////////////////////////
CRITICAL_SECTION	g_cs;			//스레드 동기화 객체.
SOCKET				g_hSocket;		//서버의 리슨 소켓.
std::list<SOCKET>	g_listClient;	//연결된 클라이언트 소켓 리스트.

/////////////////////////////////////////////////////////////////////////
//새로 연결된 클라이언트의 소켓을 리스트에 저장한다.
BOOL AddUser(SOCKET hSocket)
{
	::EnterCriticalSection(&g_cs);		//임계영역 시작
	//※ 이 코드는 오직 한 스레드만 수행한다는 것이 보장된다!
	g_listClient.push_back(hSocket);
	::LeaveCriticalSection(&g_cs);		//임계영역 끝

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////
//연결된 클라이언트 모두에게 메시지를 전송한다.
void SendChattingMessage(char* pszParam)
{
	int nLength = (int)strlen(pszParam);
	std::list<SOCKET>::iterator it;

	::EnterCriticalSection(&g_cs);		//임계영역 시작
	//연결된 모든 클라이언트들에게 같은 메시지를 전달한다.
	for (it = g_listClient.begin(); it != g_listClient.end(); ++it)
		::send(*it, pszParam, sizeof(char) * (nLength + 1), 0);
	::LeaveCriticalSection(&g_cs);		//임계영역 끝
}

/////////////////////////////////////////////////////////////////////////
//Ctrl+C 이벤트를 감지하고 프로그램을 종료한다.
BOOL CtrlHandler(DWORD dwType)
{
	if (dwType == CTRL_C_EVENT)
	{
		std::list<SOCKET>::iterator it;

		//연결된 모든 클라이언트 및 리슨 소켓을 닫고 프로그램을 종료한다.
		::shutdown(g_hSocket, SD_BOTH);

		::EnterCriticalSection(&g_cs);		//임계영역 시작
		for (it = g_listClient.begin(); it != g_listClient.end(); ++it)
			::closesocket(*it);
		//연결 리스트에 등록된 모든 정보를 삭제한다.
		g_listClient.clear();
		::LeaveCriticalSection(&g_cs);		//임계영역 끝

		puts("All sessions are closed.");
		//클라이언트와 통신하는 스레드들이 종료되기를 기다린다.
		::Sleep(100);
		::DeleteCriticalSection(&g_cs);
		::closesocket(g_hSocket);

		//윈속 해제
		::WSACleanup();
		exit(0);
		return TRUE;
	}

	return FALSE;
}

/////////////////////////////////////////////////////////////////////////
//클라이언트에게 채팅 메시지 서비스를 제공하는 스레드 함수.
//연결된 각각의 클라이언트마다 한 스레드가 생성된다.
DWORD WINAPI ThreadFunction(LPVOID pParam)
{
	char szBuffer[128] = { 0 };
	int nReceive = 0;
	SOCKET hClient = (SOCKET)pParam;
	char szIp[128];

	struct sockaddr_in remoteAddr;
	socklen_t addrLen = sizeof(remoteAddr);
	getpeername(hClient, (struct sockaddr*)&remoteAddr, &addrLen);
	inet_ntop(AF_INET, &remoteAddr.sin_addr, szIp, sizeof(szIp));

	puts("***New client***");
	while ((nReceive = ::recv(hClient,
		szBuffer, sizeof(szBuffer), 0)) > 0)
	{
		printf("%s: %s\n", szIp, szBuffer);
		//수신한 문자열을 연결된 전체 클라이언트들에게 전송
		SendChattingMessage(szBuffer);
		memset(szBuffer, 0, sizeof(szBuffer));
	}

	puts("Closed by client");
	::EnterCriticalSection(&g_cs);		//임계영역 시작
	g_listClient.remove(hClient);
	::LeaveCriticalSection(&g_cs);		//임계영역 끝

	::closesocket(hClient);
	return 0;
}

int main()
{
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		puts("ERROR: 윈속을 초기화 할 수 없습니다.");
		return 0;
	}

	::InitializeCriticalSection(&g_cs);

	if (::SetConsoleCtrlHandler(
		(PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE)
		puts("ERROR: Ctrl+C 처리기를 등록할 수 없습니다.");

	g_hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (g_hSocket == INVALID_SOCKET)
	{
		puts("ERROR: 접속 대기 소켓을 생성할 수 없습니다.");
		return 0;
	}

	SOCKADDR_IN	svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	svraddr.sin_port = htons(25000);
	svraddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	if (::bind(g_hSocket,
		(SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR)
	{
		puts("ERROR: 소켓에 IP주소와 포트를 바인드 할 수 없습니다.");
		return 0;
	}

	if (::listen(g_hSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		puts("ERROR: 리슨 상태로 전환할 수 없습니다.");
		return 0;
	}
	puts("*** The server has started. ***");

	//클라이언트 접속 처리 및 대응
	SOCKADDR_IN clientaddr = { 0 };
	int nAddrLen = sizeof(clientaddr);
	SOCKET hClient = 0;
	DWORD dwThreadID = 0;
	HANDLE hThread;

	//클라이언트 연결을 받아들이고 새로운 소켓 생성(개방)
	while ((hClient = ::accept(g_hSocket,
		(SOCKADDR*)&clientaddr, &nAddrLen)) != INVALID_SOCKET)
	{
		if (AddUser(hClient) == FALSE)
		{
			puts("ERROR: 더 이상 클라이언트 연결을 처리할 수 없습니다.");
			CtrlHandler(CTRL_C_EVENT);
			break;
		}

		//클라이언트로부터 문자열을 수신함.
		hThread = ::CreateThread(NULL,	//보안속성 상속
			0,				//스택 메모리는 기본크기(1MB)
			ThreadFunction,	//스래드로 실행할 함수이름
			(LPVOID)hClient,	//새로 생성된 클라이언트 소켓
			0,				//생성 플래그는 기본값 사용
			&dwThreadID);	//생성된 스레드ID가 저장될 변수주소

		::CloseHandle(hThread);
	}

	puts("*** The server has shutdown. ***");
	return 0;
}