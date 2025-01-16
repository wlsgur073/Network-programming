#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")


#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct UdpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short length;
	unsigned short checksum;
} UdpHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;
	unsigned int dstIp;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
} PseudoHeader;
#pragma pack(pop)

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	for (int i = 0; i < ihl / 2; i++)
	{
		if (i != 5)
			dwSum += wData[i];

		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return ~(dwSum & 0x0000FFFF);
}

unsigned short CalcChecksumUdp(IpHeader* pIpHeader, UdpHeader* pUdpHeader)
{
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pUdpHeader;
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nDatagramSize = 0; //헤더 포함 데이터그램 크기

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;


	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 17;
	pseudoHeader.length = pUdpHeader->length;

	nDatagramSize = ntohs(pseudoHeader.length);

	if (nDatagramSize % 2)
		nLengthOfArray = nDatagramSize / 2 + 1;
	else
		nLengthOfArray = nDatagramSize / 2;

	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	//((UdpHeader*)wData)->checksum = 0x0000;
	for (int i = 0; i < nLengthOfArray; i++)
	{
		if (i != 3)
			dwSum += pwDatagram[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return (USHORT)~(dwSum & 0x0000FFFF);
}


int main(int argc, char** argv)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
		//fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
		return 2;
	}

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d%*c", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	printf("[Ethernet message sender]\n");


	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,		// name of the device
			0, // portion of the packet to capture. 0 == no capture.
			0, // non-promiscuous mode
			1000,			// read timeout
			errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
	}

	pcap_freealldevs(alldevs);

	unsigned char frameData[1514] = { 0 };
	int msgSize = 0;
	EtherHeader* pEtherHeader = (EtherHeader*)frameData;

	// setup dst MAC address, must match the receiver exactly.
	pEtherHeader->dstMac[0] = 0x00; pEtherHeader->dstMac[1] = 0x0C;
	pEtherHeader->dstMac[2] = 0x29; pEtherHeader->dstMac[3] = 0x3A;
	pEtherHeader->dstMac[4] = 0x62; pEtherHeader->dstMac[5] = 0xBA;

	pEtherHeader->srcMac[0] = 0x00; pEtherHeader->srcMac[1] = 0x50;
	pEtherHeader->srcMac[2] = 0x56; pEtherHeader->srcMac[3] = 0xC0;
	pEtherHeader->srcMac[4] = 0x00; pEtherHeader->srcMac[5] = 0x08;

	pEtherHeader->type = 0x0008;

	// setup IP header
	IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
	pIpHeader->verIhl = 0x45;
	pIpHeader->tos = 0x00;
	pIpHeader->length = 0;
	pIpHeader->id = 0x3412;
	pIpHeader->fragOffset = 0x0040; //DF
	pIpHeader->ttl = 0xFF;
	pIpHeader->protocol = 17; // UDP
	pIpHeader->checksum = 0x0000;

	// send custom IP address to the receiver
	pIpHeader->srcIp[0] = 3;
	pIpHeader->srcIp[1] = 3;
	pIpHeader->srcIp[2] = 3;
	pIpHeader->srcIp[3] = 3;

	// setup IP header
	pIpHeader->dstIp[0] = 192;
	pIpHeader->dstIp[1] = 168;
	pIpHeader->dstIp[2] = 81;
	pIpHeader->dstIp[3] = 128;

	int ipHeaderLen = 20;
	UdpHeader* pUdpHeader =
		(UdpHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

	pUdpHeader->srcPort = htons(26780); // is it real port number? Receiver don't know.
	pUdpHeader->dstPort = htons(26001);
	pUdpHeader->length = 0;
	pUdpHeader->checksum = 0x0000;


	char szInput[1024];
	char *pPayload = (char*)(frameData + sizeof(EtherHeader) +
		ipHeaderLen + sizeof(UdpHeader));
	while (1)
	{
		memset(szInput, 0, sizeof(szInput));
		printf("Message: ");
		gets_s(szInput, sizeof(szInput));
		if (strcmp(szInput, "exit") == 0)
			break;

		msgSize = (int)strlen(szInput);
		strcpy_s(pPayload, msgSize + 1, szInput);

		pUdpHeader->length = htons(
			(unsigned short)sizeof(UdpHeader) + msgSize);
		pIpHeader->length = htons(
			(unsigned short)(sizeof(IpHeader) +
				sizeof(UdpHeader) + msgSize));

		pIpHeader->checksum = CalcChecksumIp(pIpHeader);
		pUdpHeader->checksum = CalcChecksumUdp(pIpHeader, pUdpHeader);

		/* Send down the packet */
		if (pcap_sendpacket(adhandle,	// Adapter
			frameData, // buffer with the packet
			sizeof(EtherHeader) + sizeof(IpHeader) +
			sizeof(UdpHeader) + msgSize // size
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
			break;
		}
	}

	pcap_close(adhandle);
	return 0;
}
