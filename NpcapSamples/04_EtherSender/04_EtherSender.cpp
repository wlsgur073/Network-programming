#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;
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
	// Broadcast
	pEtherHeader->dstMac[0] = 0xFF; pEtherHeader->dstMac[1] = 0xFF;
	pEtherHeader->dstMac[2] = 0xFF; pEtherHeader->dstMac[3] = 0xFF;
	pEtherHeader->dstMac[4] = 0xFF; pEtherHeader->dstMac[5] = 0xFF;

	// Unicast
	/*pEtherHeader->dstMac[0] = 0x00;
	pEtherHeader->dstMac[1] = 0x0C;
	pEtherHeader->dstMac[2] = 0x29;
	pEtherHeader->dstMac[3] = 0x3A;
	pEtherHeader->dstMac[4] = 0x62;
	pEtherHeader->dstMac[5] = 0xBA;*/
	pEtherHeader->type = 0x0000; // unsual type
	char *pData = (char*)frameData + sizeof(EtherHeader);
	char szInput[1024] = { 0 };

	while (1)
	{
		// init buffer
		memset(pData, 0, 1514 - sizeof(EtherHeader));
		memset(szInput, 0, sizeof(szInput));
		printf("Message: ");
		gets_s(szInput, sizeof(szInput));

		if (strcmp(szInput, "exit") == 0)
			break;

		msgSize = strlen(szInput);
		strcpy_s(pData, msgSize + 1, szInput);

		/* Send down the packet */
		if (pcap_sendpacket(adhandle,	// Adapter
			frameData, // buffer with the packet
			sizeof(EtherHeader) + msgSize // size
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
			break;
		}
	}

	pcap_close(adhandle);
	return 0;
}
