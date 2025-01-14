#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

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
#pragma pack(pop)

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


void dispatcher_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->fragOffset & htons((short)0x2000) // 0010 <-> 0DMF (M: more fragments) flag
		||
		ntohs(pIpHeader->fragOffset & (unsigned short)0xFF1F) > 0) // 1FFF <-> 0001 FFF (offset)
	{
		printf("ID: %04X, Flags: %04X, Offset: %d, Protocol: 0x%02X\n",
			ntohs(pIpHeader->id),
			ntohs(pIpHeader->fragOffset & htons((short)0xE000)),
			ntohs(pIpHeader->fragOffset & (unsigned short)0xFF1F) * 8, // you can use htons()
			pIpHeader->protocol);

		printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
			pIpHeader->srcIp[0], pIpHeader->srcIp[1],
			pIpHeader->srcIp[2], pIpHeader->srcIp[3],
			pIpHeader->dstIp[0], pIpHeader->dstIp[1],
			pIpHeader->dstIp[2], pIpHeader->dstIp[3]
		);

		printf("\n");
	}
}

int main(int argc, char** argv)
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Open the capture file */
	if ((fp = pcap_open_offline(
		"C:\\SampleTraces\\ip-fragments.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"C:\\SampleTraces\\ip-fragments.pcap");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	pcap_close(fp);
	return 0;
}
