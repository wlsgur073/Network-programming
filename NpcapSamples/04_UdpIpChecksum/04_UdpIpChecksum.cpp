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

unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; // `<< 2` == `* 4` 와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	for (int i = 0; i < ihl / 2; i++)
	{
		if (i != 5) // location of checksum field
			dwSum += wData[i];

		if (dwSum & 0xFFFF0000) // over range of 16 bits
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return ~(dwSum & 0x0000FFFF);
}

unsigned short CalcChecksumUdp(	IpHeader* pIpHeader,
								UdpHeader* pUdpHeader)
{
	// need to virtual pseudo header
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
	pseudoHeader.length = pUdpHeader->length; // length of UDP header + data, means total length of datagram, including UDP data

	nDatagramSize = ntohs(pseudoHeader.length); // translate to host byte order

	if (nDatagramSize % 2) // calculate length of array
		nLengthOfArray = nDatagramSize / 2 + 1;
	else
		nLengthOfArray = nDatagramSize / 2;

	// calculate checksum of pseudo header
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



void dispatcher_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 17)
		return;

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;

	UdpHeader* pUdpHeader =
		(UdpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);


	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3]
	);

	printf("IP header checksum: %04X, Calculated checksum: %04X\n",
		pIpHeader->checksum, CalcChecksumIp(pIpHeader));
	printf("UDP checksum: %04X, Calculated checksum: %04X\n\n",
		pUdpHeader->checksum, CalcChecksumUdp(pIpHeader, pUdpHeader));
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
		"C:\\SampleTraces\\udp-echo.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"C:\\SampleTraces\\udp-echo.pcap");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	pcap_close(fp);
	return 0;
}
