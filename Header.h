#pragma once

#include <iostream>
#include <string>
#include <iomanip> //setw
#include <mutex>
#include <unordered_map>
#include <winsock2.h>
#include <psapi.h>   //process id//
#include <shlwapi.h> //			 //
#include <netfw.h>
#include <conio.h> //_getch
#include "windivert.h"

using namespace std;

#define ntohs(x) WinDivertHelperNtohs(x)
#define ntohl(x) WinDivertHelperNtohl(x)
#define htons(x) WinDivertHelperHtons(x)
#define htonl(x) WinDivertHelperHtonl(x)

#define MAXBUF 65536
#define INET6_ADDRSTRLEN 45

bool log_mode = true;

unordered_map<string, string> processByPort_ = {};

HANDLE s_handle;
HANDLE n_handle;
HANDLE console;

mutex mtx_sockets;
mutex mtx_processByPort;
mutex mtx_console;
mutex mtx_queued;

typedef struct {
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, * PTCPPACKET;
typedef struct {
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, * PTCPV6PACKET;
typedef struct {
	WINDIVERT_IPHDR ip;
	WINDIVERT_ICMPHDR icmp;
	UINT8 data[];
} ICMPPACKET, * PICMPPACKET;
typedef struct {
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_ICMPV6HDR icmpv6;
	UINT8 data[];
} ICMPV6PACKET, * PICMPV6PACKET;

TCPPACKET reset0;
PTCPPACKET reset = &reset0;
UINT8 dnr0[sizeof(ICMPPACKET) + 0x0F * sizeof(UINT32) + 8 + 1];
PICMPPACKET dnr = (PICMPPACKET)dnr0;

TCPV6PACKET resetv6_0;
PTCPV6PACKET resetv6 = &resetv6_0;
UINT8 dnrv6_0[sizeof(ICMPV6PACKET) + sizeof(WINDIVERT_IPV6HDR) +
sizeof(WINDIVERT_TCPHDR)];
PICMPV6PACKET dnrv6 = (PICMPV6PACKET)dnrv6_0;

enum consoleColor {
	DarkBlue = 9,
	Green = 10,
	LightBlue = 11,
	Red = 12,
	Purple = 13,
	Yellow = 14,
	White = 15
};

void winfw(bool enable);
bool init();
void UI();
void legend();
void socket_();
void firewall();