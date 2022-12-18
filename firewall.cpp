#include "Header.h"

int main() {
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(console, White);

	if (!init()) return 1;
	system("cls");
	UI();

	this_thread::sleep_for(chrono::seconds(3));
	thread thSocket(socket_);
	thread thFirewall(firewall);

	while (1) {
		int key = toupper(_getch());
		switch (key) {
		case 'L':
			log_mode = false;
			system("cls");
			legend();
			while (toupper(_getch()) != 'L');
			system("cls");
			log_mode = true;
			break;
		case 'Q':
			log_mode = false;
			system("cls");
			winfw(true);
			cout << endl << endl << "\tWindows firewall on." << endl << endl;
			exit(0);
		}
	}
}

// win firewall on/off
HRESULT wfCoInit(INetFwPolicy2** NetFwPolicy)
{
	HRESULT hr = S_OK;
	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)NetFwPolicy);
	return hr;
}
void winfw(bool enable)
{
	static VARIANT_BOOL fw_domain, fw_private, fw_public;
	HRESULT hrCoInit = S_OK, hr = S_OK;
	INetFwPolicy2* NetFwPolicy = NULL;

	hrCoInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	hr = wfCoInit(&NetFwPolicy);

	if (!FAILED(hrCoInit)) {
		if (!FAILED(hr)) {
			if (enable) {
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, fw_domain);
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, fw_private);
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, fw_public);
			}
			else {
				NetFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &fw_domain);
				NetFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &fw_private);
				NetFwPolicy->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &fw_public);
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, FALSE);
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, FALSE);
				hr = NetFwPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, FALSE);
			}
		}
	}

	if (NetFwPolicy != NULL) { NetFwPolicy->Release(); }
	if (SUCCEEDED(hrCoInit)) { CoUninitialize(); }
}

// format of ip
string IP_format(string ip)
{
	if (ip.compare("::") == 0) { return "  0.  0.  0.  0"; }
	else {
		char point = '.';
		vector<string> octets;
		string arg = "";

		for (string::size_type i = 0; i < ip.size(); i++) {
			char temp = ip[i];
			if (temp == point && arg.compare("") != 0) { octets.push_back(arg); arg = ""; }
			else { arg.push_back(temp); }
		}
		if (arg.compare("") != 0) { octets.push_back(arg); arg = ""; }

		if (octets.size() == 4) {
			octets[0].insert(0, 3 - octets[0].length(), ' ');
			octets[1].insert(0, 3 - octets[1].length(), ' ');
			octets[2].insert(0, 3 - octets[2].length(), ' ');
			octets[3].insert(0, 3 - octets[3].length(), ' ');
			return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
		}
		else { return ip; }
	}
}

// process
string processById(DWORD id)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, id);
	DWORD path_word = 0;
	string process_name = "";
	char path[MAX_PATH + 1];

	if (process != NULL) {
		path_word = GetProcessImageFileNameA(process, path, sizeof(path));
		CloseHandle(process);
	}
	if (path_word != 0) {
		char* process_name_ = PathFindFileNameA(path);
		process_name = string(process_name_);
	}
	else if (id == 4) { process_name = "System"; }
	else { process_name = "pid=" + to_string(id); }

	return process_name;
}
string processByPort(string protocol, string ip, string port)
{
	string cortege1 = protocol + " " + ip + ":" + port;
	string cortege2 = protocol + " 0.0.0.0:" + port;
	string process = "";

	mtx_processByPort.lock();
	if (processByPort_.find(cortege1) != processByPort_.cend()) { process = processByPort_[cortege1]; }
	else if (processByPort_.find(cortege2) != processByPort_.cend()) { process = processByPort_[cortege2]; }
	mtx_processByPort.unlock();

	return process;
}

// packet init
static void PacketIpInit(PWINDIVERT_IPHDR packet) {
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}
static void PacketIpTcpInit(PTCPPACKET packet) {
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
static void PacketIpIcmpInit(PICMPPACKET packet) {
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet) {
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}
static void PacketIpv6TcpInit(PTCPV6PACKET packet) {
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet) {
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}

bool init() {
	cout << endl << endl << "\tOpen socket handle - ";
	s_handle = WinDivertOpen("true", WINDIVERT_LAYER_SOCKET, 1, WINDIVERT_FLAG_SNIFF + WINDIVERT_FLAG_READ_ONLY);
	if (s_handle == INVALID_HANDLE_VALUE) { cout << "Error: " << GetLastError() << endl; return false; }
	cout << "yes" << endl << endl;

	cout << "\tOpen network handle - ";
	n_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (n_handle == INVALID_HANDLE_VALUE) { cout << "Error: " << GetLastError() << endl; return false; }
	cout << "yes" << endl << endl;

	winfw(false);
	cout << "\tWindows firewall - off" << endl;

	// Initialize all packets.
	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketIpIcmpInit(dnr);
	dnr->icmp.Type = 3;
	dnr->icmp.Code = 3;
	PacketIpv6TcpInit(resetv6);
	resetv6->tcp.Rst = 1;
	resetv6->tcp.Ack = 1;
	PacketIpv6Icmpv6Init(dnrv6);
	dnrv6->ipv6.Length = htons(sizeof(WINDIVERT_ICMPV6HDR) + 4 + sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR));
	dnrv6->icmpv6.Type = 1;
	dnrv6->icmpv6.Code = 4;

	return true;
}

void UI() {
	cout << endl << "\tThe program will start after 3 seconds." << endl << endl;
	cout << "Press:" << endl
		<< "   [Q] for quit" << endl
		<< "   [L] for legend" << endl << endl;
}
void legend() {
	//cout << "protocol      local ip:port       direction       remote ip:port        process" << endl;
	//cout << "UDP/TCP   255.255.255.255:00000      <->       255.255.255.255:00000   chrome.exe" << endl;

	SetConsoleTextAttribute(console, White);
	cout << "Press:" << endl
		<< "   [Q] for quit" << endl
		<< "   [L] for legend" << endl << endl;

	cout << "protocol      local ip:port       direction       remote ip:port        process" << endl;
	SetConsoleTextAttribute(console, DarkBlue); cout << "UDP";
	SetConsoleTextAttribute(console, White); cout << "/";
	SetConsoleTextAttribute(console, Yellow); cout << "TCP";
	SetConsoleTextAttribute(console, White); cout << "   255.255.255.255:00000";
	SetConsoleTextAttribute(console, Red); cout << setw(7) << "<-";
	SetConsoleTextAttribute(console, Green); cout << " ->";
	SetConsoleTextAttribute(console, White);
	cout << setw(6) << " " << "255.255.255.255:00000   chrome.exe" << endl;

	cout << endl << left << "   Press [L] again to return" << setw(64) << endl;
}

void log(string protocol, string direction, string local_ip, string local_port,
	string remote_ip, string remote_port, string process) 
{
	if (log_mode == true) {
		mtx_console.lock();

		if (protocol == "UDP") { SetConsoleTextAttribute(console, DarkBlue); }
		else if (protocol == "TCP") { SetConsoleTextAttribute(console, Yellow); }
		else { SetConsoleTextAttribute(console, White); }
		cout << setw(3) << protocol << "   ";

		SetConsoleTextAttribute(console, White);
		cout << IP_format(local_ip) << ":" << setw(5) << local_port << "  ";

		if (direction == "<-") { SetConsoleTextAttribute(console, Red); }
		else if (direction == "->") { SetConsoleTextAttribute(console, Green); }
		else { SetConsoleTextAttribute(console, White); }
		cout << direction << "  ";

		SetConsoleTextAttribute(console, White);
		cout << IP_format(remote_ip) << ":" << setw(5) << remote_port << "   " << process << endl;

		mtx_console.unlock();
	}
}

void socket_() {
	for (ULONG i = 0; ; i++) {
		WINDIVERT_ADDRESS addr;
		if (!WinDivertRecv(s_handle, NULL, 0, NULL, &addr))	continue;
		if (addr.IPv6) continue;

		mtx_queued.lock();

		string process = processById(addr.Socket.ProcessId);
		string event, protocol, direction;

		switch (addr.Event) {
		case WINDIVERT_EVENT_SOCKET_BIND: event = "BIND"; break;
		case WINDIVERT_EVENT_SOCKET_LISTEN: event = "LISTEN"; break;
		case WINDIVERT_EVENT_SOCKET_CONNECT: event = "CONNECT"; break;
		case WINDIVERT_EVENT_SOCKET_ACCEPT: event = "ACCEPT"; break;
		case WINDIVERT_EVENT_SOCKET_CLOSE: event = "CLOSE"; break;
		default: event = ""; break;
		}

		switch (addr.Socket.Protocol) {
		case IPPROTO_TCP: protocol = "TCP"; break;
		case IPPROTO_UDP: protocol = "UDP"; break;
		case IPPROTO_ICMP: protocol = "ICMP"; break;
		case IPPROTO_ICMPV6: protocol = "ICMPV6"; break;
		default: protocol = to_string(addr.Socket.Protocol); break;
		}

		if (addr.Outbound) { direction = "->"; }
		else { direction = "<-"; }

		char local_str[INET6_ADDRSTRLEN + 1], remote_str[INET6_ADDRSTRLEN + 1];

		WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str, sizeof(local_str));
		WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str, sizeof(remote_str));

		string local_ip = string(local_str);
		if (local_ip.compare("::") == 0) { local_ip = "0.0.0.0"; }
		string local_port = to_string(addr.Socket.LocalPort);

		string remote_ip = string(remote_str);
		if (remote_ip.compare("::") == 0) { remote_ip = "0.0.0.0"; }
		string remote_port = to_string(addr.Socket.RemotePort);

		if (event.compare("BIND") == 0 || (addr.Loopback && event.compare("CONNECT") == 0)) {
			mtx_processByPort.lock();
			processByPort_[protocol + " " + local_ip + ":" + local_port] = process;
			mtx_processByPort.unlock();
		}
		else if (event.compare("CLOSE") == 0 && remote_ip.compare("0.0.0.0") == 0 && remote_port.compare("0") == 0) {
			mtx_processByPort.lock();
			processByPort_.erase(protocol + " " + local_ip + ":" + local_port);
			mtx_processByPort.unlock();
		}
		mtx_queued.unlock();
	}
}
void firewall() {
	WINDIVERT_ADDRESS address, address_; // Packet address
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	PVOID payload;
	UINT payload_len;
	string protocol, direction, src_ip, src_port, dst_ip, dst_port;
	char packet[MAXBUF];    // Packet buffer
	char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];

	for (ULONG i = 0; ; i++) {
		if (!WinDivertRecv(n_handle, packet, sizeof(packet), &packet_len, &address)) { continue; }

		mtx_queued.lock();

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL, &icmp_header,
			&icmpv6_header, &tcp_header, &udp_header, &payload, &payload_len, NULL, NULL);

		if (ip_header == NULL || (tcp_header == NULL && udp_header == NULL)) { goto end; }

		WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
		WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));

		src_ip = string(src_str);
		dst_ip = string(dst_str);

		if (tcp_header != NULL) {
			protocol = "TCP";
			src_port = to_string(ntohs(tcp_header->SrcPort));
			dst_port = to_string(ntohs(tcp_header->DstPort));
		}
		else if (udp_header != NULL) {
			protocol = "UDP";
			src_port = to_string(ntohs(udp_header->SrcPort));
			dst_port = to_string(ntohs(udp_header->DstPort));
		}

		bool accept;
		bool reject;

		if (address.Loopback) {
			string client_process = processByPort(protocol, src_ip, src_port);
			string server_process = processByPort(protocol, dst_ip, dst_port);

			log(protocol, "->", src_ip, src_port, dst_ip, dst_port, client_process);
			log(protocol, "<-", dst_ip, dst_port, src_ip, src_port, server_process);

			if (client_process != "chrome.exe" && server_process != "chrome.exe") { reject = true; accept = false; }
			else { reject = false; accept = true; }
		}
		else if (address.Outbound) {
			string client_process = processByPort(protocol, src_ip, src_port);
			log(protocol, "->", src_ip, src_port, dst_ip, dst_port, client_process);

			if (client_process != "chrome.exe") { reject = true; accept = false; }
			else { reject = false; accept = true; }
		}
		else {
			string server_process = processByPort(protocol, dst_ip, dst_port);
			log(protocol, "<-", src_ip, src_port, dst_ip, dst_port, server_process);

			if (server_process != "chrome.exe") { reject = true; accept = false; }
			else { reject = false; accept = true; }
		}

		if (accept) { WinDivertSend(n_handle, packet, packet_len, NULL, &address); }

		if (reject && tcp_header != NULL) {
			reset->ip.SrcAddr = ip_header->DstAddr;
			reset->ip.DstAddr = ip_header->SrcAddr;
			reset->tcp.SrcPort = tcp_header->DstPort;
			reset->tcp.DstPort = tcp_header->SrcPort;
			reset->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
			reset->tcp.AckNum =
				(tcp_header->Syn ? htonl(ntohl(tcp_header->SeqNum) + 1) : htonl(ntohl(tcp_header->SeqNum) + payload_len));

			memcpy(&address_, &address, sizeof(address_));
			address_.Outbound = !address.Outbound;
			WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET), &address_, 0);
			WinDivertSend(n_handle, (PVOID)reset, sizeof(TCPPACKET), NULL, &address_);
		}
		else if (reject && udp_header != NULL) {
			UINT icmp_length = ip_header->HdrLength * sizeof(UINT32) + 8;
			memcpy(dnr->data, ip_header, icmp_length);
			icmp_length += sizeof(ICMPPACKET);
			dnr->ip.Length = htons((UINT16)icmp_length);
			dnr->ip.SrcAddr = ip_header->DstAddr;
			dnr->ip.DstAddr = ip_header->SrcAddr;

			memcpy(&address_, &address, sizeof(address_));
			address_.Outbound = !address.Outbound;
			WinDivertHelperCalcChecksums((PVOID)dnr, icmp_length, &address_, 0);
			WinDivertSend(n_handle, (PVOID)dnr, icmp_length, NULL, &address_);
		}

	end:
		mtx_queued.unlock();
	}
}