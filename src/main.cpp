#include <chrono>
#include <iostream>
#include "pcap.h"
#include "RtmpParse.h"
//#include "RtmpParse.h"
#if defined(WIN32)
#pragma comment(lib,"Ws2_32.lib")
#endif
#if 0
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void print_devices(pcap_if_t* device)
{
	pcap_addr_t* address = nullptr;
    char ip6_address_str[128] {0};
	// print the device name and description
	std::cout << device->name << std::endl;
	if (device->description)
	{
		std::cout << " (" << device->description << ")" << std::endl;
	}
	else
	{
		std::cout << " (No description available)" << std::endl;
	}
	// is loopback address
	bool is_loopback_address = device->flags & PCAP_IF_LOOPBACK;
	std::cout << "Loopback: " << (is_loopback_address ? "yes" : "no") << std::endl;
	// IP address
	for (address = device->addresses;address != nullptr;address = address->next)
	{
		std::cout << "Address Family: #" << address->addr->sa_family << std::endl;
		switch (address->addr->sa_family)
		{
		case AF_INET:
		{
			std::cout << "Address Family Name: AF_INET" << std::endl;
			if (address->addr)
			{
				std::cout << "Address: " << inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr) << std::endl;
			}
			if (address->netmask)
			{
				std::cout << "Netmask: " << inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr) << std::endl;
			}
			if (address->broadaddr)
			{
				std::cout << "Broadcast Address: " << inet_ntoa(((struct sockaddr_in*)address->broadaddr)->sin_addr) << std::endl;
			}
			if (address->dstaddr)
			{
				std::cout << "Destination Address: " << inet_ntoa(((struct sockaddr_in*)address->dstaddr)->sin_addr) << std::endl;
			}
				
			}
			break;
		case AF_INET6:
		{
			std::cout << "Address Family Name: AF_INET6" << std::endl;
			if (address->addr)
			{
				inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->addr)->sin6_addr, ip6_address_str, sizeof(ip6_address_str));
				std::cout << "Address: " << ip6_address_str << std::endl;
			}
			//if (address->netmask)
			//{
			//	inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->netmask)->sin6_addr, ip6_address_str, sizeof(ip6_address_str));
			//	std::cout << "Netmask: " << ip6_address_str << std::endl;
			//}
			//if (address->broadaddr)
			//{
			//	inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->broadaddr)->sin6_addr, ip6_address_str, sizeof(ip6_address_str));
			//	std::cout << "Broadcast Address: " << ip6_address_str << std::endl;
			//}
			//if (address->dstaddr)
			//{
			//	inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->dstaddr)->sin6_addr, ip6_address_str, sizeof(ip6_address_str));
			//	std::cout << "Destination Address: " << ip6_address_str << std::endl;
			//}
		}
			break;
		default:
			std::cout << "Address Family Name: Unknown" << std::endl;
			break;
		}
	}

}
int main() {

    ::SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
    pcap_if_t* all_devices = nullptr;
	pcap_if_t* device = nullptr;
    int index = 0;
	char error_buffer[PCAP_ERRBUF_SIZE]{0};
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,nullptr,&all_devices,error_buffer) == -1)
    {
		std::cerr << "Error in pcap_findalldevs_ex: " << error_buffer << std::endl;
		return 1;
    }
	// Print the list
    for(device = all_devices;device != nullptr;device = device->next)
    {
		++index;
		print_devices(device);
		//std::cout << "Devices index: " << ++index << "Device: " << device->name << std::endl;
		//if(device->description)
		//{
		//	std::cout << " (" << device->description << ")" << std::endl;
		//}
		//else
		//{
		//	std::cout << " (No description available)" << std::endl;

		//}
    }
    if(index == 0)
    {
		std::cout << "No interfaces found! Make sure WinPcap is installed." << std::endl;
    }

	std::cout << "Enter the interface number (1-" << index << "): ";
	int inum = 0;
	std::cin >> inum;
	if(inum < 1 || inum > index)
	{
		std::cout << "Interface number out of range." << std::endl;
		pcap_freealldevs(all_devices);
		return 1;
	}
	// Jump to the selected adapter
	for (device = all_devices, index = 0; index < inum - 1; device = device->next, index++);

	auto dapter_handle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, error_buffer);
	if (dapter_handle == nullptr)
	{
		std::cerr << "Error in pcap_open: " << error_buffer << std::endl;
		pcap_freealldevs(all_devices);
		return 1;
	}
	DWORD netmask = 0xffffff;
	if(device->addresses)
	{
		netmask = ((struct sockaddr_in*)device->addresses->netmask)->sin_addr.S_un.S_addr;
	}
	// compile the filter
	struct bpf_program fcode;
	if (pcap_compile(dapter_handle, &fcode, "ip and udp", 1, netmask) < 0)
	{
		std::cerr << "Error in pcap_compile" << std::endl;
		pcap_freealldevs(all_devices);
		return 1;
	}
	// set the filter
	if (pcap_setfilter(dapter_handle, &fcode) < 0)
	{
		std::cerr << "Error setting the filter" << std::endl;
		pcap_freealldevs(all_devices);
		return 1;
	}
	std::cout << "Listening on: " << device->description << std::endl;
	pcap_freealldevs(all_devices);
	// pcap_loop(dapter_handle, 0, packet_handler, nullptr);

	int res = -1;
	pcap_pkthdr* header = nullptr;
	const u_char* packet = nullptr;
    while ((res = pcap_next_ex(dapter_handle,&header,&packet)) >= 0)
    {
		if (res == 0)
		{
			// timeout
			continue;
		}
		tm ltime;
		char timestr[16];
		time_t local_tv_sec;
		// convert the timestamp to readable format
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
		std::cout << timestr << "," << header->ts.tv_usec << "len: " << header->len << std::endl;
    }
    return 0;
}


void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	 tm ltime;
	 char timestr[16];
	 time_t local_tv_sec;
	 (void)user;
	 (void)packet;
	 // convert the timestamp to readable format
	 local_tv_sec = pkthdr->ts.tv_sec;
	 localtime_s(&ltime, &local_tv_sec);
	 strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	 std::cout << timestr << "," << pkthdr->ts.tv_usec << "len: " << pkthdr->len << std::endl;


}

#else
#include <vector>
#include <unordered_map>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>

// 定义IP头结构
typedef struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    u_long  saddr;
    u_long  daddr;
} IP_HEADER;

// 定义TCP头结构
typedef struct tcp_header {
    u_short sport;
    u_short dport;
    u_long  seq;
    u_long  ack_seq;
    u_short flags;
    u_short window;
    u_short crc;
    u_short urgp;
} TCP_HEADER;

enum class RTMPState {
    WAITING_FOR_HANDSHAKE,
    HANDSHAKING,
    READY_FOR_MESSAGES
};

enum class HandshakeState {
    WAITING_C0C1,
    WAITING_C2,
    COMPLETED
};

// 用于跟踪 TCP 连接的结构
struct TCPConnection {
    RTMPState rtmp_state;
    HandshakeState handshake_state;
    std::vector<uint8_t> buffer;
    uint32_t last_seq_num;
    uint32_t expected_seq_num;
};

// TCP 连接键
struct TCPConnectionKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const TCPConnectionKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
            src_port == other.src_port && dst_port == other.dst_port;
    }
};

namespace std {
    template<>
    struct hash<TCPConnectionKey> {
        std::size_t operator()(const TCPConnectionKey& k) const {
            return std::hash<std::string>()(k.src_ip) ^
                std::hash<std::string>()(k.dst_ip) ^
                std::hash<uint16_t>()(k.src_port) ^
                std::hash<uint16_t>()(k.dst_port);
        }
    };
}

std::unordered_map<TCPConnectionKey, TCPConnection> connections;

const int RTMP_HANDSHAKE_SIZE = 1536;
const int RTMP_MINIMUM_CHUNK_SIZE = 11;  // Basic header (1) + Type 0 chunk Message Header (11)

bool is_rtmp_handshake(const uint8_t* data, int len) {
    if(len > 0 && data[0] == 0x03)
    {
        return true;
    }
    return false;
}

bool handle_rtmp_handshake(TCPConnection& connection) {
    if (connection.handshake_state == HandshakeState::WAITING_C0C1) {
        if (connection.buffer.size() >= RTMP_HANDSHAKE_SIZE + 1) {
            // C0 (1 byte) + C1 (1536 bytes) received
            connection.buffer.erase(connection.buffer.begin(), connection.buffer.begin() + RTMP_HANDSHAKE_SIZE + 1);
            connection.handshake_state = HandshakeState::WAITING_C2;
            std::cout << "C0C1 received, waiting for C2" << std::endl;
        }
    }
    else if (connection.handshake_state == HandshakeState::WAITING_C2) {
        if (connection.buffer.size() >= RTMP_HANDSHAKE_SIZE) {
            // C2 (1536 bytes) received
            connection.buffer.erase(connection.buffer.begin(), connection.buffer.begin() + RTMP_HANDSHAKE_SIZE);
            connection.handshake_state = HandshakeState::COMPLETED;
            std::cout << "C2 received, handshake completed" << std::endl;
            return true;
        }
    }
    return false;
}

void analyze_tcp_flags(const TCP_HEADER* tcp_header) {
    uint16_t flags = ntohs(tcp_header->flags);
    std::cout << "TCP Flags: ";
    if (flags & 0x02) std::cout << "SYN ";
    if (flags & 0x10) std::cout << "ACK ";
    if (flags & 0x01) std::cout << "FIN ";
    if (flags & 0x04) std::cout << "RST ";
    if (flags & 0x08) std::cout << "PSH ";
    if (flags & 0x20) std::cout << "URG ";
    std::cout << std::endl;
}

std::string get_current_time() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void handle_payload(TCPConnection& connection, const u_char* payload, int payload_len) {

    //connection.buffer.insert(connection.buffer.end(), payload, payload + payload_len);
    //std::cout << "Payload length: " << payload_len << std::endl;

    // 打印前16字节的负载数据
    //std::cout << "Payload data: ";
    //for (int i = 0; i < min(16, payload_len); ++i) {
    //    printf("%02x ", payload[i]);
    //}
    std::vector<std::uint8_t> data;
	data.insert(data.end(), payload, payload + payload_len);
    if(data.size() > RTMP_MINIMUM_CHUNK_SIZE)
    {
        parseRTMPPacket(data);
    }
    //std::cout << std::endl;
    
}

void handle_rtmp_packet(TCPConnection& connection) {
    if(connection.buffer.empty()) return;
    try {
        int nsize = parseRTMPPacket(connection.buffer);
        // 假设 parseRTMPPacket 处理了整个 chunk，清除已处理的数据
		if(connection.buffer.size() >= nsize)
		{
            connection.buffer.erase(connection.buffer.begin(), connection.buffer.begin() + nsize);
		}
    }
    catch (const std::runtime_error& e) {
        // 如果解析失败，可能是数据不完整，等待更多数据
        std::cout << "Failed to parse RTMP packet: " << e.what() << std::endl;
    }
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    IP_HEADER* ip_header;
    TCP_HEADER* tcp_header;
    int ip_len;
    int tcp_len;
    const u_char* payload;
    int payload_len;

    // 跳过以太网头部
    pkt_data += 14;

    // 获取IP头部
    ip_header = (IP_HEADER*)pkt_data;
    ip_len = (ip_header->ver_ihl & 0xf) * 4;

    // 确保是TCP包
    if (ip_header->proto != IPPROTO_TCP) {
        return;
    }

    // 获取TCP头部
    tcp_header = (TCP_HEADER*)(pkt_data + ip_len);
    tcp_len = ((ntohs(tcp_header->flags) & 0xf000) >> 12) * 4;

    // 计算payload
    payload = pkt_data + ip_len + tcp_len;

    // 计算载荷长度
    uint16_t total_len = ntohs(ip_header->tlen);
    payload_len = (total_len >= (ip_len + tcp_len)) ? (total_len - (ip_len + tcp_len)) : 0;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    // 创建连接键
    TCPConnectionKey key = {
        src_ip,
        dst_ip,
        ntohs(tcp_header->sport),
        ntohs(tcp_header->dport)
    };

    //std::cout << get_current_time() << " - ";
    //std::cout << "Packet: " << src_ip << ":" << ntohs(tcp_header->sport) << " -> "
    //    << dst_ip << ":" << ntohs(tcp_header->dport) << " ";
    //analyze_tcp_flags(tcp_header);

    // 检查连接是否已知
    auto it = connections.find(key);
    if (it == connections.end()) {
        // 新连接
        connections[key] = { RTMPState::WAITING_FOR_HANDSHAKE, HandshakeState::WAITING_C0C1, std::vector<uint8_t>(), 0, 0 };
        it = connections.find(key);
       // std::cout << "New connection detected" << std::endl;
    }

    auto& connection = it->second;

    // 更新序列号
    uint32_t seq_num = ntohl(tcp_header->seq);
    if (connection.last_seq_num == 0) {
        connection.last_seq_num = seq_num;
        connection.expected_seq_num = seq_num + max(1, payload_len);
    }
    else {
        if (seq_num != connection.expected_seq_num) {
        /*    std::cout << "Unexpected sequence number. Expected: "
                << connection.expected_seq_num << ", Got: " << seq_num << std::endl;*/
        }
        connection.last_seq_num = seq_num;
        connection.expected_seq_num = seq_num + max(1, payload_len);
    }

    // 处理负载数据
    if (payload_len > 0) {
        handle_payload(connection, payload, payload_len);
    }
    else {
       // std::cout << "Zero payload packet" << std::endl;
    }

#if 0
    // RTMP 处理
    if (connection.rtmp_state == RTMPState::WAITING_FOR_HANDSHAKE) {
        if (is_rtmp_handshake(connection.buffer.data(), connection.buffer.size())) {
            connection.rtmp_state = RTMPState::HANDSHAKING;
            std::cout << "RTMP handshake started" << std::endl;
        }
    }

    if (connection.rtmp_state == RTMPState::HANDSHAKING) {
        if (handle_rtmp_handshake(connection)) {
            connection.rtmp_state = RTMPState::READY_FOR_MESSAGES;
            std::cout << "RTMP handshake completed" << std::endl;
        }
    }

    if (connection.rtmp_state == RTMPState::READY_FOR_MESSAGES) {
        handle_rtmp_packet(connection);
    }
#endif


  //  std::cout << std::endl;  // 为每个包的输出添加一个空行，提高可读性
}

void initialize_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("Failed to initialize Winsock");
    }
}

void cleanup_winsock() {
    WSACleanup();
}

int select_network_interface(pcap_if_t* alldevs) {
    pcap_if_t* d;
    int inum;
    int i = 0;

    // 打印设备列表
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        return -1;
    }

    return inum;
}

pcap_t* open_network_interface(pcap_if_t* alldevs, int inum, char* errbuf) {
    pcap_if_t* d;
    int i = 0;
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    pcap_t* adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return NULL;
    }

    return adhandle;
}

int main() {
    try {
        initialize_winsock();

        pcap_if_t* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
            throw std::runtime_error("Error in pcap_findalldevs: " + std::string(errbuf));
        }

        int inum = select_network_interface(alldevs);
        if (inum == -1) {
            pcap_freealldevs(alldevs);
            return -1;
        }

        pcap_t* adhandle = open_network_interface(alldevs, inum, errbuf);
        if (adhandle == NULL) {
            pcap_freealldevs(alldevs);
            return -1;
        }

        // 检查数据链路层，我们只考虑以太网
        if (pcap_datalink(adhandle) != DLT_EN10MB) {
            throw std::runtime_error("This program works only on Ethernet networks.");
        }

        u_int netmask;
        pcap_if_t* d;
        int i = 0;
        for (d = alldevs; i < inum - 1; d = d->next, i++);
        if (d->addresses != NULL)
            netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else
            netmask = 0xffffff;

        struct bpf_program fcode;
        char packet_filter[] = "tcp";  // 捕获所有 TCP 流量

        // 编译过滤器
        if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
            throw std::runtime_error("Unable to compile the packet filter. Check the syntax.");
        }

        // 设置过滤器
        if (pcap_setfilter(adhandle, &fcode) < 0) {
            throw std::runtime_error("Error setting the filter.");
        }

        printf("\nlistening on %s...\n", d->description);

        // 我们不再需要设备列表了，释放它
        pcap_freealldevs(alldevs);

        // 开始捕获
        pcap_loop(adhandle, 0, packet_handler, NULL);

        // 清理
        pcap_close(adhandle);
        cleanup_winsock();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        cleanup_winsock();
        return 1;
    }

    return 0;
}

#endif
