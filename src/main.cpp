#include <iostream>
#include <csignal>   // Required for capturing console interrupt signals
#include <iomanip>   // Required for formatting decimal metrics display
#define HAVE_REMOTE 
#include <pcap.h>
#include <winsock2.h> // Required for byte order translation functions (ntohs)

using namespace std;

// Global session tracking state
int protocol_filter = 1; 
pcap_t* global_handle = nullptr; 

// Traffic metrics tracking infrastructure
struct NetworkStats {
    unsigned long long total_packets = 0;
    unsigned long long tcp_packets = 0;
    unsigned long long udp_packets = 0;
    unsigned long long icmp_packets = 0;
    unsigned long long other_packets = 0;
    unsigned long long total_bytes = 0;
} stats;

// Network protocol header layouts mapped using tight 1-byte packed alignment
#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type; // 0x0800 = IPv4, 0x0806 = ARP
};

struct IPv4Header {
    uint8_t version_ihl;      // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t tos;              // Type of Service
    uint16_t total_length;    // Total length of the packet
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;              // Time to Live
    uint8_t protocol;         // Next layer protocol (TCP = 6, UDP = 17, ICMP = 1)
    uint16_t checksum;
    uint8_t src_ip[4];        // Source IP Address
    uint8_t dest_ip[4];       // Destination IP Address
};

struct UDPHeader {
    uint16_t src_port;        // Source port
    uint16_t dest_port;       // Destination port
    uint16_t length;          // UDP length field
    uint16_t checksum;        // UDP checksum
};

struct TCPHeader {
    uint16_t src_port;        // Source port
    uint16_t dest_port;       // Destination port
    uint32_t seq_num;         // Sequence number
    uint32_t ack_num;         // Acknowledgment number
    uint8_t data_offset;      // Data offset size
    uint8_t flags;            // Control flags
    uint16_t window_size;     // Window size
    uint16_t checksum;        // TCP Checksum
    uint16_t urgent_ptr;      // Urgent pointer
};

#pragma pack(pop)

// Intercepts termination events to gracefully unwind the processing loop
void signal_handler(int signum) {
    cout << "\n[!] Stopping packet capture gracefully..." << endl;
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle); 
    }
}

// Packet processing subsystem callback
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(pkt_data);
    uint16_t eth_type = ntohs(eth->type);

    // Process layer 3 IPv4 streams
    if (eth_type == 0x0800) {
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(pkt_data + 14);

        // Apply active user runtime protocol traffic filters
        if (protocol_filter == 2 && ip->protocol != 6) return;    
        if (protocol_filter == 3 && ip->protocol != 17) return;   
        if (protocol_filter == 4 && ip->protocol != 1) return;    

        // Log general session traffic volume data
        stats.total_packets++;
        stats.total_bytes += header->len;

        // Extract dynamic internet header length offset
        uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;

        // Parse layer 4 protocols and map corresponding segment values
        if (ip->protocol == 6) {
            stats.tcp_packets++;
            cout << "[TCP]  ";
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(pkt_data + 14 + ip_header_len);
            
            cout << (int)ip->src_ip[0] << "." << (int)ip->src_ip[1] << "."
                 << (int)ip->src_ip[2] << "." << (int)ip->src_ip[3] << ":" << ntohs(tcp->src_port);
            cout << " -> ";
            cout << (int)ip->dest_ip[0] << "." << (int)ip->dest_ip[1] << "."
                 << (int)ip->dest_ip[2] << "." << (int)ip->dest_ip[3] << ":" << ntohs(tcp->dest_port);
        }
        else if (ip->protocol == 17) {
            stats.udp_packets++;
            cout << "[UDP]  ";
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(pkt_data + 14 + ip_header_len);
            
            cout << (int)ip->src_ip[0] << "." << (int)ip->src_ip[1] << "."
                 << (int)ip->src_ip[2] << "." << (int)ip->src_ip[3] << ":" << ntohs(udp->src_port);
            cout << " -> ";
            cout << (int)ip->dest_ip[0] << "." << (int)ip->dest_ip[1] << "."
                 << (int)ip->dest_ip[2] << "." << (int)ip->dest_ip[3] << ":" << ntohs(udp->dest_port);
        }
        else if (ip->protocol == 1) {
            stats.icmp_packets++;
            cout << "[ICMP] ";
            cout << (int)ip->src_ip[0] << "." << (int)ip->src_ip[1] << "."
                 << (int)ip->src_ip[2] << "." << (int)ip->src_ip[3];
            cout << " -> ";
            cout << (int)ip->dest_ip[0] << "." << (int)ip->dest_ip[1] << "."
                 << (int)ip->dest_ip[2] << "." << (int)ip->dest_ip[3];
        }
        else {
            stats.other_packets++;
            cout << "[OTHER] ";
            cout << (int)ip->src_ip[0] << "." << (int)ip->src_ip[1] << "."
                 << (int)ip->src_ip[2] << "." << (int)ip->src_ip[3];
            cout << " -> ";
            cout << (int)ip->dest_ip[0] << "." << (int)ip->dest_ip[1] << "."
                 << (int)ip->dest_ip[2] << "." << (int)ip->dest_ip[3];
        }

        cout << " | Size: " << header->len << " bytes" << endl;
    }
}

int main() {
    // Register custom interrupt vector callback to cleanly break loop architectures
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    // Enumerate hardware and virtual adapter configurations from the system kernel
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network devices: " << errbuf << endl;
        return 1;
    }

    // Print active network device directory
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << (d->description ? " (" + string(d->description) + ")" : "") << endl;
    }

    if (i == 0) {
        cout << "No interfaces found. Check Npcap installations." << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }

    int choice_num;
    cout << "\nEnter the interface number to analyze (1-" << i << "): ";
    cin >> choice_num;

    if (choice_num < 1 || choice_num > i) {
        cout << "Invalid choice selection. Exiting." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_if_t* choice = alldevs;
    for (int c = 1; c < choice_num; c++) {
        choice = choice->next;
    }

    // Configure selection criteria for runtime filtering rules
    cout << "\nChoose a Protocol Filter Option:\n";
    cout << "1. Show All Captured Traffic\n";
    cout << "2. TCP Only\n";
    cout << "3. UDP Only\n";
    cout << "4. ICMP Only\n";
    cout << "Enter filter selection (1-4): ";
    cin >> protocol_filter;

    if (protocol_filter < 1 || protocol_filter > 4) {
        cout << "Invalid selection. Defaulting to Show All Traffic.\n";
        protocol_filter = 1;
    }
    
    // Instantiate raw link layer capture descriptor 
    pcap_t* handle = pcap_open_live(choice->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Failed to open adapter: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    global_handle = handle; 

    cout << "\nAnalyzing live traffic on: " << (choice->description ? choice->description : choice->name) << "..." << endl;
    cout << "Press [Ctrl + C] at any time to stop session and view summary dashboard.\n" << endl;

    // Execute streaming evaluation loop
    pcap_loop(handle, 0, packet_handler, NULL);

    // Print out runtime session aggregate analytics dashboard
    cout << "\n==================================================" << endl;
    cout << "          CAPTURE SESSION METRICS DASHBOARD       " << endl;
    cout << "==================================================" << endl;
    cout << " Total Packets Analyzed : " << stats.total_packets << endl;
    cout << " Total Data Throughput  : " << fixed << setprecision(2) << (stats.total_bytes / 1024.0) << " KB" << endl;
    cout << "--------------------------------------------------" << endl;
    
    if (stats.total_packets > 0) {
        cout << " [TCP]  Packets: " << stats.tcp_packets  << " (" << (stats.tcp_packets * 100.0 / stats.total_packets)  << "%)" << endl;
        cout << " [UDP]  Packets: " << stats.udp_packets  << " (" << (stats.udp_packets * 100.0 / stats.total_packets)  << "%)" << endl;
        cout << " [ICMP] Packets: " << stats.icmp_packets << " (" << (stats.icmp_packets * 100.0 / stats.total_packets) << "%)" << endl;
        cout << " [Misc] Packets: " << stats.other_packets << " (" << (stats.other_packets * 100.0 / stats.total_packets) << "%)" << endl;
    } else {
        cout << " No network frames evaluated during session profile." << endl;
    }
    cout << "==================================================" << endl;

    // Release active adapter binding locks and drop device structures cleanly
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}