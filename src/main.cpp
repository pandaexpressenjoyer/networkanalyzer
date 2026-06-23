#include <iostream>
#define HAVE_REMOTE 
#include <pcap.h>
#include <winsock2.h> 

using namespace std;

// Force the compiler to pack these structures with tight 1-byte alignment
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

#pragma pack(pop)

// The packet processing callback engine
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // 1. Cast the raw byte data pointer to our Ethernet structure
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(pkt_data);

    // Convert network byte order (Big Endian) to host byte order (Little Endian)
    uint16_t eth_type = ntohs(eth->type);

    // 0x0800 means the payload inside this Ethernet frame is an IPv4 Packet
    if (eth_type == 0x0800) {
        // 2. The IP header sits exactly 14 bytes (Ethernet header length) into the packet
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(pkt_data + 14);

        // Print Protocol String
        if (ip->protocol == 6) cout << "[TCP]  ";
        else if (ip->protocol == 17) cout << "[UDP]  ";
        else if (ip->protocol == 1) cout << "[ICMP] ";
        else cout << "[OTHER] ";

        // Print Source and Destination IPs
        cout << (int)ip->src_ip[0] << "." << (int)ip->src_ip[1] << "."
             << (int)ip->src_ip[2] << "." << (int)ip->src_ip[3];

        cout << " -> ";

        cout << (int)ip->dest_ip[0] << "." << (int)ip->dest_ip[1] << "."
             << (int)ip->dest_ip[2] << "." << (int)ip->dest_ip[3];

        cout << " | Size: " << header->len << " bytes" << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    // 1. Find all network adapters available on the host machine
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network devices: " << errbuf << endl;
        return 1;
    }

    // 2. Display devices to the user
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << (d->description ? " (" + string(d->description) + ")" : "") << endl;
    }

    if (i == 0) {
        cout << "No interfaces found. Check Npcap installations." << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }

    // Automatically loops the first available interface for our packet stream
    int choice_num;
    cout << "\nEnter the interface number to analyze (1-" << i << "): ";
    cin >> choice_num;

    if (choice_num < 1 || choice_num > i) {
        cout << "Invalid choice selection. Exiting." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Advance the device list pointer to match user selection
    pcap_if_t* choice = alldevs;
    for (int c = 1; c < choice_num; c++) {
        choice = choice->next;
    }
    
    // 3. Open the active network adapter for live analysis
    pcap_t* handle = pcap_open_live(choice->name, 
                                    65536,  // Snapshot length (captures complete packet frame)
                                    1,      // Promiscuous mode enabled
                                    1000,   // Read timeout in milliseconds
                                    errbuf);

    if (handle == NULL) {
        cerr << "Failed to open adapter: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    cout << "\nAnalyzing live traffic on: " << (choice->description ? choice->description : choice->name) << "...\n" << endl;

    // 4. Run the infinite packet processing loop (0 means loop forever)
    pcap_loop(handle, 0, packet_handler, NULL);

    // Clean up memory
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}