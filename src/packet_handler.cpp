#include "packet_handler.h"
#include "protocol.h"
#include "metrics.h"
#include <iostream>
#include <winsock2.h>

using namespace std;

int protocol_filter = 1; 
pcap_t* global_handle = nullptr; 

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(pkt_data);
    uint16_t eth_type = ntohs(eth->type);

    if (eth_type == 0x0800) {
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(pkt_data + 14);

        if (protocol_filter == 2 && ip->protocol != 6) return;    
        if (protocol_filter == 3 && ip->protocol != 17) return;   
        if (protocol_filter == 4 && ip->protocol != 1) return;    

        stats.total_packets++;
        stats.total_bytes += header->len;

        uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;

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