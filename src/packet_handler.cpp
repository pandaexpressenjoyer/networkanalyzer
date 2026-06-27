#include "packet_handler.h"
#include "protocol.h"
#include "metrics.h"
#include <iostream>
#include <winsock2.h>
#include <string>

using namespace std;

int protocol_filter = 1; 
pcap_t* global_handle = nullptr; 

string parse_dns_name(const uint8_t* payload_start, const uint8_t* name_ptr, int packet_len) {
    string domain = "";
    const uint8_t* curr = name_ptr;
    
    while (*curr != 0) {
        if ((curr - payload_start) > packet_len) return "[Malformed Name]";

        uint8_t label_len = *curr;
        curr++;

        for (uint8_t i = 0; i < label_len; i++) {
            domain += static_cast<char>(*curr);
            curr++;
        }

        if (*curr != 0) {
            domain += ".";
        }
    }
    return domain;
}

string ip_to_string(const uint8_t* ip_array) {
    return to_string(ip_array[0]) + "." + to_string(ip_array[1]) + "." + 
           to_string(ip_array[2]) + "." + to_string(ip_array[3]);
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (param != nullptr) {
        pcap_dump(param, header, pkt_data);
    }

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
        string src_ip_str = ip_to_string(ip->src_ip);
        string dst_ip_str = ip_to_string(ip->dest_ip);

        if (ip->protocol == 6) {
            stats.tcp_packets++;
            cout << "[TCP]  ";
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(pkt_data + 14 + ip_header_len);
            
            uint16_t src_port = ntohs(tcp->src_port);
            uint16_t dst_port = ntohs(tcp->dest_port);

            update_flow(src_ip_str, src_port, dst_ip_str, dst_port, "TCP", header->len);
            
            // FEED THE SECURITY ENGINE: Log the destination port attempt
            detect_port_scan(src_ip_str, dst_port);

            cout << src_ip_str << ":" << src_port << " -> " << dst_ip_str << ":" << dst_port;
            cout << " | Size: " << header->len << " bytes" << endl;
        }
        else if (ip->protocol == 17) {
            stats.udp_packets++;
            cout << "[UDP]  ";
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(pkt_data + 14 + ip_header_len);
            
            uint16_t src_port = ntohs(udp->src_port);
            uint16_t dest_port = ntohs(udp->dest_port);

            update_flow(src_ip_str, src_port, dst_ip_str, dest_port, "UDP", header->len);

            cout << src_ip_str << ":" << src_port << " -> " << dst_ip_str << ":" << dest_port;
            cout << " | Size: " << header->len << " bytes" << endl;

            if (src_port == 53 || dest_port == 53) {
                const uint8_t* udp_payload = pkt_data + 14 + ip_header_len + 8;
                const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(udp_payload);
                uint16_t questions = ntohs(dns->questions_count);

                if (questions > 0) {
                    const uint8_t* dns_name_start = udp_payload + sizeof(DNSHeader);
                    int remaining_packet_length = header->len - (14 + ip_header_len + 8);
                    
                    string queried_domain = parse_dns_name(udp_payload, dns_name_start, remaining_packet_length);
                    cout << "   └── [DNS Query] Lookup Domain: " << queried_domain << endl;
                }
            }
        }
        else if (ip->protocol == 1) {
            stats.icmp_packets++;
            cout << "[ICMP] " << src_ip_str << " -> " << dst_ip_str << " | Size: " << header->len << " bytes" << endl;
        }
        else {
            stats.other_packets++;
            cout << "[OTHER] " << src_ip_str << " -> " << dst_ip_str << " | Size: " << header->len << " bytes" << endl;
        }
    }
}