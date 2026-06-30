#include "packet_handler.h"
#include "protocol.h"
#include "metrics.h"
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
        for (uint8_t i = 0; i < label_len; i++) { domain += static_cast<char>(*curr); curr++; }
        if (*curr != 0) domain += ".";
    }
    return domain;
}

string ip_to_string(const uint8_t* ip_array) { return to_string(ip_array[0]) + "." + to_string(ip_array[1]) + "." + to_string(ip_array[2]) + "." + to_string(ip_array[3]); }
string mac_to_string(const uint8_t* mac_array) { char buf[18]; snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5]); return string(buf); }

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (param != nullptr) pcap_dump(param, header, pkt_data);

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(pkt_data);
    uint16_t eth_type = ntohs(eth->type);

    if (eth_type == 0x0800) {
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(pkt_data + 14);

        if (protocol_filter == 2 && ip->protocol != 6) return;    
        if (protocol_filter == 3 && ip->protocol != 17) return;   
        if (protocol_filter == 4 && ip->protocol != 1) return;    

        uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;
        string src_ip_str = ip_to_string(ip->src_ip);
        string dst_ip_str = ip_to_string(ip->dest_ip);
        string src_mac_str = mac_to_string(eth->src_mac);

        lock_guard<mutex> lock(data_mutex);

        stats.total_packets++;
        stats.total_bytes += header->len;
        update_device(src_mac_str, src_ip_str);

        if (ip->protocol == 6) {
            stats.tcp_packets++;
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(pkt_data + 14 + ip_header_len);
            
            update_flow(src_ip_str, ntohs(tcp->src_port), dst_ip_str, ntohs(tcp->dest_port), "TCP", header->len);
            
            detect_port_scan(src_ip_str, ntohs(tcp->dest_port));
        }
        else if (ip->protocol == 17) {
            stats.udp_packets++;
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(pkt_data + 14 + ip_header_len);
            update_flow(src_ip_str, ntohs(udp->src_port), dst_ip_str, ntohs(udp->dest_port), "UDP", header->len);
        }
        else if (ip->protocol == 1) {
            stats.icmp_packets++;
        } else {
            stats.other_packets++;
        }
    }
}