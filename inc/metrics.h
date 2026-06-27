#ifndef METRICS_H
#define METRICS_H

#include <string>
#include <unordered_map>
#include <unordered_set> // Required for storing unique port numbers
#include <vector>
#include <algorithm>
#include <cstdint>
struct NetworkStats {
    unsigned long long total_packets = 0;
    unsigned long long tcp_packets = 0;
    unsigned long long udp_packets = 0;
    unsigned long long icmp_packets = 0;
    unsigned long long other_packets = 0;
    unsigned long long total_bytes = 0;
};

struct FlowStats {
    std::string protocol;
    unsigned long long total_bytes = 0;
    unsigned long long packet_count = 0;
};

extern NetworkStats stats;
extern std::unordered_map<std::string, FlowStats> flow_table;
// New tracking table for our Intrusion Detection Engine
extern std::unordered_map<std::string, std::unordered_set<uint16_t>> port_scan_map;

void update_flow(const std::string& src_ip, uint16_t src_port, 
                 const std::string& dst_ip, uint16_t dst_port, 
                 const std::string& protocol, uint32_t length);

// New IDS function
void detect_port_scan(const std::string& src_ip, uint16_t dst_port);

void print_metrics_dashboard();

#endif