#ifndef METRICS_H
#define METRICS_H

#include <string>
#include <unordered_map>
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

// Data structure to track individual connection flows
struct FlowStats {
    std::string protocol;
    unsigned long long total_bytes = 0;
    unsigned long long packet_count = 0;
};

// Share the stats struct and flow tracking table across source files
extern NetworkStats stats;
extern std::unordered_map<std::string, FlowStats> flow_table;

void update_flow(const std::string& src_ip, uint16_t src_port, 
                 const std::string& dst_ip, uint16_t dst_port, 
                 const std::string& protocol, uint32_t length);

void print_metrics_dashboard();

#endif