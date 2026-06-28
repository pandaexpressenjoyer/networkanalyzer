#ifndef METRICS_H
#define METRICS_H

#include <string>
#include <unordered_map>
#include <unordered_set>
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

// New structure to track physical hardware devices
struct DeviceInfo {
    std::string last_seen_ip;
    unsigned long long total_packets = 0;
};

extern NetworkStats stats;
extern std::unordered_map<std::string, FlowStats> flow_table;
extern std::unordered_map<std::string, std::unordered_set<uint16_t>> port_scan_map;
// New tracking table for hardware discovery
extern std::unordered_map<std::string, DeviceInfo> device_table;

void update_flow(const std::string& src_ip, uint16_t src_port, 
                 const std::string& dst_ip, uint16_t dst_port, 
                 const std::string& protocol, uint32_t length);

void detect_port_scan(const std::string& src_ip, uint16_t dst_port);

// New function to log discovered devices
void update_device(const std::string& mac, const std::string& ip);

void print_metrics_dashboard();

#endif