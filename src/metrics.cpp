#include "metrics.h"
#include <iostream>
#include <iomanip>
#include <cstdint>

using namespace std;

NetworkStats stats;
unordered_map<string, FlowStats> flow_table;
unordered_map<string, unordered_set<uint16_t>> port_scan_map;
unordered_map<string, DeviceInfo> device_table;

const int PORT_SCAN_THRESHOLD = 15; 

void update_flow(const string& src_ip, uint16_t src_port, 
                 const string& dst_ip, uint16_t dst_port, 
                 const string& protocol, uint32_t length) {
    
    string endpoint1 = src_ip + ":" + to_string(src_port);
    string endpoint2 = dst_ip + ":" + to_string(dst_port);

    string flow_key = (endpoint1 < endpoint2) ? 
                      (endpoint1 + " <-> " + endpoint2) : 
                      (endpoint2 + " <-> " + endpoint1);

    flow_table[flow_key].protocol = protocol;
    flow_table[flow_key].total_bytes += length;
    flow_table[flow_key].packet_count += 1;
}

void detect_port_scan(const string& src_ip, uint16_t dst_port) {
    port_scan_map[src_ip].insert(dst_port);

    if (port_scan_map[src_ip].size() >= PORT_SCAN_THRESHOLD) {
        cout << "\n==================================================" << endl;
        cout << " [!] 🚨 INTRUSION ALERT: PORT SCAN DETECTED 🚨" << endl;
        cout << "     Source IP: " << src_ip << " hit " << port_scan_map[src_ip].size() << " unique ports!" << endl;
        cout << "==================================================\n" << endl;
    }
}

// Hardware tracking logic: updates the map with the latest IP associated with a MAC
void update_device(const string& mac, const string& ip) {
    device_table[mac].last_seen_ip = ip;
    device_table[mac].total_packets++;
}

void print_metrics_dashboard() {
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
        
        cout << "\n--------------------------------------------------" << endl;
        cout << "               LARGEST CONNECTION FLOWS           " << endl;
        cout << "--------------------------------------------------" << endl;

        vector<pair<string, FlowStats>> sorted_flows(flow_table.begin(), flow_table.end());
        sort(sorted_flows.begin(), sorted_flows.end(), 
             [](const auto& a, const auto& b) { return a.second.total_bytes > b.second.total_bytes; });

        int display_count = min(5, (int)sorted_flows.size());
        for (int i = 0; i < display_count; i++) {
            cout << " " << i + 1 << ". [" << sorted_flows[i].second.protocol << "] " << sorted_flows[i].first << "\n"
                 << "    Packets: " << sorted_flows[i].second.packet_count 
                 << " | Data: " << fixed << setprecision(2) << (sorted_flows[i].second.total_bytes / 1024.0) << " KB\n" << endl;
        }

        cout << "--------------------------------------------------" << endl;
        cout << "               DISCOVERED HARDWARE         " << endl;
        cout << "--------------------------------------------------" << endl;
        
        // Print every unique physical device discovered during the session
        int dev_count = 1;
        for (const auto& device : device_table) {
            cout << " " << dev_count++ << ". MAC: " << device.first << "\n"
                 << "    IP: " << device.second.last_seen_ip 
                 << " | Packets Sent: " << device.second.total_packets << "\n" << endl;
        }

    } else {
        cout << " No network frames evaluated during session profile." << endl;
    }
}