#include "metrics.h"
#include <iostream>
#include <iomanip>

using namespace std;

NetworkStats stats;
unordered_map<string, FlowStats> flow_table;
unordered_map<string, unordered_set<uint16_t>> port_scan_map;

// Configure the security sensitivity (alert after hitting 15 unique ports)
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

// Intrusion Detection Engine: Evaluates traffic for scanning heuristics
void detect_port_scan(const string& src_ip, uint16_t dst_port) {
    // Insert the destination port into the set (sets automatically ignore duplicates)
    port_scan_map[src_ip].insert(dst_port);

    // If the size of the set exactly hits our threshold, trigger a live terminal warning
    // (We use '==' instead of '>=' so it only prints the warning once per IP)
    if (port_scan_map[src_ip].size() == PORT_SCAN_THRESHOLD) {
        cout << "\n==================================================" << endl;
        cout << " [!] INTRUSION ALERT: PORT SCAN DETECTED" << endl;
        cout << "     Source IP: " << src_ip << " is scanning the network!" << endl;
        cout << "==================================================\n" << endl;
    }
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
        cout << " [Misc] Packets: " << stats.other_packets << " (" << (stats.other_packets * 100.0 / stats.total_packets) << "%)" << endl;
        
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

    } else {
        cout << " No network frames evaluated during session profile." << endl;
    }
}