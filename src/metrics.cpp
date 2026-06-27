#include "metrics.h"
#include <iostream>
#include <iomanip>
#include <cstdint>
using namespace std;

NetworkStats stats;
unordered_map<string, FlowStats> flow_table;

// Ingests packet data and groups it into bidirectional connection buckets
void update_flow(const string& src_ip, uint16_t src_port, 
                 const string& dst_ip, uint16_t dst_port, 
                 const string& protocol, uint32_t length) {
    
    string endpoint1 = src_ip + ":" + to_string(src_port);
    string endpoint2 = dst_ip + ":" + to_string(dst_port);

    // Sort endpoints alphabetically to ensure bidirectional tracking (A->B is the same as B->A)
    string flow_key = (endpoint1 < endpoint2) ? 
                      (endpoint1 + " <-> " + endpoint2) : 
                      (endpoint2 + " <-> " + endpoint1);

    flow_table[flow_key].protocol = protocol;
    flow_table[flow_key].total_bytes += length;
    flow_table[flow_key].packet_count += 1;
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
        cout << "               LARGEST DATA FLOWS              " << endl;
        cout << "--------------------------------------------------" << endl;

        // Extract map contents to a vector for bandwidth sorting
        vector<pair<string, FlowStats>> sorted_flows(flow_table.begin(), flow_table.end());
        
        // Sort the vector using a lambda function comparing total_bytes in descending order
        sort(sorted_flows.begin(), sorted_flows.end(), 
             [](const auto& a, const auto& b) { return a.second.total_bytes > b.second.total_bytes; });

        // Print the top 5 heaviest bandwidth connections
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