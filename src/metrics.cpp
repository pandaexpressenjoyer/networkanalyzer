#include "metrics.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

using namespace std;

NetworkStats stats;
unordered_map<string, FlowStats> flow_table;
unordered_map<string, DeviceInfo> device_table;

unordered_map<string, unordered_set<uint16_t>> port_scan_map;
unordered_map<string, int> flagged_scanners;

std::mutex data_mutex;
std::atomic<bool> is_capturing(true);

const int PORT_SCAN_THRESHOLD = 15; 

void update_flow(const string& src_ip, uint16_t src_port, const string& dst_ip, uint16_t dst_port, const string& protocol, uint32_t length) {
    string endpoint1 = src_ip + ":" + to_string(src_port);
    string endpoint2 = dst_ip + ":" + to_string(dst_port);
    string flow_key = (endpoint1 < endpoint2) ? (endpoint1 + " <-> " + endpoint2) : (endpoint2 + " <-> " + endpoint1);
    flow_table[flow_key].protocol = protocol;
    flow_table[flow_key].total_bytes += length;
    flow_table[flow_key].packet_count += 1;
}

void update_device(const string& mac, const string& ip) {
    device_table[mac].last_seen_ip = ip;
    device_table[mac].total_packets++;
}

// Intrusion Engine: Flag IPs that hit the threshold
void detect_port_scan(const string& src_ip, uint16_t dst_port) {
    port_scan_map[src_ip].insert(dst_port);
    if (port_scan_map[src_ip].size() >= PORT_SCAN_THRESHOLD) {
        // Save the attacker's IP and how many ports they've hit so the UI thread can draw it
        flagged_scanners[src_ip] = port_scan_map[src_ip].size();
    }
}

void draw_live_dashboard() {
    while (is_capturing) {
        system("cls"); 
        
        data_mutex.lock(); 

        cout << "==================================================" << endl;
        cout << "    LIVE NETWORK METRICS DASHBOARD (Running)    " << endl;
        cout << "==================================================" << endl;
        
        // Pin active security alerts to the very top of the dashboard
        if (!flagged_scanners.empty()) {
            cout << " [!] INTRUSION ALERTS: PORT SCANS DETECTED" << endl;
            for (const auto& scanner : flagged_scanners) {
                cout << "     -> IP: " << scanner.first << " probed " << scanner.second << " distinct ports!" << endl;
            }
            cout << "==================================================" << endl;
        }

        cout << " Total Packets : " << stats.total_packets << endl;
        cout << " Total Data    : " << fixed << setprecision(2) << (stats.total_bytes / 1024.0) << " KB" << endl;
        
        if (stats.total_packets > 0) {
            cout << "--------------------------------------------------" << endl;
            cout << "               LARGEST CONNECTION FLOWS           " << endl;
            cout << "--------------------------------------------------" << endl;

            vector<pair<string, FlowStats>> sorted_flows(flow_table.begin(), flow_table.end());
            sort(sorted_flows.begin(), sorted_flows.end(), [](const auto& a, const auto& b) { return a.second.total_bytes > b.second.total_bytes; });

            int display_count = min(5, (int)sorted_flows.size());
            for (int i = 0; i < display_count; i++) {
                cout << " " << i + 1 << ". [" << sorted_flows[i].second.protocol << "] " << sorted_flows[i].first << "\n"
                     << "    Packets: " << sorted_flows[i].second.packet_count 
                     << " | Data: " << fixed << setprecision(2) << (sorted_flows[i].second.total_bytes / 1024.0) << " KB\n";
            }

            cout << "--------------------------------------------------" << endl;
            cout << "               DISCOVERED HARDWARE (IoT)          " << endl;
            cout << "--------------------------------------------------" << endl;
            
            int dev_count = 1;
            for (const auto& device : device_table) {
                if (dev_count > 5) break; 
                cout << " " << dev_count++ << ". MAC: " << device.first << " | IP: " << device.second.last_seen_ip << "\n";
            }
        } else {
            cout << "\n Listening for traffic..." << endl;
        }

        cout << "\n==================================================" << endl;
        cout << " Press [Ctrl + C] to safely stop and save trace." << endl;
        
        data_mutex.unlock();
        this_thread::sleep_for(chrono::seconds(1)); 
    }
}