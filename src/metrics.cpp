#include "metrics.h"
#include <iostream>
#include <iomanip>

using namespace std;

// Allocate the concrete storage location for the shared stats instance
NetworkStats stats;

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
    } else {
        cout << " No network frames evaluated during session profile." << endl;
    }
    cout << "==================================================" << endl;
}