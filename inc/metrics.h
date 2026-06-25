#ifndef METRICS_H
#define METRICS_H

struct NetworkStats {
    unsigned long long total_packets = 0;
    unsigned long long tcp_packets = 0;
    unsigned long long udp_packets = 0;
    unsigned long long icmp_packets = 0;
    unsigned long long other_packets = 0;
    unsigned long long total_bytes = 0;
};

// Share the stats struct across source files
extern NetworkStats stats;

void print_metrics_dashboard();

#endif