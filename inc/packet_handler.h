#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#define HAVE_REMOTE 
#include <pcap.h>

extern int protocol_filter;
extern pcap_t* global_handle;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#endif