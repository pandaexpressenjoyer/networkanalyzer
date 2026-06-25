#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type; 
};

struct IPv4Header {
    uint8_t version_ihl;      
    uint8_t tos;              
    uint16_t total_length;    
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;              
    uint8_t protocol;         
    uint16_t checksum;
    uint8_t src_ip[4];        
    uint8_t dest_ip[4];       
};

struct UDPHeader {
    uint16_t src_port;        
    uint16_t dest_port;       
    uint16_t length;          
    uint16_t checksum;        
};

struct TCPHeader {
    uint16_t src_port;        
    uint16_t dest_port;       
    uint32_t seq_num;         
    uint32_t ack_num;         
    uint8_t data_offset;      
    uint8_t flags;            
    uint16_t window_size;     
    uint16_t checksum;        
    uint16_t urgent_ptr;      
};

#pragma pack(pop)

#endif