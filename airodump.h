#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define UNUSED(x) (void)(x)

// Define the 802.11 header structure
typedef struct {
    uint8_t  frame_control;
    uint8_t  duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_header_t;

// Define the Beacon frame information structure
typedef struct {
    uint8_t  mac[6];
    char     essid[32];
    int      beacons;
    int      data;
    char     enc[16];
    int      pwr;
} network_info_t;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_networks(network_info_t *networks, int count);
int parse_radiotap_header(const u_char *packet, int *pwr);
void parse_beacon_frame(const u_char *packet, network_info_t *network);

#endif // AIRODUMP_H