#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Radiotap header structure
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

// Beacon frame structure
struct beacon_frame {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6];
    uint16_t fragment_sequence_number;
};

// Probe frame structure
struct probe_frame {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6];
    uint16_t fragment_sequence_number;
};

// SSID structure
typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t ssid[];
} Tag_SSID;

// Supported rates structure
typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t rates[];
} Tag_Supported_Rates;

// DS parameter structure
typedef struct {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t channel;
} Tag_DS;

// Wireless management structure
struct wireless_management {
    uint8_t fixed_parameter[12];
    Tag_SSID SSID;
    Tag_Supported_Rates Rates;
    Tag_DS DS;
};

// Beacon data structure
struct airodump_beacon {
    uint8_t BSSID[6];
    int PWR;
    int BEACONS;
    uint8_t CH;
    const char *ENC;
    uint8_t *ESSID;
};

// Probe data structure
struct airodump_probe {
    uint8_t BSSID[6];
    uint8_t STATION[6];
    int PWR;
    int Frames;
    uint8_t *PROBE;
};

// Function prototypes
int process_packet(const struct pcap_pkthdr *header, const u_char *packet);
int find_signal_strength(const struct pcap_pkthdr *header, const u_char *packet);
void find_bssid(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *bssid);
uint8_t *find_wireless_static(const struct pcap_pkthdr *header, const u_char *packet, int *ssid_length);
uint8_t find_wireless_dynamic(const struct pcap_pkthdr *header, const u_char *packet);
const char *find_encryption_type(const struct pcap_pkthdr *header, const u_char *packet);
void printData(struct airodump_beacon *wlan_data, int start_num, struct airodump_probe *wlan_data1, int start_num2);
void set_channel(char *interface, int channel);

#endif // AIRODUMP_H