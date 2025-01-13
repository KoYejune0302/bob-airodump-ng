#include "airodump.h"
#include <string.h>
#include <arpa/inet.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    UNUSED(header);
    network_info_t *networks = (network_info_t *)args;
    int pwr;
    int radiotap_length = parse_radiotap_header(packet, &pwr);
    packet += radiotap_length;

    ieee80211_header_t *wh = (ieee80211_header_t *)packet;
    uint8_t frame_type = wh->frame_control & 0x0f;
    uint8_t frame_subtype = (wh->frame_control >> 4) & 0x0f;

    if (frame_type == 0 && frame_subtype == 8) { // Management frame, subtype Beacon
        printf("Beacon frame received.\n");
        parse_beacon_frame(packet, networks);
    }
}

void print_networks(network_info_t *networks, int count) {
    printf("BSSID              PWR  Beacons    #Data   ENC  ESSID\n");
    for (int i = 0; i < count; i++) {
        if (networks[i].beacons > 0) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x %3d     %5d %6d %4s %s\n",
                   networks[i].mac[0], networks[i].mac[1], networks[i].mac[2],
                   networks[i].mac[3], networks[i].mac[4], networks[i].mac[5],
                   networks[i].pwr, networks[i].beacons, networks[i].data,
                   networks[i].enc, networks[i].essid);
        }
    }
}

int parse_radiotap_header(const u_char *packet, int *pwr) {
    uint8_t version = packet[0];
    uint8_t pad = packet[1];
    uint16_t length = packet[2] | packet[3] << 8;
    uint32_t present = packet[4] | packet[5] << 8 | packet[6] << 16 | packet[7] << 24;

    if (present & (1 << 1)) { // dBm Antenna Signal present
        *pwr = (int8_t)packet[8];
    } else {
        *pwr = 0;
    }

    return length;
}

void parse_beacon_frame(const u_char *packet, network_info_t *networks) {
    // Placeholder for Beacon frame parsing
    // Implement actual parsing logic here
    UNUSED(packet);
    UNUSED(networks);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: airodump <interface>\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    struct bpf_program fp;
    char filter_exp[] = "type mgt subtype beacon";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return -1;
    }

    network_info_t networks[100];
    memset(networks, 0, sizeof(networks));

    pcap_loop(handle, -1, process_packet, (u_char *)networks);

    print_networks(networks, 100);

    pcap_close(handle);
    return 0;
}