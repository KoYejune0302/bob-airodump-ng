#include "airodump.h"
#include <time.h>

// 프레임 종류 판별
int process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    uint16_t radiotap_header_length = radio_hdr->len;
    u_char type_subtype = packet[radiotap_header_length];
    u_char type = (type_subtype & 0x0C) >> 2;    // 타입 필드
    u_char subtype = (type_subtype & 0xF0) >> 4; // 서브타입 필드
    if (type == 0 && subtype == 8) {
        return 1; // Beacon frame
    } else if (type == 0 && subtype == 4) {
        return 2; // Probe Request frame
    } else if (type == 0 && subtype == 5) {
        return 3; // Probe Response frame
    } else {
        return 0; // Other frame
    }
}

// Signal strength 찾기
int find_signal_strength(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = sizeof(struct radiotap_header);
    uint32_t present = *(uint32_t *)(packet + offset);
    offset += 4;

    // Parse Radiotap header to find dBm Antenna Signal
    if (present & (1 << 1)) { // Check for dBm Antenna Signal field
        return (int8_t)packet[offset]; // Signal strength in dBm
    }
    return 0; // Default value if not found
}

// 채널 찾기
uint8_t find_channel(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = sizeof(struct radiotap_header);
    uint32_t present = *(uint32_t *)(packet + offset);
    offset += 4;

    // Parse Radiotap header to find Channel field
    if (present & (1 << 3)) { // Check for Channel field
        offset += 1; // Skip flags field
        return packet[offset]; // Channel number
    }
    return 0; // Default value if not found
}

// BSSID 찾기
void find_bssid(const struct pcap_pkthdr *header, const u_char *packet, uint8_t *bssid) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    struct beacon_frame *beacon_fr = (struct beacon_frame *)(packet + offset);
    memcpy(bssid, beacon_fr->bss_id, 6);
}

// ESSID 찾기
uint8_t *find_wireless_static(const struct pcap_pkthdr *header, const u_char *packet, int *ssid_length) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    struct wireless_management *wl_mg = (struct wireless_management *)(packet + offset + 24);
    Tag_SSID *ssid = &(wl_mg->SSID);
    *ssid_length = ssid->tag_length;
    return ssid->ssid;
}

// Encryption type 찾기
const char *find_encryption_type(const struct pcap_pkthdr *header, const u_char *packet) {
    struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
    int offset = radio_hdr->len;

    struct wireless_management *wl_mg = (struct wireless_management *)(packet + offset + 24);
    uint8_t *ptr = (uint8_t *)wl_mg;
    ptr += sizeof(struct wireless_management);

    while (ptr < packet + header->caplen) {
        uint8_t tag_number = *ptr++;
        uint8_t tag_length = *ptr++;

        if (tag_number == 48) { // RSN information element
            return "WPA2";
        } else if (tag_number == 221) { // Vendor specific
            if (tag_length >= 4 && memcmp(ptr, "\x00\x50\xf2\x01", 4) == 0) {
                return "WPA";
            }
        }

        ptr += tag_length;
    }

    return "OPEN";
}

// 출력 함수
void printData(struct airodump_beacon *wlan_data, int start_num, struct airodump_probe *wlan_data1, int start_num2) {
    system("clear"); // 화면 클리어
    printf("BSSID              PWR  Beacons  CH   ENC  ESSID\n");
    printf("--------------------------------------------------\n");
    for (int i = 0; i < start_num; i++) {
        for (int j = 0; j < 6; j++) {
            printf("%02x", wlan_data[i].BSSID[j]);
            if (j != 5) printf(":");
        }
        printf("  %-3d    %-7d  %-3d   %-4s  %s\n", wlan_data[i].PWR, wlan_data[i].BEACONS, wlan_data[i].CH, wlan_data[i].ENC, wlan_data[i].ESSID);
    }

    printf("\n\nBSSID             STATION         PWR  FRAMES  PROBES\n");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < start_num2; i++) {
        for (int j = 0; j < 6; j++) {
            printf("%02x", wlan_data1[i].BSSID[j]);
            if (j != 5) printf(":");
        }
        printf("  ");
        for (int j = 0; j < 6; j++) {
            printf("%02x", wlan_data1[i].STATION[j]);
            if (j != 5) printf(":");
        }
        printf("  %-3d    %-6d  %s\n", wlan_data1[i].PWR, wlan_data1[i].Frames, wlan_data1[i].PROBE);
    }
}

// 채널 설정 함수
void set_channel(char *interface, int channel) {
    char command[100];
    sprintf(command, "iwconfig %s channel %d", interface, channel);
    system(command);
}

// 메인 함수
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 2;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    struct airodump_beacon *wlan_data = NULL;
    int wlan_data_size = 0;
    struct airodump_probe *wlan_data1 = NULL;
    int wlan_data_size2 = 0;
    int start_num = 0;
    int start_num2 = 0;

    int current_channel = 1;
    const int max_channel = 13;
    time_t last_channel_change = time(NULL);

    while (1) {
        // Change channel every 1000ms
        if (time(NULL) - last_channel_change >= 1) {
            set_channel(argv[1], current_channel);
            current_channel++;
            if (current_channel > max_channel) current_channel = 1;
            last_channel_change = time(NULL);
        }

        const u_char *packet;
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue; // 타임아웃 발생
        if (res == -1 || res == -2) {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        }

        int frame_type = process_packet(header, packet);
        if (frame_type == 1) { // Beacon frame
            struct airodump_beacon *temp_wlan_data = realloc(wlan_data, (wlan_data_size + 1) * sizeof(struct airodump_beacon));
            if (!temp_wlan_data) {
                fprintf(stderr, "Memory allocation failed\n");
                break;
            }
            wlan_data = temp_wlan_data;
            wlan_data_size++;

            int pwr = find_signal_strength(header, packet);
            uint8_t bssid[6];
            find_bssid(header, packet, bssid);

            int ssid_length;
            uint8_t *essid = find_wireless_static(header, packet, &ssid_length);
            uint8_t channel = find_channel(header, packet);
            const char *enc = find_encryption_type(header, packet);

            int found = 0;
            for (int i = 0; i < start_num; i++) {
                if (memcmp(wlan_data[i].BSSID, bssid, 6) == 0) {
                    wlan_data[i].PWR = pwr;
                    wlan_data[i].BEACONS++;
                    wlan_data[i].CH = channel;
                    wlan_data[i].ENC = enc;
                    if (wlan_data[i].ESSID) free(wlan_data[i].ESSID);
                    wlan_data[i].ESSID = (uint8_t *)malloc(ssid_length + 1);
                    memcpy(wlan_data[i].ESSID, essid, ssid_length);
                    wlan_data[i].ESSID[ssid_length] = '\0';
                    found = 1;
                    break;
                }
            }

            if (!found && start_num < wlan_data_size) {
                memcpy(wlan_data[start_num].BSSID, bssid, 6);
                wlan_data[start_num].PWR = pwr;
                wlan_data[start_num].BEACONS = 1;
                wlan_data[start_num].CH = channel;
                wlan_data[start_num].ENC = enc;
                wlan_data[start_num].ESSID = (uint8_t *)malloc(ssid_length + 1);
                memcpy(wlan_data[start_num].ESSID, essid, ssid_length);
                wlan_data[start_num].ESSID[ssid_length] = '\0';
                start_num++;
            }
        }

        printData(wlan_data, start_num, wlan_data1, start_num2);
    }

    // 메모리 해제
    for (int i = 0; i < start_num; i++) {
        if (wlan_data[i].ESSID) free(wlan_data[i].ESSID);
    }
    if (wlan_data) free(wlan_data);

    for (int i = 0; i < start_num2; i++) {
        if (wlan_data1[i].PROBE) free(wlan_data1[i].PROBE);
    }
    if (wlan_data1) free(wlan_data1);

    pcap_close(handle);
    return 0;
}