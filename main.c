#define _DEFAULT_SOURCE
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <stdint.h>

#include "config.h"
#include "radius.h"
#include "log.h"

#define VLAN_MAX_LENGTH 4

void send_packet(packet *packet, char *secret,
                 int sockfd, struct sockaddr_in *client_addr, socklen_t client_addr_len) {
    uint8_t response[40];
    if (packet->length > sizeof(response)) {
        return;
    }
    write_packet(packet, secret, response);
    sendto(sockfd, (const char*) response, packet->length,
           MSG_CONFIRM, (const struct sockaddr*) client_addr, client_addr_len);
}

void run(config *cfg) {
    int e;
    int sockfd;
    struct sockaddr_in client_addr = {0};
    socklen_t client_addr_len = sizeof(client_addr);
    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(cfg->port),
        .sin_zero = {0}
    };

    e = inet_pton(AF_INET, cfg->address, &servaddr.sin_addr.s_addr);
    if (e != 1) {
        fatalf("invalid network address: %s", cfg->address);
    }

    uint8_t buffer[4096];
    ssize_t n;
    packet request;
    char password[129];
    char mac[48];
    client_config *client;

    client_config default_client = {
        .description = "default",
        .vlan = cfg->default_vlan
    };

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

    logf("Starting radius server on %s:%d", cfg->address, cfg->port);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr*) &servaddr, sizeof(servaddr)) < 0){
        perror("bind failed");
        exit(1);
    }

    while (1) {
        n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_WAITALL,
                     (struct sockaddr *) &client_addr, &client_addr_len);

        if (n <= 0) {
            continue;
        }

        e = parse_packet(buffer, n, &request);
        if (e < 0) {
            fprintf(stderr, "invalid packet\n");
            continue;
        }

        if (request.code != AccessRequest) {
            fprintf(stderr, "unsupported request code %d\n", request.code);
            continue;
        }

        e = lookup_password(&request, cfg->secret, password);
        if (e < 0) {
            fprintf(stderr, "password error\n");
            continue;
        }

        packet response = {
            .identifier = request.identifier,
            .length = 20,
            .authenticator = request.authenticator,
            .attributes = 0,
        };

        e = lookup_attribute(&request, UserName, mac, sizeof(mac), NULL);
        if (e < 0) {
            logf("[%s:%d] rejecting client: attribute User-Name not found",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            response.code = AccessReject;
            send_packet(&response, cfg->secret, sockfd, &client_addr, client_addr_len);
            continue;
        }

        e = strcmp(password, mac);
        if (e != 0) {
            logf("[%s:%d] rejecting client %s: password mismatch",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), mac);
            response.code = AccessReject;
            send_packet(&response, cfg->secret, sockfd, &client_addr, client_addr_len);
            continue;
        }

        e = lookup_client(mac, cfg, &client); 
        if (e < 0) { // client not found
            client = &default_client;
        }

        logf("[%s:%d] accepting client: %s (%s) => vlan-id: %d",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
               mac, client->description, client->vlan);

        // Attributes required for VLAN assignment
        uint8_t attributes[] = {
            // Tunnel-Type = VLAN
            64, 6, 0, 0, 0, 13,

            // Tunnel-Medium-Type = IEEE 802
            65, 6, 0, 0, 0, 6,
           
            // Tunnel-Private-Group-ID
            81, 3, 0, 0, 0, 0, 0, 0
            //  ^     ^
            //  |      \-- vlan_string
            //  |
            //   \-- tpgid_length
        };

        uint8_t *tpgid_length = &attributes[13];
        uint8_t *vlan_string = &attributes[15];

        int n = snprintf((char*) vlan_string, VLAN_MAX_LENGTH, "%d", client->vlan);
        if (n >= VLAN_MAX_LENGTH || n < 0) {
            fprintf(stderr, "invalid vlan for client %s\n", client->mac);
            continue;
        }
        *tpgid_length += n;

        response.code = AccessAccept;
        response.length += 6 + 6 + *tpgid_length;
        response.attributes = &attributes;

        send_packet(&response, cfg->secret, sockfd, &client_addr, client_addr_len);
    }
}

int main(int argc, char **argv) {
    char *config_file = "config.ini";
    int opt;
    opterr = 0;

    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
        case 'c': config_file = strdup(optarg); break;
        default:
                  fprintf(stderr, "Usage: %s [-c <config-file>]\n", argv[0]);
                  exit(1);
        }
    }

    config *cfg = read_config(config_file);

    run(cfg);

    return 0;
}
