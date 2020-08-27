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

void run(config *cfg) {
    int e;
    int sockfd;
    struct sockaddr_in client_addr = {0};
    unsigned int client_addr_len = sizeof(client_addr);
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
    uint8_t response[40] = {0};

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

        e = lookup_attribute(&request, UserName, mac, sizeof(mac), NULL);
        if (e < 0) {
            fprintf(stderr, "attribute not found\n");
            continue;
        }

        e = strcmp(password, mac);
        if (e != 0) {
            fprintf(stderr, "password mismatch\n");
            continue;
        }

        e = lookup_client(mac, cfg, &client); 
        if (e < 0) { // client not found
            client = &default_client;
        }

        logf("[%s:%d] new client: %s (%s) => vlan-id: %d",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
               mac, client->description, client->vlan);

        uint8_t attributes[] = {
            // Attributes
            64, 6, 0, 0, 0, 13, // Tunnel-Type (VLAN)
            65, 6, 0, 0, 0, 6,  // Tunnel-Medium-Type (IEEE802)

            // Tunnel-Private-Group-ID (vlan id)
            81, /*[13]*/ 0, 0,

            // vlan id placeholder
            /*[15]*/ 0, 0, 0, 0, 0
        };

        uint8_t *tunnel_private_group_id_length = &attributes[13];
        char *vlan_attribute = ((char *) &attributes[15]);

        int vlan_length = sprintf(vlan_attribute, "%d", client->vlan);
        int attr_len = 3 + vlan_length;
        *tunnel_private_group_id_length = attr_len;

        int attributes_size = 6 + 6 + attr_len;
        int response_size = 20 + attributes_size;

        packet r = {
            .code = AccessAccept,
            .identifier = request.identifier,
            .length = response_size,
            .authenticator = request.authenticator,
            .attributes = &attributes,
            .attributes_length = attributes_size,
        };

        write_packet(&r, cfg->secret, response);

        sendto(sockfd, (const char*) response, response_size,
               MSG_CONFIRM, (const struct sockaddr*) &client_addr, client_addr_len);
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
