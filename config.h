#ifndef CONFIG_H
#define CONFIG_H

typedef struct client_config {
  char *description;
  char *mac;
  int vlan;
} client_config;

typedef struct config {
    char *address;
    int port;
    char *secret;
    int default_vlan;
    int clients_length;
    client_config *clients;
} config;

config *read_config(char *filename);

int lookup_client(char *mac, config *config, client_config **client);

#endif /* CONFIG_H */
