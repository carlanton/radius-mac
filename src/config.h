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
    int clients_length;
    client_config *clients;
    client_config default_client;
} config;

config *read_config(char *filename);
client_config *get_client(char *mac, config *cfg);

#endif /* CONFIG_H */
