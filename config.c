#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"
#include "log.h"

static void trim(char **string) {
    char *s = *string;

    // trim start
    while (*s != '\0' && isspace(*s) != 0) {
        s++;
    }

    // trim end    
    for (int i = strlen(s) - 1; i >= 0 && isspace(s[i]) != 0; i--) {
        s[i] = '\0';
    }

    *string = s;
}

config *read_config(char *filename) {
    FILE *fp;
    char *line = NULL;
    char *buf = NULL;
    size_t len = 0;
    ssize_t read;

    config *cfg = calloc(1, sizeof(config));
    int default_vlan = 0;

    int state = 0;

    cfg->clients = NULL;
    client_config *client = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fatalf("Failed to open %s: %s", filename, strerror(errno));
    }

    while ((read = getline(&buf, &len, fp)) != -1) {
        if (read <= 1) {
            continue;
        }

        line = buf;
        trim(&line);

        if (line[0] == ';' || line[0] == '#') {
            continue;
        }

        if (line[0] == '[') { // new section
            char *end = strchr(line, ']');
            if (end == NULL) {
                fprintf(stderr, "syntax error\n");
                exit(EXIT_FAILURE);
            }
            *end = '\0';
            char *section = line + 1;
            trim(&section);

            if (strcmp(section, "server") == 0) {
                state = 1;
            } else { // new client
                state = 2;

                int n = ++cfg->clients_length;
                cfg->clients = realloc(cfg->clients, n * sizeof(client_config));
                client = &cfg->clients[n - 1];
                memset(client, 0, sizeof(client_config));
                client->mac = strdup(section);
            }
        } else {
            char *eq = strchr(line, '=');
            if (eq == NULL) {
                continue; // ugh
            }
            *eq = '\0';
            char *key = line;
            char *value = eq + 1;

            trim(&key);
            trim(&value);

            if (state == 1) { // server section
                if (strcmp(key, "address") == 0) {
                    cfg->address = strdup(value);
                } else if (strcmp(key, "port") == 0) {
                    cfg->port = atoi(value);
                } else if (strcmp(key, "default_vlan") == 0) {
                    default_vlan = atoi(value);
                } else if (strcmp(key, "secret") == 0) {
                    cfg->secret = strdup(value);
                } else {
                    fatalf("config: unknown key in [server]: %s", key);
                }
            } else if (state == 2) { // client section
                if (strcmp(key, "description") == 0) {
                    client->description = strdup(value);
                } else if (strcmp(key, "vlan") == 0) {
                    client->vlan = atoi(value);
                }
            }
        }
    }

    fclose(fp);
    free(line);

    // validate config
    if (cfg->address == NULL) {
        fatal("server/address not set");
    }

    if (cfg->port == 0) {
        fatal("server/port not set");
    }

    if (default_vlan < 1 || default_vlan > 4095) {
        fatal("server/default_vlan not set or invalid");
    }

    if (cfg->secret == NULL) {
        fatal("server/secret not set");
    }

    for (int i = 0; i < cfg->clients_length; i++) {
        client_config *client = &cfg->clients[i];
        if (client->mac == NULL) {
            fatal("invalid client config");
        }
        if (client->description == NULL) {
            fatalf("missing description for client %s", client->mac);
        }
        if (client->vlan < 1 || client->vlan > 4095) {
            fatalf("invalid vlan for client %s", client->mac);
        }
    }

    cfg->default_client = (client_config) {
      .description = strdup("default"),
      .mac = strdup(""),
      .vlan = default_vlan
    };

    return cfg;
}

client_config *get_client(char *mac, config *cfg) {
    client_config *c = cfg->clients;

    for (int i = 0; i < cfg->clients_length; i++, c++) {
        if (strcmp(c->mac, mac) == 0) {
            return c;
        }
    }

    return &cfg->default_client; // fallback
}

void free_config(config *cfg) {

  (void) cfg;
  /*
    client_config *c = cfg->clients;
    for (int i = 0; i < cfg->clients_length; i++, c++) {
    }
    */
}
