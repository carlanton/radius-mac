#ifndef RADIUS_H
#define RADIUS_H

#define ACCESS_REQUEST 1
#define ACCESS_ACCEPT 2

typedef struct packet {
  uint8_t code;
  uint8_t identifier;
  uint16_t length;
  uint8_t *authenticator;
  void *attributes;
  int attributes_length;
} packet;

int parse_packet(uint8_t *buffer, size_t length, packet *packet);
int write_packet(packet *packet, char *secret, uint8_t *data);
int lookup_attribute(packet *packet, int type, char *value, size_t value_size, size_t *length);
int lookup_password(packet *request, char *secret, char *password);

#endif
