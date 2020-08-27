#ifndef RADIUS_H
#define RADIUS_H

#define AUTHENTICATOR_SIZE 16

enum radius_attribute {
  UserName = 1,
  UserPassword = 2,
};

enum radius_packet_type {
  AccessRequest = 1,
  AccessAccept = 2,
  AccessReject = 3,
};


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
