#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <stdint.h>

#include "radius.h"
#include "md5.h"

int parse_packet(uint8_t *buffer, size_t length, packet *packet) {
    if (length < 20) { // minimum packet size
        return -1;
    }

    packet->code = buffer[0];
    packet->identifier = buffer[1];
    packet->length = (buffer[2] << 8) + buffer[3];

    if (packet->length > 4096 || packet->length > length) {
        return -1;
    }

    packet->authenticator = &buffer[4];
    packet->attributes = &buffer[20];
    packet->attributes_length = packet->length - 20;

    return 0;
}

int write_packet(packet *packet, char *secret, uint8_t *data) {
    data[0] = packet->code;
    data[1] = packet->identifier;
    data[2] = packet->length >> 8;
    data[3] = packet->length;
    memcpy(&data[20], packet->attributes, packet->attributes_length);

    // ResponseAuth =
    //     MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) data, 4); // Code+ID+Length
    MD5Update(&context, (uint8_t*) packet->authenticator, 16);
    MD5Update(&context, (uint8_t*) &data[20], data[3] - 20);
    MD5Update(&context, (uint8_t*) secret, strlen(secret));
    MD5Final(&data[4], &context);

    return 0;
}

int lookup_attribute(packet *packet, int type, char *value, size_t value_size, size_t *length) {
    int rem = packet->attributes_length;
    uint8_t *p = packet->attributes;

    while (rem > 2) {
        uint8_t kvp_type = p[0];
        uint8_t kvp_length = p[1];
        if (kvp_length > rem) {
            perror("kvp_length > rem");
            break;
        }

        size_t kvp_value_length = kvp_length - 2;

        if (kvp_type == type && kvp_length > 0) {
            if (kvp_value_length + 1 > value_size) {
                fprintf(stderr, "value too large\n");
                break;
            }
            memcpy(value, p + 2, kvp_value_length);
            value[kvp_value_length] = '\0';

            if (length != NULL) {
                *length = kvp_value_length;
            }

            return 0; // found
        }

        rem -= kvp_length;
        p += kvp_length;
    }

    return -1; // not found
}

int lookup_password(packet *request, char *secret, char *password) {
    uint8_t b[16];
    MD5_CTX context;
    int e;
    char cs[129];
    size_t cs_length = 0;

    e = lookup_attribute(request, UserPassword, cs, sizeof(cs), &cs_length);
    if (e < 0) {
        fprintf(stderr, "attribute not found\n");
        return -1;
    }

    if (cs_length == 0 || cs_length % 16 != 0) {
        fprintf(stderr, "invalid password attribute length\n");
        return -1;
    }

    int secret_len = strlen(secret);
    for (unsigned int k = 0; k < cs_length; k += 16) {
        MD5Init(&context);
        MD5Update(&context, (uint8_t*) secret, secret_len);
        if (k == 0) {
            MD5Update(&context, request->authenticator, AUTHENTICATOR_SIZE);
        } else {
            MD5Update(&context, (uint8_t*) &cs[k - 16], 16);
        }
        MD5Final(&b[0], &context); // TODO type ?

        for (int j = 0; j < 16; j++) {
            password[k + j] = b[j] ^ cs[k + j];
        }
    }

    return 0;
}
