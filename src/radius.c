#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <stdint.h>

#include "radius.h"
#include "md5.h"

int parse_packet(uint8_t *buffer, size_t length, packet *packet) {
    if (length < HEADER_SIZE) { // minimum packet size
        return -1;
    }

    packet->code = buffer[0];
    packet->identifier = buffer[1];
    packet->length = (buffer[2] << 8) + buffer[3];

    if (packet->length < HEADER_SIZE || packet->length > 4096 || packet->length > length) {
        return -1;
    }

    packet->authenticator = &buffer[4];
    packet->attributes = &buffer[20];

    return 0;
}

int write_packet(packet *packet, char *secret, uint8_t *data) {
    data[0] = packet->code;
    data[1] = packet->identifier;
    data[2] = packet->length >> 8;
    data[3] = packet->length;
    memcpy(&data[20], packet->attributes, packet->length - HEADER_SIZE);

    // ResponseAuth =
    //     MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) data, 4); // Code+ID+Length
    MD5Update(&context, (uint8_t*) packet->authenticator, AUTHENTICATOR_SIZE);
    MD5Update(&context, (uint8_t*) &data[20], packet->length - HEADER_SIZE);
    MD5Update(&context, (uint8_t*) secret, strlen(secret));
    MD5Final(&data[4], &context);

    return 0;
}

int lookup_attribute(packet *packet, int type, char *value, size_t value_size, size_t *length) {
    int rem = packet->length - HEADER_SIZE;
    uint8_t *p = packet->attributes;
    uint8_t attr_type, attr_length;
    uint8_t *attr_value;

    while (rem > 2) {
        attr_type = p[0];
        attr_length = p[1];
        attr_value = &p[2];

        if (attr_length < 2 || attr_length > rem) {
            fprintf(stderr, "attr_length < 2 || attr_length > rem\n");
            return -1;
        }
        
        if (attr_type == type) {
            size_t attr_value_length = attr_length - 2;
            if (attr_value_length + 1 > value_size) {
                fprintf(stderr, "value too large\n");
                return -1;
            }

            memcpy(value, attr_value, attr_value_length);
            value[attr_value_length] = '\0';

            if (length != NULL) {
                *length = attr_value_length;
            }
            return 0; // found
        }

        rem -= attr_length;
        p += attr_length;
    }

    return -1; // not found
}

int lookup_password(packet *request, char *secret, char *password) {
    uint8_t b[16];
    MD5_CTX context;
    int e;
    char cs[129];
    size_t cs_length;

    e = lookup_attribute(request, UserPassword, cs, sizeof cs, &cs_length);
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
        MD5Final(&b[0], &context);

        for (int j = 0; j < 16; j++) {
            password[k + j] = b[j] ^ cs[k + j];
        }
    }

    return 0;
}
