/******************************************************************************
 * File: uMQTT.c
 * Description: MicroMQTT (uMQTT) library implementation suitable for
 *              constrained environments.
 * Author: Steven Swann - swannonline@googlemail.com
 *
 * Copyright (c) swannonline, 2013-2014
 * 
 * This file is part of uMQTT.
 *
 * uMQTT is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * uMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with uMQTT.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "uMQTT.h"

/**
 * \brief Function to allocate memory for an mqtt packet.
 * \param pkt Pointer to the address of the new packet.
 */
void init_packet(struct mqtt_packet **pkt_p) {
  struct mqtt_packet *pkt;

  if (!(pkt = calloc(1, sizeof(struct mqtt_packet)))) {
    printf("Error: Allocating space for MQTT packet failed.\n");
    //free_packet
  }

  *pkt_p = pkt;

  return;
}

/**
 * \brief Function to allocate memory for mqtt packet headers
 *        including both fixed and variable header components.
 * \param pkt Pointer to the address of the packet containing headers.
 * \param type The type of packet to be created.
 * \retrun Length of new packet headers
 */
int init_packet_header(struct mqtt_packet *pkt, ctrl_pkt_type type) {

  unsigned int fix_len = 0;
  unsigned int var_len = 0;

  /* allocate fixed header memory - always same size*/
  fix_len = sizeof(struct pkt_fixed_header);
  if (!(pkt->fixed = calloc(1, fix_len))) {
    printf("Error: Allocating space for fixed header failed.\n");
    //free_packet
  }

  //pkt->fixed->ps.reserved = 6;
  pkt->fixed->connect.type = type;

  switch (type) {
    case CONNECT:
      /* variable header */
      var_len = sizeof(struct connect_variable_header);
      break;

    case PUBLISH:
      /* variable header */
      var_len = sizeof(struct publish_variable_header);
      break;

    default:
      printf("Error: MQTT packet type not currently supported.\n");
      return 0;
  }

  /* allocate variable header */
  if (!(pkt->variable = calloc(1, var_len))) {
    printf("Error: Allocating space for variable header failed.\n");
    //free_packet
  }

  /* debug */
  printf("Length of fixed packet header: %d\n", fix_len);
  printf("Length of variable packet header: %d\n", var_len);

  pkt->length = fix_len + var_len;

  encode_remaining_pkt_len(pkt, var_len);

  return pkt->length;
}

/**
 * \brief Function to encode the remaining length of an MQTT packet, after the fixed header,
 *        into the fixed packet header - see section 2.2.3 of the MQTT spec.
 * \param pkt The packet whose length to encode.
 * \param len The length that should be encoded.
 */
void encode_remaining_pkt_len(struct mqtt_packet *pkt, unsigned int len) {
  int i = 0;
  do {
    pkt->fixed->remain_len[i] = len % 128;
    len /= 128;

    if (len > 0) {
      pkt->fixed->remain_len[i] |= 128;
    }
    i++;
  } while (len > 0 && i < 4);

  return;
}

/**
 * \brief Function to decode the remain_len variable in the fixed header of an MQTT packet
 *        into an int - see section 2.2.3 of the MQTT spec.
 * \param pkt The packet whose length to decode.
 * \return The length that should be encoded.
 */
unsigned int decode_remaining_pkt_len(struct mqtt_packet *pkt) {
  int i = 0;
  unsigned int len = 0;
  unsigned int product = 1;
  do {
    len += (pkt->fixed->remain_len[i] & 127) * product;

    if (product > 128*128*128) {
      printf("Error: Malformed remaining length.\n");
      return 0;
    }
    product *= 128;

  } while ((pkt->fixed->remain_len[i++] & 128) != 0 && i < 4);

  return len;
}

void free_pkt_fixed_header(struct pkt_fixed_header *fixed) {
  free(fixed);
  return;
}
  
void print_memory_bytes_hex(void *ptr, int bytes) {
  int i;

  printf("%d bytes starting at address 0x%X\n", (bytes + 1), &ptr);
  for (i = 0; i <= bytes; i++) {
    printf("0x%02X ", ((uint8_t *)ptr)[i]);
  }

  return;
}

