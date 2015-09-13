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
 * \brief Function to allocate memory for an mqtt packet, including both fixed and variable
 *        header components.
 * \param pkt Pointer to the address of the new packet.
 * \param type The type of packet to be created.
 */
void init_packet_header(struct mqtt_packet **pkt_p, ctrl_pkt_type type) {

  struct mqtt_packet *pkt;
  int len = 0;

  /* fixed header - always the same size */
  len += sizeof(struct pkt_fixed_header);

  switch (type) {
    case CONNECT:
      /* variable header */
      len += sizeof(struct connect_variable_header);

      /* allocate header memory */
  if (!(pkt->fixed = calloc(1, sizeof(struct pkt_fixed_header)))) {
    printf("Error allocating space for fixed header");
    //free_packet
  }

  /* allocate variable header */
  if (!(pkt->variable = calloc(1, sizeof(struct pkt_variable_header)))) {
    printf("Error allocating space for variable header");
    //free_packet
  }

  /* allocate payload struct - NOT data */
  if (!(pkt->payload = calloc(1, sizeof(struct pkt_payload)))) {
    printf("Error allocating space for payload");
    //free_packet
  }

  *pkt_p = pkt;
  return;
}

void free_packet(struct mqtt_packet *pkt) {

}
  
void print_pkt_hex(struct mqtt_packet *pkt, int pkt_len) {
  int i;

  for (i = 0; i <= pkt_len; i++) {
    printf("0x0.2%X ", pkt + i);
  }

  return;
}

