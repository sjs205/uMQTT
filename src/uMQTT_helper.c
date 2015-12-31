/******************************************************************************
 * File: uMQTT_helper.c
 * Description: uMQTT helper fucntions - not necessarily required for general
                usage.
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

#include "uMQTT_helper.h"


/**
 * \brief Function to return the name of a give type.
 * \param type The type string to return.
 */
char *get_type_string(ctrl_pkt_type type) {
  char *ret = 0;

  switch (type) {
    case RESERVED_0:
    case RESERVED_15:
      ret = RESERVED_STR;
      break;

    case CONNECT:
      ret = CONNECT_STR;
      break;

    case CONNACK:
      ret = CONNACK_STR;
      break;

    case PUBLISH:
      ret = PUBLISH_STR;
      break;

    case PUBACK:
      ret = PUBACK_STR;
      break;

    case PUBREC:
      ret = PUBREC_STR;
      break;

    case PUBREL:
      ret = PUBREL_STR;
      break;

    case PUBCOMP:
      ret = PUBCOMP_STR;
      break;

    case SUBSCRIBE:
      ret = SUBSCRIBE_STR;
      break;

    case SUBACK:
      ret = SUBACK_STR;
      break;

    case UNSUBSCRIBE:
      ret = UNSUBSCRIBE_STR;
      break;

    case UNSUBACK:
      ret = UNSUBACK_STR;
      break;

    case PINGREQ:
      ret = PINGREQ_STR;
      break;

    case PINGRESP:
      ret = PINGRESP_STR;
      break;

    case DISCONNECT:
      ret = DISCONNECT_STR;
      break;
  }

  return ret;
}

/**
 * \brief Function to print memory in hex.
 * \param ptr The memory to start printing.
 * \param len The number of bytes to print.
 */
void print_memory_bytes_hex(void *ptr, size_t len) {
  size_t i;

  printf("%zu bytes starting at address 0x%p\n", len, &ptr);
  for (i = 0; i < len; i++) {
    printf("0x%02X ", ((uint8_t *)ptr)[i]);
  }
  printf("\n");

  return;
}

/**
 * \brief Function to print a packet.
 * \param pkt Pointer to the packet to be printed
 * \param len The number of bytes to print.
 */
void print_packet(struct mqtt_packet *pkt) {

  printf("\n%s Packet Type:\n", get_type_string(pkt->fixed->generic.type));

  printf("\nFixed header:\n");
  printf("Length: %zu\n", pkt->fix_len);
  print_memory_bytes_hex((void *)pkt->fixed, pkt->fix_len);

  if (pkt->var_len) {
    printf("\nVariable header:\n");
    printf("Length: %zu\n", pkt->var_len);
    print_memory_bytes_hex((void *)pkt->variable, pkt->var_len);
  } else {
    printf("\nNo Variable header.\n");
  }

  if (pkt->pay_len) {
    printf("\nPayload:\n");
    printf("Length: %zu\n", pkt->pay_len);
    print_memory_bytes_hex((void *)&pkt->payload->data,
        pkt->pay_len);
  } else {
    printf("\nNo Payload.\n");
  }

  printf("\nRaw packet:\n");
  print_memory_bytes_hex((void *)pkt->raw.buf, pkt->len);
}

