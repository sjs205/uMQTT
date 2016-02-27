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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uMQTT_helper.h"
#include "../inc/log.h"

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

  char buf[5 * len];
  buf[0] = '\0';

  char tbuf[10] = "\0";

  log_stderr(LOG_DEBUG, "%zu bytes starting at address 0x%p", len, &ptr);
  for (i = 0; i < len; i++) {
    sprintf(tbuf, "0x%02X ", ((uint8_t *)ptr)[i]);
    strcat(buf, tbuf);
  }
  log_stderr(LOG_DEBUG, "%s", buf);

  return;
}

/**
 * \brief Function to print a packet.
 * \param pkt Pointer to the packet to be printed
 */
void print_packet(struct mqtt_packet *pkt) {

  log_stderr(LOG_DEBUG, "%s Packet Type:", get_type_string(pkt->fixed->generic.type));

  log_stderr(LOG_DEBUG, "Fixed header:");
  log_stderr(LOG_DEBUG, "Length: %zu", pkt->fix_len);
  print_memory_bytes_hex((void *)pkt->fixed, pkt->fix_len);

  if (pkt->var_len) {
    log_stderr(LOG_DEBUG, "Variable header:");
    log_stderr(LOG_DEBUG, "Length: %zu", pkt->var_len);
    print_memory_bytes_hex((void *)pkt->variable, pkt->var_len);
  } else {
    log_stderr(LOG_DEBUG, "No Variable header.");
  }

  if (pkt->pay_len) {
    log_stderr(LOG_DEBUG, "Payload:");
    log_stderr(LOG_DEBUG, "Length: %zu", pkt->pay_len);
    print_memory_bytes_hex((void *)&pkt->payload->data,
        pkt->pay_len);
  } else {
    log_stderr(LOG_DEBUG, "No Payload.");
  }

  log_stderr(LOG_DEBUG, "Raw packet:");
  print_memory_bytes_hex((void *)pkt->raw.buf, pkt->len);
}

/**
 * \brief Function to print a PUBLISH packet.
 * \param pkt Pointer to the publish packet to be printed
 */
void print_publish_packet(struct mqtt_packet *pkt) {

  if (pkt->fixed->generic.type == PUBLISH) {
    char buf[1024];

    log_stdout(LOG_INFO, "\nPUBLISH MSG");

    uint16_t len = (uint16_t)((pkt->variable->publish.topic.len_msb << 8)
        | (pkt->variable->publish.topic.len_lsb));
    strncpy(buf, &pkt->variable->publish.topic.utf8_str, len);
    buf[len] = '\0';
    log_stdout(LOG_INFO, "TOPIC: %s", buf);

    strncpy(buf, (char *)&pkt->payload->data, pkt->pay_len);
    buf[pkt->pay_len] = '\0';
    log_stdout(LOG_INFO, "PAYLOAD:\n%s", buf);
  }

  return;
}

/**
 * \brief Function to generate a unique string to be used
 *        as part of the default clientid.
 * \param str Buffer to store generated string.
 * \param len Length of the string to generate.
 */
void gen_unique_string(char *str, size_t len) {

  const char charset[] = UNIQUE_STR_CHARSET;
  size_t i;

  srand(time(NULL));
  if (len) {
    --len;
    for (i = 0; i < len; i++) {
      int key = rand() % (int) (sizeof(charset) - 1);
      str[i] = charset[key];
    }
    str[len] = '\0';
  }
}
