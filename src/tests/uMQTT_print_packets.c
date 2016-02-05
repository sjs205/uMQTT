/******************************************************************************
 * File: uMQTT_print_packets.c
 * Description: Program to create and print the default packets supported
 *              by uMQTT.
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

#include <string.h>

#include "uMQTT.h"
#include "uMQTT_helper.h"
#include "../inc/log.h"

void print_struct_sizes() {

  log_stdout(LOG_INFO, "\n\nThe following shows the compile-time sizes of a number of variables used:\n");

  log_stdout(LOG_INFO, "UMQTT_MAX_PACKET_LEN \t\t\t\t\t\t%d\n", UMQTT_MAX_PACKET_LEN);

  log_stdout(LOG_INFO, "sizeof(struct mqtt_packet): \t\t\t\t\t%zu bytes",
      sizeof(struct mqtt_packet));
  log_stdout(LOG_INFO, "{");
  log_stdout(LOG_INFO, "\tsizeof(struct pkt_fixed_header): \t\t\t%zu bytes",
      sizeof(struct pkt_fixed_header));
  log_stdout(LOG_INFO, "\t{");
  log_stdout(LOG_INFO, "\t\tsizeof(struct pkt_generic_fixed_header): \t%zu bytes",
      sizeof(struct pkt_generic_fixed_header));
  log_stdout(LOG_INFO, "\t\tsizeof(struct pkt_publish_fixed_header): \t%zu bytes",
      sizeof(struct pkt_publish_fixed_header));
  log_stdout(LOG_INFO, "\t}");
  log_stdout(LOG_INFO, "\tsizeof(struct pkt_variable_header): \t\t\t%zu bytes",
      sizeof(struct pkt_variable_header));
  log_stdout(LOG_INFO, "\t{");
  log_stdout(LOG_INFO, "\t\tsizeof(struct generic_variable_header): \t%zu bytes",
      sizeof(struct generic_variable_header));
  log_stdout(LOG_INFO, "\t\tsizeof(struct connect_variable_header): \t%zu bytes",
      sizeof(struct connect_variable_header));
  log_stdout(LOG_INFO, "\t\tsizeof(struct connack_variable_header): \t%zu bytes",
      sizeof(struct connack_variable_header));
  log_stdout(LOG_INFO, "\t\tsizeof(struct publish_variable_header): \t%zu bytes",
      sizeof(struct publish_variable_header));
  log_stdout(LOG_INFO, "\t}");
  log_stdout(LOG_INFO, "\tsizeof(struct pkt_payload): \t\t\t\t%zu bytes",
      sizeof(struct pkt_payload));
  log_stdout(LOG_INFO, "\n\tsizeof(struct raw_pkt): \t\t\t\t%zu bytes",
      sizeof(struct raw_pkt));

  log_stdout(LOG_INFO, "}");
  log_stdout(LOG_INFO, "\n\nsizeof(struct utf8_enc_str): \t\t\t\t\t%zu bytes",
      sizeof(struct utf8_enc_str));

  return;
}


int main() {
  log_level(LOG_DEBUG);

  struct mqtt_packet *pkt;

  /* connect packet */
  pkt = construct_default_packet(CONNECT, 0, 0);

  print_packet(pkt);

  free_packet(pkt);

  /* publish packet */
  pkt = construct_default_packet(PUBLISH,
      (uint8_t *)"uMQTT test PUBLISH packet",
      sizeof("uMQTT test PUBLISH packet"));

  print_packet(pkt);

  free_packet(pkt);

  /* subscribe packet */
  pkt = construct_default_packet(SUBSCRIBE, 0, 0);

  print_packet(pkt);

  free_packet(pkt);

  /* pingreq packet */
  pkt = construct_default_packet(PINGREQ, 0, 0);

  print_packet(pkt);

  free_packet(pkt);

  /* pingresp packet */
  pkt = construct_default_packet(PINGRESP, 0, 0);

  print_packet(pkt);

  free_packet(pkt);

  /* disconnect packet */
  pkt = construct_default_packet(DISCONNECT, 0, 0);

  print_packet(pkt);

  free_packet(pkt);

  print_struct_sizes();

  return 0;
}

