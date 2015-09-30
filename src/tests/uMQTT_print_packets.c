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

int main() {

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

  return 0;
}

