/******************************************************************************
 * File: uMQTT_client_test.c
 * Description: Program to create a test broker connection. 
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
#include "uMQTT_client.h"

#define MQTT_BROKER_IP        "127.0.0.1"
#define MQTT_BROKER_PORT      1883

int main() {
  struct broker_conn *conn;

  init_connection(&conn, MQTT_BROKER_IP, sizeof(MQTT_BROKER_IP), 1883);
  if (!conn)
    return -1;
  
  printf("New broker connection:\nip: %s port: %d\n", conn->ip, conn->port);

  /* connect packet */

  struct mqtt_packet *con_pkt = construct_default_packet(CONNECT, 0, 0);

  print_packet(con_pkt);

  broker_connect(conn);

  send_packet(conn, (struct raw_pkt *)con_pkt->raw.buf);
//rx_pkt->len = read_packet(conn, rx_pkt);

  printf("CONNECT packet sent...\n");
  free_pkt(con_pkt);

  /* publish packet */
  struct mqtt_packet *pub_pkt = construct_default_packet(PUBLISH,
      "uMQTT test PUBLISH packet", sizeof("uMQTT test PUBLISH packet"));

  print_packet(pub_pkt);
  send_packet(conn, (struct raw_pkt *)pub_pkt->raw.buf);

  free_pkt(pub_pkt);

  do {

  } while (1);
}

