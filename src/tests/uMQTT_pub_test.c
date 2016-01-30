/******************************************************************************
 * File: uMQTT_pub_test.c
 * Description: Program to create a test Linux socket broker connection and
 *              send a publish message before disconnecting from the broker.
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
#include "uMQTT_linux_client.h"
#include "uMQTT_helper.h"

/* ip of test.mosquitto.org - need to perform dns lookup
   using gethostbyname */
#define MQTT_BROKER_IP        "85.119.83.194"
#define MQTT_BROKER_PORT      1883

int main() {
  struct broker_conn *conn;

  init_linux_socket_connection(&conn, MQTT_BROKER_IP,
      sizeof(MQTT_BROKER_IP), 1883);
  if (!conn) {
    printf("Error: Initialising socket connection\n");
    free_linux_socket(conn);
    return -1;
  }

  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  if (broker_connect(conn)) {
    printf("Error: Initialising socket connection\n");
    free_linux_socket(conn);
    return -1;
  } else {
    printf("Connected to broker:\nip: %s port: %d\n", skt->ip, skt->port);
  }


  /* publish packet */
  struct mqtt_packet *pub_pkt = construct_default_packet(PUBLISH,
      (uint8_t *)"uMQTT test PUBLISH packet",
      sizeof("uMQTT test PUBLISH packet"));

  print_packet(pub_pkt);
  conn->send_method(conn, pub_pkt);

  free_packet(pub_pkt);

  broker_disconnect(conn);

  free_connection(conn);

  return 0;
}

