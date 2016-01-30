/******************************************************************************
 * File: uMQTT_sub_test.c
 * Description: Program to create a test Linux socket broker connection and
 *              send a sublish message before disconnecting from the broker.
 * Author: Steven Swann - swannonline@googlemail.com
 *
 * Copyright (c) swannonline, 2013-2014
 *
 * This file is part of uMQTT.
 *
 * uMQTT is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as sublished by
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
#define MQTT_BROKER_IP        "127.0.0.1"
#define MQTT_BROKER_PORT      1883

int main() {
  int ret;
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


  /* subscribe packet */
  struct mqtt_packet *sub_pkt = construct_default_packet(SUBSCRIBE, 0, 0);
  struct mqtt_packet *pub_pkt = construct_default_packet(PUBLISH, 0, 0);

  struct mqtt_packet *pkt = NULL;
  if (init_packet(&pkt)) {
    printf("Error: Initialising packet\n");
    free_linux_socket(conn);
    free_packet(sub_pkt);
    return -1;
  }

  /* Send SUBSCRIBE and wait for SUBACK - although, note that this could be
     a PUBLISH msg. */
  printf("\n\nSending Packet\n--------------\n");
  print_packet(sub_pkt);
  conn->send_method(conn, sub_pkt);

  pkt->len = conn->receive_method(conn, pkt); 
  disect_raw_packet(pkt);
  if (pkt->fixed->generic.type != SUBACK && pkt->payload->data != 0x00) {
    printf("Error, incorrect SUBACK return\n");
    return -1;
  }
    
  printf("\n\nReceived Packet\n---------------\n");
  print_packet(pkt);

  /* PUBLISH message */
  printf("\n\nSending Packet\n--------------\n");
  print_packet(pub_pkt);
  conn->send_method(conn, pub_pkt);

  /* Wait for first message - should be the PUBLISH */
  pkt->len = conn->receive_method(conn, pkt); 
  printf("\n\nReceived Packet\n---------------\n");
  disect_raw_packet(pkt);
  print_packet(pkt);

  /* not fool proof */
  if (pkt->fixed->generic.type == PUBLISH) {
    printf("\n*** Tests Passed ***\n");
    ret = 0;
  } else {
    printf("\n*** Tests Failed ***\n");
    ret = -1;
  }

  broker_disconnect(conn);

  free_connection(conn);
  free_packet(pkt);
  free_packet(sub_pkt);
  free_packet(pub_pkt);

  return ret;
}

