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
#include "../inc/log.h"

int main() {
  log_level(LOG_DEBUG);

  int ret;
  struct broker_conn *conn;

  init_linux_socket_connection(&conn, MQTT_BROKER_IP,
      sizeof(MQTT_BROKER_IP), 1883);
  if (!conn) {
    log_std(LOG_ERROR, "Initialising socket connection");
    free_linux_socket(conn);
    return -1;
  }

  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  if (broker_connect(conn)) {
    log_std(LOG_ERROR, "Initialising socket connection");
    free_linux_socket(conn);
    return -1;
  } else {
    log_std(LOG_INFO, "Connected to broker:\nip: %s port: %d", skt->ip, skt->port);
  }


  /* subscribe packet */
  struct mqtt_packet *sub_pkt = construct_default_packet(SUBSCRIBE, 0, 0);
  struct mqtt_packet *pub_pkt = construct_default_packet(PUBLISH, 0, 0);
  struct mqtt_packet *pkt = NULL;

  if (init_packet(&pkt)) {
    log_std(LOG_ERROR, "Initialising packet");
    free_linux_socket(conn);
    free_packet(sub_pkt);
    return -1;
  }

  /* Send SUBSCRIBE and wait for SUBACK - although, note that this could be
     a PUBLISH msg. */
  log_std(LOG_INFO, "\nSending Packet\n--------------");
  print_packet_hex_debug(sub_pkt);
  conn->send_method(conn, sub_pkt);

  ret = conn->receive_method(conn, pkt);
  if (ret) {
    log_std(LOG_ERROR, "SUBACK failed");
    goto free;
  }

  log_std(LOG_INFO, "\nReceived Packet\n---------------");
  print_packet_hex_debug(pkt);

  /* PUBLISH message */
  log_std(LOG_INFO, "\nSending Packet\n--------------");
  print_packet_hex_debug(pub_pkt);
  ret = conn->send_method(conn, pub_pkt);
  if (ret) {
    log_std(LOG_ERROR, "Sending PUBLISH message failed");
    goto free;
  }

  /* Wait for first message - should be the PUBLISH */
  ret = conn->receive_method(conn, pkt); 
  if (ret) {
    log_std(LOG_ERROR, "Receiving PUBLISH failed");
    goto free;
  }

  log_std(LOG_INFO, "\nReceived Packet\n---------------");
  print_packet_hex_debug(pkt);

  /* not fool proof */
  if (pkt->fixed->generic.type == PUBLISH) {
    log_std(LOG_INFO, "\n*** Tests Passed ***");
    ret = 0;
  } else {
    log_std(LOG_INFO, "\n*** Tests Failed ***");
    ret = -1;
  }

free:
  free_packet(pkt);
  free_packet(sub_pkt);
  free_packet(pub_pkt);

  broker_disconnect(conn);
  free_connection(conn);
  return ret;
}

