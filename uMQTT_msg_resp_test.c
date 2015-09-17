/******************************************************************************
 * File: uMQTT_msg_resp_test.c
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
#include "uMQTT_msg_resp.h"

#define MQTT_BROKER_IP        "127.0.0.1"
#define MQTT_BROKER_PORT      1883

int main() {
  struct broker_conn *conn;

  init_connection(&conn, MQTT_BROKER_IP, sizeof(MQTT_BROKER_IP), 1883);
  if (!conn)
    return -1;
  
  printf("New broker connection:\nip: %s port: %d\n", conn->ip, conn->port);

  struct mqtt_packet *pkt = '\0';

  init_packet(&pkt);

  init_packet_header(pkt, CONNECT);

  init_packet_payload(pkt, CONNECT);

  printf("\nFixed header:\n");
  printf("Length: %d\n", pkt->fix_len);
  print_memory_bytes_hex((void *)pkt->fixed, pkt->fix_len);

  printf("\nVariable header:\n");
  printf("Length: %d\n", pkt->var_len);
  print_memory_bytes_hex((void *)pkt->variable, pkt->var_len);

  printf("\nPayload:\n");
  printf("Length: %d\n", pkt->pay_len);
  print_memory_bytes_hex((void *)&pkt->payload->data, pkt->pay_len);

  printf("\nTotal Length of new packet = %d\n", pkt->len);


  broker_connect(conn);

  struct raw_pkt *tx_pkt, *rx_pkt;
  init_raw_packet(&tx_pkt);
  tx_pkt->len = pkt->len;
  init_raw_packet(&rx_pkt);

  unsigned int offset = 0;
  memcpy((void *)tx_pkt->buf, pkt->fixed, pkt->fix_len);
  memcpy((void *)&tx_pkt->buf[pkt->fix_len], pkt->variable, pkt->var_len);
  memcpy((void *)&tx_pkt->buf[pkt->fix_len + pkt->var_len],&pkt->payload->data, pkt->pay_len);

  printf("\nTX packet:\n");
  print_memory_bytes_hex((void *)tx_pkt->buf, tx_pkt->len);


  send_packet(conn, tx_pkt);

  rx_pkt->len = read_packet(conn, rx_pkt);
  printf("\nRX packet:\n");
  print_memory_bytes_hex((void *)rx_pkt->buf, rx_pkt->len);



  do {

  } while (1);
}

