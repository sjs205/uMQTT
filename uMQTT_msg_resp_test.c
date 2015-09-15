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

int main() {
  struct broker_conn *conn;
  struct mqtt_packet *pkt = '\0';

  init_packet(&pkt);

  init_packet_header(pkt, CONNECT);

  init_packet_payload(pkt, CONNECT);

  printf("Length of new packet = %d\n", pkt->length);

  printf("Fixed header:\n");
  print_memory_bytes_hex((void *)pkt->fixed, 1);
  printf("Variable header:\n");
  print_memory_bytes_hex((void *)pkt->variable, 0x0A);
  printf("Payload:\n");
  print_memory_bytes_hex((void *)&pkt->payload->data, 7);

  init_connection(&conn);
  if (!conn)
    return -1;

  broker_connect(conn);

  struct raw_pkt *tx_pkt, *rx_pkt;
  init_raw_packet(&tx_pkt);
  init_raw_packet(&rx_pkt);

  memcpy((void *)tx_pkt->buf,pkt->fixed,  2);
  memcpy( (void *)&tx_pkt->buf[2],pkt->variable, 0x0A);

  tx_pkt->len = 0x0A + 0x01;

  memcpy((void *)tx_pkt->buf,pkt->fixed,  2);
  memcpy((void *)&tx_pkt->buf[2],pkt->variable, 0x0A);
  memcpy((void *)&tx_pkt->buf[11],&pkt->payload->data, 7);

  tx_pkt->len = 0x0A + 0x01+ 6;

  printf("TX packet:\n");
  print_memory_bytes_hex((void *)tx_pkt->buf, tx_pkt->len);


  send_packet(conn, tx_pkt);

  rx_pkt->len = read_packet(conn, rx_pkt);
  printf("RX packet:\n");
  print_memory_bytes_hex((void *)rx_pkt->buf, rx_pkt->len);


  do {
  }while (1);
}

