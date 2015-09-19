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

  /* connect */

  struct mqtt_packet *con_pkt = '\0';

  init_packet(&con_pkt);

  init_packet_fixed_header(con_pkt, CONNECT);
  init_packet_variable_header(con_pkt, CONNECT);

  init_packet_payload(con_pkt, CONNECT, '\0', 0);

  printf("\nFixed header:\n");
  printf("Length: %d\n", con_pkt->fix_len);
  print_memory_bytes_hex((void *)con_pkt->fixed, con_pkt->fix_len);

  printf("\nVariable header:\n");
  printf("Length: %d\n", con_pkt->var_len);
  print_memory_bytes_hex((void *)con_pkt->variable, con_pkt->var_len);

  printf("\nPayload:\n");
  printf("Length: %d\n", con_pkt->pay_len);
  print_memory_bytes_hex((void *)&con_pkt->payload->data,
      con_pkt->pay_len);

  printf("\nTotal Length of new packet = %d\n", con_pkt->len);

  broker_connect(conn);

  struct raw_pkt *tx_pkt, *rx_pkt;
  init_raw_packet(&tx_pkt);
  tx_pkt->len = con_pkt->len;
  init_raw_packet(&rx_pkt);

  memcpy((void *)tx_pkt->buf, con_pkt->fixed, con_pkt->fix_len);
  memcpy((void *)&tx_pkt->buf[con_pkt->fix_len], con_pkt->variable,
      con_pkt->var_len);
  memcpy((void *)&tx_pkt->buf[con_pkt->fix_len + con_pkt->var_len],
      &con_pkt->payload->data, con_pkt->pay_len);

  printf("\nTX packet:\n");
  print_memory_bytes_hex((void *)tx_pkt->buf, tx_pkt->len);


  send_packet(conn, tx_pkt);

  rx_pkt->len = read_packet(conn, rx_pkt);
  printf("\nRX packet:\n");
  print_memory_bytes_hex((void *)rx_pkt->buf, rx_pkt->len);

  /* publish */
  struct mqtt_packet *pub_pkt = '\0';

  init_packet(&pub_pkt);

  init_packet_fixed_header(pub_pkt, PUBLISH);
  init_packet_variable_header(pub_pkt, PUBLISH);

  init_packet_payload(pub_pkt, PUBLISH, "hi", 2);

  printf("\nFixed header:\n");
  printf("Length: %d\n", pub_pkt->fix_len);
  print_memory_bytes_hex((void *)pub_pkt->fixed, pub_pkt->fix_len);

  printf("\nVariable header:\n");
  printf("Length: %d\n", pub_pkt->var_len);
  print_memory_bytes_hex((void *)pub_pkt->variable, pub_pkt->var_len);

  
  printf("\nPayload:\n");
  printf("Length: %d\n", pub_pkt->pay_len);
  print_memory_bytes_hex((void *)&pub_pkt->payload->data,
      pub_pkt->pay_len);

  printf("\nTotal Length of new packet = %d\n", pub_pkt->len);

  tx_pkt->len = pub_pkt->len;

  memcpy((void *)tx_pkt->buf, pub_pkt->fixed, pub_pkt->fix_len);
  memcpy((void *)&tx_pkt->buf[pub_pkt->fix_len], pub_pkt->variable,
      pub_pkt->var_len);
  memcpy((void *)&tx_pkt->buf[pub_pkt->fix_len + pub_pkt->var_len],
      &pub_pkt->payload->data, pub_pkt->pay_len);

  printf("\nTX packet:\n");
  print_memory_bytes_hex((void *)tx_pkt->buf, tx_pkt->len);


  send_packet(conn, tx_pkt);

  memset(rx_pkt, 0, 1024);
  rx_pkt->len = read_packet(conn, rx_pkt);
  printf("\nRX packet:\n");
  print_memory_bytes_hex((void *)rx_pkt->buf, rx_pkt->len);
  

  do {

  } while (1);
}

