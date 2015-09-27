/******************************************************************************
 * File: uMQTT_client.c
 * Description: Functions to implement socket based client.
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
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

#include "inc/uMQTT.h"
#include "inc/uMQTT_client.h"

/**
 * \brief Function to allocate memory for a broker connection struct.
 * \param conn_p Pointer to the address of the new connection struct.
 */
void init_connection(struct broker_conn **conn_p, char *ip, unsigned int ip_len,  unsigned int port) {
  struct broker_conn *conn;

  if (!(conn = calloc(1, sizeof(struct broker_conn)))) {
    printf("Error: Allocating space for the broker connection failed.\n");
    free_connection(conn);
  }

  /* the following should be dynamic */
  conn->serv_addr.sin_family = AF_INET;
  conn->port = port;
  conn->serv_addr.sin_port = htons(conn->port); 
  memcpy(conn->ip, ip, ip_len);

  *conn_p = conn;

  return;
}

/**
 * \brief Function to connect to broker socket and send a
 *        CONNECT packet..
 * \param conn Pointer to the broker_conn struct.
 * \return mqtt_ret
 */
umqtt_ret broker_connect(struct broker_conn *conn) {

  if ((conn->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("Error: Could not create socket\n");
    return UMQTT_CONNECT_ERROR;
  } 

  /* convert ip address to binary */
  if (inet_pton(conn->serv_addr.sin_family, conn->ip,
        &conn->serv_addr.sin_addr) <= 0)
  {
    printf("ERROR: inet_pton error occured\n");
    return UMQTT_CONNECT_ERROR;
  } 

  if (connect(conn->sockfd, (struct sockaddr *)&conn->serv_addr,
        sizeof(conn->serv_addr)) < 0)
  {
    printf("Error: Connect Failed\n");
    return UMQTT_CONNECT_ERROR;
  } 

  /* send connect packet */
  struct mqtt_packet *pkt = construct_default_packet(CONNECT, 0, 0);
  size_t ret = send_packet(conn, &pkt->raw);

  free_packet(pkt);
  
  if (!ret) {
    printf("\n Error:Connect Packet Failed\n");
    return UMQTT_CONNECT_ERROR;
  }
  
  /* get response */
  struct mqtt_packet *pkt_resp;
  if (init_packet(&pkt_resp)) {
    printf("\n Error: Allocatiing memory\n");
    return UMQTT_MEM_ERROR;
  }

  pkt_resp->len = read_packet(conn, &pkt_resp->raw);
  if (!pkt_resp->len) {
    printf("\n Error: Connect Packet Failed\n");
    return UMQTT_CONNECT_ERROR;
  }

  disect_raw_packet(pkt);

  /* Processing response */
  if (pkt_resp->fixed->generic.type == CONNACK &&
      pkt_resp->variable->connack.connect_ret == CONN_ACCEPTED) {
    printf("Successfully connected to the MQTT broker.\n");
    conn->state = 1;
    free_packet(pkt_resp);

    return UMQTT_SUCCESS;

  } else {
    printf("Error: Failed to connect the MQTT broker.\n");
    free_packet(pkt_resp);

    return UMQTT_CONNECT_ERROR;

  }
}

/**
 * \brief Function to send DISCONNECT packet and close the connection
 * \param conn The connection to close.
 */
umqtt_ret broker_disconnect(struct broker_conn *conn) {

  if (conn->state) {
    /* disconnect from active session */
    struct mqtt_packet *pkt = construct_default_packet(DISCONNECT, 0, 0);

    if (!pkt) {
      return UMQTT_DISCONNECT_ERROR;
    }

    if (!send_packet(conn, &pkt->raw)) {
      return UMQTT_PACKET_ERROR;
    }
  }

  if (conn->sockfd) {
    if (close(conn->sockfd)) {
      return UMQTT_DISCONNECT_ERROR;
    }
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to send packet to the to the broker socket.
 * \param conn Pointer to the croker_conn struct.
 * \param pkt Pointer to the packet to be sent.
 */
size_t send_packet(struct broker_conn *conn, struct raw_pkt *pkt) {
  size_t n = write(conn->sockfd,pkt->buf, *pkt->len); //strlen(pkt->buf));
  if (n < 0) 
    printf("ERROR: writing to socket\n");
  return n;
}

/**
 * \brief Function to recieve packetfrom the broker socket.
 * \param conn Pointer to the croker_conn struct.
 * \param pkt Pointer to the reciever buffer/packet.
 * \return Number of bytes read.
 */
size_t read_packet(struct broker_conn *conn, struct raw_pkt *pkt) {
  size_t n = read(conn->sockfd, pkt->buf, sizeof(pkt->buf) - 1);
  if (n < 0) 
    printf("ERROR: reading from socket\n");
  return n;
}

/**
 * \brief Function to print memory in hex.
 * \param ptr The memory to start printing.
 * \param len The number of bytes to print.
 */
void print_memory_bytes_hex(void *ptr, size_t len) {
  size_t i;

  printf("%zu bytes starting at address 0x%p\n", len, &ptr);
  for (i = 0; i < len; i++) {
    printf("0x%02X ", ((uint8_t *)ptr)[i]);
  }
  printf("\n");

  return;
}

/**
 * \brief Function to print a packet.
 * \param pkt Pointer to the packet to be printed
 * \param len The number of bytes to print.
 */
void print_packet(struct mqtt_packet *pkt) {

  printf("\nFixed header:\n");
  printf("Length: %zu\n", pkt->fix_len);
  print_memory_bytes_hex((void *)pkt->fixed, pkt->fix_len);

  printf("\nVariable header:\n");
  printf("Length: %zu\n", pkt->var_len);
  print_memory_bytes_hex((void *)pkt->variable, pkt->var_len);

  printf("\nPayload:\n");
  printf("Length: %zu\n", pkt->pay_len);
  print_memory_bytes_hex((void *)&pkt->payload->data,
      pkt->pay_len);

  printf("\nTotal Length of new packet = %zu\n", pkt->len);

  printf("\nTX packet:\n");
  print_memory_bytes_hex((void *)pkt->raw.buf, pkt->len);
}

/**
 * \brief Function to free memory allocated to struct broker_conn.
 * \param conn The connection to free.
 */
void free_connection(struct broker_conn *conn) {
  if (conn) {
    free(conn);
  }

  return;
}
