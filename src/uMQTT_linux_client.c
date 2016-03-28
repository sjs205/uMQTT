/******************************************************************************
 * File: uMQTT_linux_client.c
 * Description: Functions to implement socket based Linux client.
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
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "uMQTT_linux_client.h"
#include "uMQTT_helper.h"
#include "inc/log.h"

/**
 * \brief Function to initialise socket based broker connection struct.
 * \param conn_p Pointer to the address of the new connection struct.
 * \param ip Pointer to the IP address string.
 * \param ip_len The length of the IP address string.
 * \param port The port to connect to.
 */
void init_linux_socket_connection(struct broker_conn **conn_p, char *ip, unsigned int ip_len,
    unsigned int port) {
  log_stderr(LOG_DEBUG, "fn: init_linux_socket_connection");

  struct broker_conn *conn;

  init_connection(&conn);
  struct linux_broker_socket *skt = '\0';

  if (conn && (!(skt = calloc(1, sizeof(struct linux_broker_socket))))) {
      log_stderr(LOG_ERROR, "Allocating space for the broker connection failed");
      free_linux_socket(conn);
      return;
  }

  skt->serv_addr.sin_family = AF_INET;
  skt->port = port;
  skt->serv_addr.sin_port = htons(skt->port);
  memcpy(skt->ip, ip, ip_len);

  register_connection_methods(conn, linux_socket_connect,
      linux_socket_disconnect, send_socket_packet, read_socket_packet,
      broker_process_packet, free_linux_socket);

  conn->context = skt;
  *conn_p = conn;

  return;
}

/**
 * \brief Function to connect to linux socket.
 * \param conn Pointer to the broker_conn struct.
 * \return mqtt_ret
 */
umqtt_ret linux_socket_connect(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: linux_socket_connect");

  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  if ((skt->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    log_stderr(LOG_ERROR, "Could not create socket");
    return UMQTT_CONNECT_ERROR;
  }

  /* convert ip address to binary */
  if (inet_pton(skt->serv_addr.sin_family, skt->ip,
        &skt->serv_addr.sin_addr) <= 0)
  {
    log_stderr(LOG_ERROR, "inet_pton error occured");
    return UMQTT_CONNECT_ERROR;
  }

  if (connect(skt->sockfd, (struct sockaddr *)&skt->serv_addr,
        sizeof(skt->serv_addr)) == -1)
  {
    log_stderr(LOG_ERROR, "Connect Failed: %s", strerror(errno));
    return UMQTT_CONNECT_ERROR;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to disconnect from linux socket.
 * \param conn Pointer to the broker_conn struct.
 * \return mqtt_ret
 */
umqtt_ret linux_socket_disconnect(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: linux_socket_disconnect");
  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  if (skt->sockfd) {
    if (close(skt->sockfd)) {
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
umqtt_ret send_socket_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  log_stderr(LOG_DEBUG, "fn: send_socket_packet");

  log_stderr(LOG_DEBUG, "TX: %s", get_type_string(pkt->fixed->generic.type));

  umqtt_ret ret = UMQTT_SUCCESS;
  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;
  print_packet(pkt);
  int n = write(skt->sockfd, pkt->raw.buf, pkt->len);
  if (n < 0) {
    log_stderr(LOG_ERROR, "writing to socket");
    ret = UMQTT_SEND_ERROR;
  }

  return ret;
}

/**
 * \brief Function to receive packet from the broker socket.
 * \param conn Pointer to the croker_conn struct.
 * \param pkt Pointer to the receiver buffer/packet.
 * \return Number of bytes read.
 */
umqtt_ret read_socket_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  log_stderr(LOG_DEBUG, "fn: read_socket_packet");

  umqtt_ret ret = UMQTT_SUCCESS;
  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  pkt->len = read(skt->sockfd, pkt->raw.buf, pkt->raw.len);
  if (pkt->raw.len < 0) {
    log_stderr(LOG_ERROR, "reading from socket");
    ret = UMQTT_RECEIVE_ERROR;
  } else {
    disect_raw_packet(pkt);

    log_stderr(LOG_DEBUG, "RX: %s", get_type_string(pkt->fixed->generic.type));

    /* can we process the message? */
    if (conn->process_method) {
      ret = conn->process_method(conn, pkt);
    }
  }
  return ret;
}

/**
 * \brief Function to free memory allocated to struct broker_conn.
 * \param conn The connection to free.
 */
void free_linux_socket(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: free_linux_socket");
  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;
  if (skt) {
    free(skt);
  }

  return;
}
