#ifndef UMQTT_LINUX_CLIENT__H
#define UUMQTT_LINUX_CLIENT__H
/******************************************************************************
 * File: uMQTT_linux_client.h
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
#include <netinet/in.h>

#include "uMQTT.h"
#include "uMQTT_client.h"

/**
 * \brief Struct to store an MQTT broker socket connection.
 * \param ip The ip address of the broker.
 * \param port The port with which to bind to.
 * \param sockfd The socket file descriptor of a connection instance.
 * \param serv_addr struct holding the address of the broker.
 * \param conn_state Current connection state.
 */
struct linux_broker_socket {
  char ip[16];
  int port;
  int sockfd;
  struct sockaddr_in serv_addr;
};

void init_linux_socket_connection(struct broker_conn **conn_p, char *ip, unsigned int ip_len,
    unsigned int port);
umqtt_ret linux_socket_connect(struct broker_conn *conn);
umqtt_ret linux_socket_disconnect(struct broker_conn *conn);
umqtt_ret send_socket_packet(struct broker_conn *conn, struct mqtt_packet *pkt);
umqtt_ret read_socket_packet(struct broker_conn *conn, struct mqtt_packet *pkt);
void free_linux_socket(struct broker_conn *conn);
#endif              /* UMQTT_LINUX_CLIENT__H */
