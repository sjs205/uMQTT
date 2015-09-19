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
#include <netinet/in.h>

#define TXRX_BUF_LEN    1024


/**
 * \brief Struct to store an MQTT broker socket connection.
 * \param ip The ip address of the broker.
 * \param port The port with which to bind to.
 * \param sockfd The socket file descriptor of a connection instance.
 * \param serv_addr struct holding the address of the broker.
 */
struct broker_conn {
  char ip[16];
  int port;
  int sockfd;
  struct sockaddr_in serv_addr; 
};

/**
 * \brief Struct to store a TX/RX packet.
 * \param buf The TX/RX buffer.
 * \param len The number of valid bytes in the buffer, buf.
 */
struct raw_pkt {
  uint8_t buf[TXRX_BUF_LEN];
  unsigned int len;
};

void init_connection(struct broker_conn **conn_p, char *ip,
    unsigned int ip_len,  unsigned int port);
void init_raw_packet(struct raw_pkt **pkt_p);
int broker_connect(struct broker_conn *conn);
int send_packet(struct broker_conn *conn, struct raw_pkt *pkt);
int read_packet(struct broker_conn *conn, struct raw_pkt *pkt);
void print_memory_bytes_hex(void *ptr, unsigned int len);
