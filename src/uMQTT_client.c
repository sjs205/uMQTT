/******************************************************************************
 * File: uMQTT_client.c
 * Description: Functions to implement uMQTT client.
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

#include "uMQTT.h"
#include "uMQTT_client.h"

/**
 * \brief Function to allocate memory for a broker connection struct.
 * \param conn_p Pointer to the address of the new connection struct.
 */
void init_connection(struct broker_conn **conn_p) {
  struct broker_conn *conn;

  if (!(conn = calloc(1, sizeof(struct broker_conn)))) {
    printf("Error: Allocating space for the broker connection failed.\n");
    free_connection(conn);
  }

  *conn_p = conn;

  return;
}

/**
 * \brief Function to register implementation specific connection methods.
 * \param connect_method Function pointer to the connect method.
 * \param disconnect_method Function pointer to the disconnect method.
 * \param send_method Function pointer to the send method.
 * \param recieve_method Function pointer to the recieve method.
 */
void register_connection_methods(struct broker_conn *conn,
    umqtt_ret (*connect_method)(struct broker_conn *),
    umqtt_ret (*disconnect_method)(struct broker_conn *),
    size_t (*send_method)(struct broker_conn *,  struct raw_pkt *),
    size_t (*recieve_method)(struct broker_conn *, struct raw_pkt *),
    void (*free_method)(struct broker_conn *)) {

  if (connect_method) {
    conn->connect_method = connect_method;
  }

  if (disconnect_method) {
    conn->disconnect_method = disconnect_method;
  }

  if (send_method) {
    conn->send_method = send_method;
  }

  if (recieve_method) {
    conn->recieve_method = recieve_method;
  }

  if (free_method) {
    conn->free_method = free_method;
  }

  return;
}

/**
 * \brief Function to connect to broker socket and send a
 *        CONNECT packet..
 * \param conn Pointer to the broker_conn struct.
 * \return mqtt_ret
 */
umqtt_ret broker_connect(struct broker_conn *conn) {

  if (conn->connect_method && conn->connect_method(conn)) {
    printf("\n Error: No connect method registered\n");
    return UMQTT_CONNECT_ERROR;
  }

  /* send connect packet */
  struct mqtt_packet *pkt = construct_default_packet(CONNECT, 0, 0);
  size_t ret = conn->send_method(conn, &pkt->raw);
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

  pkt_resp->len = conn->recieve_method(conn, &pkt_resp->raw);
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

    if (!conn->send_method(conn, &pkt->raw)) {
      return UMQTT_PACKET_ERROR;
    }
  }

  if (conn->disconnect_method(conn)) {
    return UMQTT_DISCONNECT_ERROR;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to free memory allocated to struct broker_conn.
 * \param conn The connection to free.
 */
void free_connection(struct broker_conn *conn) {
  if (conn->free_method) {
    conn->free_method(conn);
  }

  if (conn) {
    free(conn);
  }
  
  return;
}
