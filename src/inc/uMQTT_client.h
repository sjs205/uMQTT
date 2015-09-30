#ifndef UMQTT_CLIENT__H
#define UMQTT_CLIENT__H
/******************************************************************************
 * File: uMQTT_client.h
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

/**
 * \brief Struct to store an MQTT broker socket connection.
 * \param conn_state Current connection state.
 * \param context Pointer to context specific struct
 * \param connect_method Function pointer to the connect method.
 * \param disconnect_method Function pointer to the disconnect method.
 * \param send_method Function pointer to the send method.
 * \param recieve_method Function pointer to the recieve method.
 * \param free_method Fuction to free the connect method and related context struct.
 */
struct broker_conn {
  uint8_t state;

  void *context;

  umqtt_ret (*connect_method)(struct broker_conn *);
  umqtt_ret (*disconnect_method)(struct broker_conn *);

  size_t (*send_method)(struct broker_conn *, struct raw_pkt *);
  size_t (*recieve_method)(struct broker_conn *, struct raw_pkt *);

  void (*free_method)(struct broker_conn *);
};

void init_connection(struct broker_conn **conn_p);
void register_connection_methods(struct broker_conn *conn,
    umqtt_ret (*connect_method)(struct broker_conn *),
    umqtt_ret (*disconnect_method)(struct broker_conn *),
    size_t (*send_method)(struct broker_conn *,  struct raw_pkt *),
    size_t (*recieve_method)(struct broker_conn *, struct raw_pkt *),
    void (*free_method)(struct broker_conn *));
umqtt_ret broker_connect(struct broker_conn *conn);
umqtt_ret broker_disconnect(struct broker_conn *conn);
void print_memory_bytes_hex(void *ptr, size_t len);
void print_packet(struct mqtt_packet *pkt);
void free_connection(struct broker_conn *conn);
#endif          /* UMQTT_CLIENT__H */
