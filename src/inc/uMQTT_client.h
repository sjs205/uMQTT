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
#define BROKER_MAX_SUBS         8
#define MAX_RESP_PKT_RETRIES    8

#define UMQTT_CLIENTID_MAX_LEN  128
#define UMQTT_USERNAME_MAX_LEN  128
#define UMQTT_PASSWORD_MAX_LEN  128

struct broker_conn;

/**
 * \brief uMQTT connection states.
 */
typedef enum {
  UMQTT_DISCONNECTED,
  UMQTT_CONNECTED,
  UMQTT_CONNECTING,
  UMQTT_UNKNOWN,
} umqtt_state;

/**
 * \brief Struct to store the MQTT client data.
 * \param clientid The MQTT client ID
 * \param username The client connection username
 * \param password The client connection password
 */
struct mqtt_client {
  char *clientid;
  char *username;
  char *password;
};

/**
 * \brief Struct to store process_method overload functions 
 * \param connect_method Function pointer to connect packet overload method
 * \param connack_method Function pointer to conack packet overload method
 * \param publish_method Function pointer to publish packet overload method
 * \param puback_method Function pointer to puback packet overload method
 * \param pubrel_method Function pointer to pubrel packet overload method
 * \param pubcomp_method Function pointer to pubcomp packet overload method
 * \param pubrec_method Function pointer to pubrec packet overload method
 * \param subscribe_method Function pointer to subscribe packet overload method
 * \param unsubscribe_method Function pointer to unsubscribe packet overload method
 * \param suback_method Function pointer to suback packet overload method
 * \param unsuback_method Function pointer to unsuback packet overload method
 * \param pingreq_method Function pointer to pingreq packet overload method
 * \param pingresp_method Function pointer to pingresp packet overload method
 * \param disconnect_method Function pointer to disconnect packet overload method
 */
struct mqtt_process_methods {
  umqtt_ret (*connect_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*connack_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*publish_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*puback_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*pubrel_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*pubcomp_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*pubrec_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*subscribe_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*unsubscribe_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*suback_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*unsuback_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*pingreq_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*pingresp_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*disconnect_method)(struct broker_conn *, struct mqtt_packet *);
};

/**
 * \brief Struct to store an MQTT broker socket connection.
 * \param conn_state Current connection state.
 * \param context Pointer to connection context specific struct
 * \param subs Array of pointer to SUBSCRIBE/SUBACK packets.
 * \param sub_count final packet in subs array.
 * \param resp Point to a packet awaiting a response.
 * \param connect_method Function pointer to the connect method.
 * \param disconnect_method Function pointer to the disconnect method.
 * \param send_method Function pointer to the send method.
 * \param receive_method Function pointer to the receive method.
 * \param free_method Fuction to free the connect method and related context struct.
 */
struct broker_conn {
  struct mqtt_client client;
  umqtt_state state;

  void *context;

  struct mqtt_packet *subs[BROKER_MAX_SUBS];
  uint8_t sub_count;

  struct mqtt_packet *resp;

  umqtt_ret (*connect_method)(struct broker_conn *);
  umqtt_ret (*disconnect_method)(struct broker_conn *);

  umqtt_ret (*send_method)(struct broker_conn *, struct mqtt_packet *);
  umqtt_ret (*receive_method)(struct broker_conn *, struct mqtt_packet *);

  umqtt_ret (*process_method)(struct broker_conn *, struct mqtt_packet *);
  struct mqtt_process_methods *proc;

  void (*free_method)(struct broker_conn *);
};

void init_connection(struct broker_conn **conn_p);
umqtt_ret init_process_methods(struct mqtt_process_methods **proc_p);

void register_connection_methods(struct broker_conn *conn,
    umqtt_ret (*connect_method)(struct broker_conn *),
    umqtt_ret (*disconnect_method)(struct broker_conn *),
    umqtt_ret (*send_method)(struct broker_conn *,  struct mqtt_packet *),
    umqtt_ret (*receive_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*process_method)(struct broker_conn *, struct mqtt_packet *),
    void (*free_method)(struct broker_conn *));
umqtt_ret register_process_methods(struct mqtt_process_methods **proc,
    umqtt_ret (*connect_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*connack_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*publish_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*puback_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*pubrel_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*pucomp_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*pubrec_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*subscribe_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*unsubscribe_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*suback_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*unsuback_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*pingreq_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*pingresp_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*disconnect_method)(struct broker_conn *, struct mqtt_packet *));
umqtt_ret broker_set_clientid(struct broker_conn *conn, const char *clientid,
    size_t len);
umqtt_ret broker_send_packet(struct broker_conn *conn, struct mqtt_packet *pkt);
umqtt_ret broker_receive_packet(struct broker_conn *conn, struct mqtt_packet *pkt);
umqtt_ret broker_process_packet(struct broker_conn *conn, struct mqtt_packet *pkt);
umqtt_ret broker_connect(struct broker_conn *conn);
umqtt_ret broker_publish(struct broker_conn *conn, const char *topic,
    uint8_t retain, uint8_t qos, uint8_t dup, size_t topic_len, uint8_t
    *payload, size_t pay_len, uint8_t flags);
umqtt_ret broker_subscribe(struct broker_conn *conn, const char *topic,
    size_t topic_len);
umqtt_ret broker_disconnect(struct broker_conn *conn);
void free_process_methods(struct mqtt_process_methods *proc);
void free_connection(struct broker_conn *conn);
#endif          /* UMQTT_CLIENT__H */
