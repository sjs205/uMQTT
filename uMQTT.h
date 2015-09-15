/******************************************************************************
 * File: uMQTT.h
 * Description: MicroMQTT (uMQTT) library implementation suitable for
 *              constrained environments.
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
#include <stdint.h>

#define MQTT_PROTO_NAME         "MQTT"
#define MQTT_PROTO_LEVEL        0x04
#define MQTT_MAX_PAYLOAD_LEN    1024
#define MQTT_CLIENT_ID          "uMQTT"

/**
 * \brief Control packet types.
 */
typedef enum {
  RESERVED_0,
  CONNECT,
  CONNACK,
  PUBLISH,
  PUBACK,
  PUBREC,
  PUBREL,
  PUBCOMP,
  SUBSCRIBE,
  SUBACK,
  UNSUBSCRIBE,
  UNSUBACK,
  PINGREQ,
  PINGRESP,
  DISCONNECT,
  RESERVED_15
} __attribute__((__packed__)) ctrl_pkt_type;

/**
 * \brief Connect return codes.
 */
typedef enum {
  CONN_ACC,
  CONN_REF_IDENTIFIER_REJ,
  CONN_REF_SERVER_UNAVAIL,
  CONN_REF_BAD_USER_PASS,
  CONN_REF_NOT_AUTH,
  RESERVED
} connect_ret_code;

/**
 * \brief Struct to store utf-8 encoded strings, as required for text fields.
 *        See '1.5.3 UTF-8 encoded strings' of the mqtt v3.1.1 specification.
 * \param lenght Length of the string.
 * \param utf8_str Pointer to the actual string data.
 */
struct __attribute__((__packed__)) utf8_enc_str {
  uint16_t length;
  char utf8_str;
};

/**
 * \brief Struct to store the MQTT client data.
 */
struct mqtt_client {
  struct utf8_enc_str clientid;
};


/**
 * \brief Struct to store the MQTT connection state.
 */
struct conn_state {
  //blah
};

/**
 * \brief Struct to store the MQTT configuration.
 */
struct mqtt_conf {
  struct utf8_enc_str *username;
  struct utf8_enc_str *password;
  struct utf8_enc_str *topic;
};

/**
 * \brief Struct to store the fixed header of a CONNECT control packet.
 * \param type The type of control packet.
 * \param reserved Reserved for future use - see MQTT spec.
 */
struct __attribute__((__packed__)) pkt_connect_fixed_header {

  uint8_t reserved                : 4;
  ctrl_pkt_type type              : 4;
};

/**
 * \brief Struct to store the fixed header of a PUBLISH control packet.
 * \param retain_flag Flag to indicate the application message should be retained.
 * \param qos_flag Quality of service flag.
 * \param dub_flag Flag to indicate whether packet is a duplicate.
 * \param type The type of control packet.
 */
struct __attribute__((__packed__)) pkt_publish_fixed_header {

  uint8_t retain_flag             : 1;
  uint8_t qos_flag                : 2;
  uint8_t dup_flag                : 1;
  ctrl_pkt_type type              : 4;
};

/**
 * \brief Struct to store the fixed header of a control packet.
 * \param connect CONNECT fixed header
 * \param publish PUBLISH fixed header
 * \param remain_length The remaining length of the packet not including
 *                   the fixed header - note, currently, only 127 bytes
 *                   remaining length supported.
 */
struct __attribute__((__packed__)) pkt_fixed_header {

  union {
    struct pkt_connect_fixed_header connect;
    struct pkt_publish_fixed_header publish;
  };

  uint8_t remain_len[4];
};

/**
 * \brief Struct to store the variable header of a CONNECT control packet.
 * \param name_len The length of the name field.
 * \param proto_name The name of the protocol, "MQTT".
 * \param proto_level The version of the protocol.
 * \param user_flag Flag indicating whether username is present.
 * \param pass_flag Flag indicating whether password is present.
 * \param vill_retain_flag Flag indicating will retian.
 * \param vill_qos_flag Flag indicating will quality of service.
 * \param vill_flag Flag indicating will.
 * \param clean_session_flag Flag indicating whether clean session is active.
 * \param keep_alive Number of seconds a session should be kept alive.
 */
struct __attribute__((__packed__)) connect_variable_header {
  uint16_t name_len               : 16;
  uint8_t proto_name[4];
  uint8_t proto_level;
  uint8_t user_flag               : 1;
  uint8_t pass_flag               : 1;
  uint8_t will_retain_flag        : 1;
  uint8_t will_qos_flag           : 1;
  uint8_t will_flag               : 1;
  uint8_t clean_session_flag      : 1;
  uint8_t reserved                : 1;
  uint16_t keep_alive             :16;
};

/**
 * \brief Struct to store the variable header of a CONNACK control packet.
 * \param session_flag Flag to indicate whether a session is present.
 * \param connect_ret Return value of the CONNECT request.
 */
struct connack_variable_header {
  uint8_t session_present_flag    : 1;
  uint8_t reserved                : 7;
  uint8_t connect_ret;
};

/**
 * \brief Struct to store the variable header of a PUBLISH control packet.
 * \param topic_name The information channel to which the payload data is published.
 * \param pkt_id The packet identifier - only required for qos = 1 or 2.
 */
struct publish_variable_header {
  struct utf8_enc_str topic_name;
  uint16_t pkt_id                 : 16;
};

/**
 * \brief Struct to store the variable header of a PUBACK control packet.
 * \param pkt_id The packet identifier - only required for qos = 1 or 2.
 */
struct puback_variable_header {
  uint16_t pkt_id                 : 16;
};

struct pkt_variable_header {
  union {
    struct connect_variable_header connect;
    struct connack_variable_header connack;
    struct publish_variable_header publish;
  };
};

/**
 * \brief Struct to store the control packet payload.
 * \param length The payload length.
 */
struct pkt_payload {
  /* uint16_t may not be big enough... check */
  uint16_t length;
  /* utf8 isn't uint8_t ... */
  uint8_t *data;
};

/**
 * \brief Struct to store the mqtt packet.
 * \param pkt Pointer to the actual packet.
 * \param fixed Pointer to the fixed packet header.
 * \param variable Pointer to the variable packet header.
 * \param payload Pointer to the packet payload.
 * \param length the packet length.
 */
struct mqtt_packet {
  struct pkt_fixed_header *fixed;
  struct pkt_variable_header *variable;
  struct pkt_payload *payload;
  uint16_t length;
};

/**
 * \brief Struct to store a raw packet.
 * \param length The packet length.
 * \param pkt Pointer to the actual packet.
 */
struct raw_packet {
  struct mqtt_packet *pkt;
};

/*
 * Function declariations
 */
void init_packet(struct mqtt_packet **pkt_p);
int init_packet_header(struct mqtt_packet *pkt_p, ctrl_pkt_type type);
int init_packet_payload(struct mqtt_packet *pkt, ctrl_pkt_type type);
void free_pkt(struct mqtt_packet *pkt);
void free_pkt_fixed_header(struct pkt_fixed_header *fix);
void free_pkt_variable_header(struct pkt_variable_header *var);
void free_pkt_payload(struct pkt_payload *pld);

void encode_remaining_pkt_len(struct mqtt_packet *pkt, unsigned int len);
unsigned int decode_remaining_pkt_len(struct mqtt_packet *pkt);
void print_memory_bytes_hex(void *ptr, int bytes);
