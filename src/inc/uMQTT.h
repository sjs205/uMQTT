#ifndef UMQTT__H
#define UMQTT__H
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

/* default defines - some can be overridden */
#define MQTT_PROTO_NAME           "MQTT"
#define MQTT_PROTO_LEVEL          0x04
#define UMQTT_DEFAULT_CLIENTID    "uMQTT"
#define UMQTT_DEFAULT_TOPIC       "uMQTT_PUB"
#define UMQTT_DEFAULT_QOS         0

/* Remaining length max bytes */
#ifdef MICRO_CLIENT
  /* 128 * 128 = 16384 */
  #define MAX_REMAIN_LEN_BYTES      2
  #define MAX_REMAIN_LEN_PRODUCT    16384

  /* used to initialise a new packet */
  #define UMQTT_MAX_PACKET_LEN      64

#else
  /* 128 * 128 * 128 * 128 = 268435456 */
  #define MAX_REMAIN_LEN_BYTES      4
  #define MAX_REMAIN_LEN_PRODUCT    268435456

  /* used to initialise a new packet */
  #define UMQTT_MAX_PACKET_LEN      1024

#endif

/**
 * \brief uMQTT return codes.
 */
typedef enum {
  UMQTT_SUCCESS,
  UMQTT_ERROR,
  UMQTT_MEM_ERROR,
  UMQTT_CONNECT_ERROR,
  UMQTT_SUBSCRIBE_ERROR,
  UMQTT_DISCONNECT_ERROR,
  UMQTT_SEND_ERROR,
  UMQTT_RECEIVE_ERROR,
  UMQTT_PACKET_ERROR,
  UMQTT_PAYLOAD_ERROR,
  UMQTT_PKT_NOT_SUPPORTED,
} umqtt_ret;

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
  QOS_AT_MOST_ONCE,
  QOS_AT_LEAST_ONCE,
  QOS_EXACTLY_ONCE,
  QOS_RESERVED,
} __attribute__((__packed__)) qos_t;
/**
 * \brief Connect return codes.
 */
typedef enum {
  CONN_ACCEPTED,
  CONN_REF_IDENTIFIER_REJ,
  CONN_REF_SERVER_UNAVAIL,
  CONN_REF_BAD_USER_PASS,
  CONN_REF_NOT_AUTH,
  RESERVED
} connect_state;

/**
 * \brief Struct to store utf-8 encoded strings, as required for text fields.
 *        See '1.5.3 UTF-8 encoded strings' of the mqtt v3.1.1 specification.
 * \param len_msb Length of the string - MSB.
 * \param len_lsb Length of the string - LSB.
 * \param utf8_str Pointer to the actual string data.
 */
struct __attribute__((__packed__)) utf8_enc_str {
  uint8_t len_msb;
  uint8_t len_lsb;
  char utf8_str;
};

/**
 * \brief Struct to store a generic fixed header of a control packet.
 * \param type The type of control packet.
 * \param reserved Reserved for future use - see MQTT spec.
 */
struct __attribute__((__packed__)) pkt_generic_fixed_header {

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

  uint8_t retain                  : 1;
  qos_t qos                       : 2;
  uint8_t dup                     : 1;
  ctrl_pkt_type                   : 4;
};

/**
 * \brief Struct to store the fixed header of a control packet.
 * \param generic igeneric fixed header
 * \param publish PUBLISH fixed header
 * \param remain_length The remaining length of the packet not including
 *                   the fixed header - note, currently, only 127 bytes
 *                   remaining length supported.
 */
struct __attribute__((__packed__)) pkt_fixed_header {

  union {
    struct pkt_generic_fixed_header generic;
    struct pkt_publish_fixed_header publish;
  };

  uint8_t remain_len[MAX_REMAIN_LEN_BYTES];
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
  uint8_t reserved                : 1;
  uint8_t clean_session_flag      : 1;
  uint8_t will_flag               : 1;
  uint8_t will_qos_flag           : 1;
  uint8_t will_retain_flag        : 1;
  uint8_t pass_flag               : 1;
  uint8_t user_flag               : 1;
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
 * \param topic The information channel to which the payload data is published.
 * \param pkt_id The packet identifier - only required for qos = 1 or 2.
 */
struct publish_variable_header {
  struct utf8_enc_str topic;
  uint16_t pkt_id                 : 16;
};

/**
 * \brief Struct to store the variable header of a generic control packet.
 * \param pkt_id The packet identifier - only required for qos = 1 or 2.
 */
struct generic_variable_header {
  uint16_t pkt_id                 : 16;
};

struct pkt_variable_header {
  union {
    struct generic_variable_header generic;
    struct connect_variable_header connect;
    struct connack_variable_header connack;
    struct publish_variable_header publish;
  };
};

/**
 * \brief Struct to store the control packet payload.
 * \param data The raw payload data.
 */
struct pkt_payload {
  uint8_t data;
};

/**
 * \brief Struct to store a TX/RX packet.
 * \param buf The TX/RX buffer.
 * \param len The number of valid bytes in the buffer, buf. Pointer to
 *        mqtt_packet->len;
 */
struct raw_pkt {
  uint8_t buf[UMQTT_MAX_PACKET_LEN];
  size_t *len;
};

/**
 * \brief Struct to store the mqtt packet.
 * \param fixed Pointer to the fixed packet header.
 * \param variable Pointer to the variable packet header.
 * \param payload Pointer to the packet payload.
 * \param fix_len The length of the fixed header.
 * \param var_len The length of the variable header.
 * \param pay_len The length of the payload.
 * \param len The total packet length.
 */
struct mqtt_packet {
  struct pkt_fixed_header *fixed;
  struct pkt_variable_header *variable;
  struct pkt_payload *payload;

  struct raw_pkt raw;

  size_t fix_len;
  size_t var_len;
  size_t pay_len;
  size_t len;
};

/*
 * Function declariations
 */
umqtt_ret init_packet(struct mqtt_packet **pkt_p);
umqtt_ret init_packet_fixed_header(struct mqtt_packet *pkt,
    ctrl_pkt_type type);
umqtt_ret init_packet_variable_header(struct mqtt_packet *pkt,
    ctrl_pkt_type type);
umqtt_ret set_publish_variable_header(struct mqtt_packet *pkt, const char *topic,
    size_t topic_len);
umqtt_ret set_publish_fixed_flags(struct mqtt_packet *pkt, uint8_t retain,
    uint8_t qos, uint8_t dup);
umqtt_ret set_subscribe_variable_header(struct mqtt_packet *pkt);
umqtt_ret init_packet_payload(struct mqtt_packet *pkt, ctrl_pkt_type type,
    uint8_t *payload, size_t pay_len);
umqtt_ret set_connect_payload(struct mqtt_packet *pkt, const char *cID,
    size_t cID_len);
umqtt_ret set_subscribe_payload(struct mqtt_packet *pkt, const char *topic,
    size_t topic_len, uint8_t qos);
struct mqtt_packet *construct_packet_headers(ctrl_pkt_type type);
struct mqtt_packet *construct_default_packet(ctrl_pkt_type type,
    uint8_t *payload, size_t pay_len);
size_t finalise_packet(struct mqtt_packet *pkt);
void disect_raw_packet(struct mqtt_packet *pkt);

void encode_remaining_len(struct mqtt_packet *pkt, unsigned int len);
unsigned int decode_remaining_len(struct mqtt_packet *pkt);
uint16_t encode_utf8_string(struct utf8_enc_str *utf8_str, const char *buf,
    uint16_t len);
uint8_t required_remaining_len_bytes(unsigned int len);

void memmove_back(uint8_t *mem, size_t delta, size_t n);
void free_packet(struct mqtt_packet *pkt);
#endif          /* UMQTT__H */
