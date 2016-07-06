#ifndef UMQTT_HELPER__H
#define UMQTT_HELPER__H
/******************************************************************************
 * File: uMQTT_helper.h
 * Description: uMQTT helper fucntions - not necessarily required for general
                usage.
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
#include "uMQTT.h"

/* Packet type strings */
#define RESERVED_STR        "RESERVED\0"
#define CONNECT_STR         "CONNECT\0"
#define CONNACK_STR         "CONNACK\0"
#define PUBLISH_STR         "PUBLISH\0"
#define PUBACK_STR          "PUBACK\0"
#define PUBREC_STR          "PUBREC\0"
#define PUBREL_STR          "PUBREL\0"
#define PUBCOMP_STR         "PUBCOMP\0"
#define SUBSCRIBE_STR       "SUBSCRIBE\0"
#define SUBACK_STR          "SUBACK\0"
#define UNSUBSCRIBE_STR     "UNSUBSCRIBE\0"
#define UNSUBACK_STR        "UNSUBACK\0"
#define PINGREQ_STR         "PINGREQ\0"
#define PINGRESP_STR        "PINGRESP\0"
#define DISCONNECT_STR      "DISCONNECT\0"

/* version strings */
#define V1_STR              "v1.x"
#define V2_STR              "v2.X"
#define V3_V3_1_STR         "v3.0-v3.1"
#define V3_1_1_STR          "v3.1.1"

/* connect return strings */
#define CONN_ACCEPTED_STR           "0x00 Connection Accepted"
#define CONN_UNACCEPT_PROTO_VER_STR "0x01 Connection Refused, unacceptable protocol version"
#define CONN_REF_IDENTIFIER_REJ_STR "0x02 Connection Refused, identifier rejected"
#define CONN_REF_SERVER_UNAVAIL_STR "0x03 Connection Refused, Server unavailable"
#define CONN_REF_BAD_USER_PASS_STR  "0x04 Connection Refused, bad user name or password"
#define CONN_REF_NOT_AUTH_STR       "0x05 Connection Refused, not authorized"
#define CONN_STATE_RESERVED_STR     "Return code reserved for future use"

/* Quality Of Service strings */
#define QOS_AT_MOST_ONCE_STR        "At most once delivery"
#define QOS_AT_LEAST_ONCE_STR       "At least once delivery"
#define QOS_EXACTLY_ONCE_STR        "Exactly once delivery"
#define QOS_RESERVED_STR            "Reserved – must not be used"

/* SUBACK return strings */
#define SUB_SUCCESS_MAX_QOS_0_STR   "Success - Maximum QoS 0"
#define SUB_SUCCESS_MAX_QOS_1_STR   "Success - Maximum QoS 1"
#define SUB_SUCCESS_MAX_QOS_2_STR   "Success - Maximum QoS 2"
#define SUB_FAILURE_STR             "Failure"

#define UNIQUE_STR_CHARSET  "abcdefghijklmnopqrstuvwxyz" \
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                            "0123456789"

char *get_type_string(ctrl_pkt_type type);
void gen_unique_string(char *str, size_t len);
void print_memory_bytes_hex(void *ptr, size_t len);
void print_packet(struct mqtt_packet *pkt);
void print_publish_packet(struct mqtt_packet *pkt);
void print_packet_detailed(struct mqtt_packet *pkt);
#endif                /* UMQTT__H */
