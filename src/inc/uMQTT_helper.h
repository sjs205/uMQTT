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

char *get_type_string(ctrl_pkt_type type);
void print_memory_bytes_hex(void *ptr, size_t len);
void print_packet(struct mqtt_packet *pkt);
#endif                /* UMQTT__H */
