/******************************************************************************
 * File: uMQTT.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inc/uMQTT.h"

/**
 * \brief Function to allocate memory for an mqtt packet.
 * \param pkt Pointer to the address of the new packet.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet(struct mqtt_packet **pkt_p) {
  struct mqtt_packet *pkt;

  if (!(pkt = calloc(1, sizeof(struct mqtt_packet)))) {
    printf("Error: Allocating space for MQTT packet failed.\n");
    free_packet(pkt);
    return UMQTT_MEM_ERROR;
  }

  pkt->raw.len = &pkt->len;
  *pkt_p = pkt;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to allocate memory for mqtt fixed packet header
 *        and set the defaults.
 * \param pkt Pointer to the address of the packet containing headers.
 * \param type The type of packet to be created.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet_fixed_header(struct mqtt_packet *pkt,
    ctrl_pkt_type type) {

  /* allocate initial fixed header length */
  pkt->fix_len =
    1 + MAX_REMAIN_LEN_BYTES;

  /* alloate fixed header */
  pkt->fixed = (struct pkt_fixed_header *)&pkt->raw.buf[0];

  pkt->fixed->generic.type = type;

  pkt->len = pkt->fix_len;

  if (type == SUBSCRIBE) {
    /* Reserved bytes should be 0x02 for SUBSCRIBE */
    pkt->fixed->generic.reserved = 0x02;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to allocate memory for mqtt variable packet header
 *        and set the defaults.
 * \param pkt Pointer to the address of the packet containing headers.
 * \param type The type of packet to be created.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet_variable_header(struct mqtt_packet *pkt,
    ctrl_pkt_type type) {

  /* allocate variable header */
  pkt->variable = (struct pkt_variable_header *)&pkt->raw.buf[pkt->fix_len];

  switch (type) {
    case CONNECT:

      /* variable header len */
      pkt->var_len = sizeof(struct connect_variable_header);

      /* defaults */
      pkt->variable->connect.name_len = (0x04>>8) | (0x04<<8);
      memcpy(pkt->variable->connect.proto_name, MQTT_PROTO_NAME, 0x04);
      pkt->variable->connect.proto_level = MQTT_PROTO_LEVEL;
      pkt->variable->connect.clean_session_flag |= 1;

      break;

    case PUBLISH:
      /* variable header - default action => qos = 0 */

      /* defaults */
      set_publish_variable_header(pkt, UMQTT_DEFAULT_TOPIC,
          (sizeof(UMQTT_DEFAULT_TOPIC) - 1));

      break;

    case SUBSCRIBE:
      /* variable header - default action => qos = 0 */
      pkt->var_len = sizeof(struct generic_variable_header);

      /* defaults */
      set_subscribe_variable_header(pkt);

      break;

    case PINGREQ:
    case PINGRESP:
    case DISCONNECT:
      break;

    default:
      printf("Error: MQTT packet type not currently supported.\n");

      return UMQTT_ERROR;
  }

  pkt->len = pkt->fix_len + pkt->var_len;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to set the variable header of a PUBLISH packet.
 * \param pkt Pointer to the address of the packet.
 * \param topic The topic for which the message should be published.
 * \param topic_len The length of the topic.
 */
umqtt_ret set_publish_variable_header(struct mqtt_packet *pkt, const char *topic,
    size_t topic_len) {

      pkt->var_len = encode_utf8_string(&pkt->variable->publish.topic_name, topic, topic_len);

      if (pkt->fixed->publish.qos) {
        /* set packet identifier */
      }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to set the variable header of a SUBSCRIBE packet.
 * \param pkt Pointer to the address of the packet.
 */
umqtt_ret set_subscribe_variable_header(struct mqtt_packet *pkt) {

  /* At present it isn't clear if this is required when qos = 0 */
  pkt->variable->generic.pkt_id = 0x0000;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to allocate memory for mqtt packet payload.
 *        NOTE: Currently if the payload type = PUBLISH, *payload
          pointer is substituted into the pkt->payload. In the
          future, it may be better to actually copy this data to a
          new payload data struct.
 * \param pkt Pointer to the address of the packet containing payload.
 * \param type The type of payload to be created.
 * \param *payload Pointer to payload data.
 * \param *pay_len The lenth of the attached payload data.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet_payload(struct mqtt_packet *pkt, ctrl_pkt_type type,
    uint8_t *payload, size_t pay_len) {

  /* allocate payload */
  pkt->payload =
    (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];

  switch (type) {
    case CONNECT:

      pkt->pay_len = encode_utf8_string(
          (struct utf8_enc_str *)&pkt->payload->data, MQTT_CLIENT_ID,
          (sizeof(MQTT_CLIENT_ID) - 1));

      break;

    case PUBLISH:
    case SUBSCRIBE:
      pkt->pay_len = pay_len;

      if (pay_len) {
        memcpy(&pkt->payload->data, payload, pay_len);
      } else {
        /* defaults */
        set_subscribe_payload(pkt, UMQTT_DEFAULT_TOPIC,
            sizeof(UMQTT_DEFAULT_TOPIC), UMQTT_DEFAULT_QOS);
      }

      break;


    case PINGREQ:
    case PINGRESP:
    case DISCONNECT:

      break;

    default:
      printf("Error: MQTT packet type not currently supported.\n");

      return UMQTT_ERROR;
  }

  pkt->len += pkt->pay_len;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to set the topic of a SUBSCRIBE packet.
 *        NOTE: We currently only support one topic per subscribe message.
 * \param topic The topic to subscribe to.
 * \param topic_len The length of the topic.
 * \param qos The subscription QOS.
 */
umqtt_ret set_subscribe_payload(struct mqtt_packet *pkt, const char *topic,
    size_t topic_len, uint8_t qos) {

  pkt->pay_len = encode_utf8_string((struct utf8_enc_str *)&pkt->payload->data,
      topic, topic_len) + 1;
  *(&pkt->payload->data + pkt->pay_len - 1) = (0x03 & qos);

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to construct new default mqtt packet headers.
 * \param type The type of packet headers to be created.
 * \return Pointer to new mqtt_packet struct, 0 on failurer.
 */
struct mqtt_packet *construct_packet_headers(ctrl_pkt_type type) {

  struct mqtt_packet *pkt = '\0';

  if (init_packet(&pkt)) {
    free_packet(pkt);
    return NULL;
  }

  if (init_packet_fixed_header(pkt, type)) {
    free_packet(pkt);
    return NULL;
  }

  if (init_packet_variable_header(pkt, type)) {
    free_packet(pkt);
    return NULL;
  }

  return pkt;
}

/**
 * \brief Function to construct a new default mqtt packet.
 * \param type The type of packet to be created.
 * \param *payload Pointer to payload data.
 * \param *pay_len The lenth of the attached payload data.
 * \return Pointer to new mqtt_packet struct, 0 on failurer.
 */
struct mqtt_packet *construct_default_packet(ctrl_pkt_type type,
    uint8_t *payload, size_t pay_len) {

  struct mqtt_packet *pkt = construct_packet_headers(type);

  if (init_packet_payload(pkt, type, payload, pay_len)) {
    free_packet(pkt);
    return NULL;
  }

  finalise_packet(pkt);

  return pkt;
}

/**
 * \brief Function to cleanup mqtt_pkt removing any unused space and
 *        ensuring memory is packed.
 * \param pkt The mxtt_packet to finalise.
 * \return the number of bytes saved
 */
size_t finalise_packet(struct mqtt_packet *pkt) {
  size_t fix_len = pkt->fix_len;
  size_t delta = 0;

  encode_remaining_len(pkt, (pkt->var_len + pkt->pay_len));

  delta = fix_len - pkt->fix_len;
  if (delta) {
    /* need to shift data backwards to ensure packet is packed */
    memmove_back(&pkt->raw.buf[pkt->fix_len], delta, pkt->var_len);
    memmove_back(&pkt->raw.buf[pkt->fix_len + pkt->var_len], delta, pkt->pay_len);

    /* reassign pointers to packet elements */
    pkt->variable = (struct pkt_variable_header *)&pkt->raw.buf[pkt->fix_len];
    pkt->payload = (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];

    pkt->len -= delta;
  }

  /* Free unused space */

  return delta;
}

/**
 * \brief Function to disect incoming raw packet into struct mqtt_pkt
 * \param pkt The mxtt_packet to disect.
 */
void disect_raw_packet(struct mqtt_packet *pkt) {
  /* assign fixed header */
  pkt->fixed = (struct pkt_fixed_header *)&pkt->raw.buf;

  /* size of fixed header */
  pkt->len = decode_remaining_len(pkt);
  pkt->fix_len =
    1 + required_remaining_len_bytes(pkt->len);

  pkt->len += pkt->fix_len;

  switch (pkt->fixed->generic.type) {
    case CONNECT:
      pkt->var_len = sizeof(struct connect_variable_header);
      break;

    case CONNACK:
      pkt->var_len = sizeof(struct connect_variable_header);
      break;

    case PUBLISH:
      pkt->var_len = sizeof(struct publish_variable_header);
      break;

    case PUBACK:
    case PUBCOMP:
    case PUBREL:
    case PUBREC:
    case SUBSCRIBE:
    case SUBACK:
    case UNSUBACK:
    case UNSUBSCRIBE:
      pkt->var_len = sizeof(struct generic_variable_header);
      break;

    case PINGREQ:
    case PINGRESP:
    case DISCONNECT:
      pkt->var_len = 0;

      break;

    default:
      printf("Error: MQTT packet type not currently supported.\n");
  }
  /* assign variable header */
  pkt->variable = (struct pkt_variable_header *)&pkt->raw.buf[pkt->fix_len];

  /* assign payload */
  pkt->pay_len = pkt->len - (pkt->fix_len + pkt->var_len);
  pkt->payload = (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];

  return;
}

/**
 * \brief Function to move memory backwards - prefered over memmove
 *        since this will copy memory to a temp location before copying
 *        to the new location, thus taking upto 3xMEM
 * \param mem Destination memory address - should be the start position
 *        i.e., current_position - delta
 * \param delta Number of positions to move memory backwards
 * \param n Number of bytes to move backwards
 */
void memmove_back(uint8_t *mem, size_t delta, size_t n) {
  size_t i;
  if (mem) {
    for (i = 0; i <= n; i++) {
      mem[i] = mem[i + delta];
    }
  }

  return;
}

/**
 * \brief Function to calculate the number of bytes required to encode
 *        the remaining length field of an MQTT packet,
 * \param len The length that should be encoded.
 */
uint8_t required_remaining_len_bytes(unsigned int len) {
  uint8_t i = 0;
  do {
    len /= 128;

    i++;
  } while (len > 0 && i < MAX_REMAIN_LEN_BYTES);

  return i;
}

/**
 * \brief Function to encode the remaining length of an MQTT packet,
 *        after the fixed header, into the fixed packet header - see section
 *        2.2.3 of the MQTT spec.
 * \param pkt The packet whose length to encode.
 * \param len The length that should be encoded.
 */
void encode_remaining_len(struct mqtt_packet *pkt, unsigned int len) {
  uint8_t i = 0;
  do {
    pkt->fixed->remain_len[i] = len % 128;
    len /= 128;

    if (len > 0) {
      pkt->fixed->remain_len[i] |= 128;
    }
    i++;
  } while (len > 0 && i < MAX_REMAIN_LEN_BYTES);

  /* Set the length of the fixed pkt */
  pkt->fix_len = 1 + i;

  return;
}

/**
 * \brief Function to decode the remain_len variable in the fixed header of
 *        an MQTT packet into an int - see section 2.2.3 of the MQTT spec.
 * \param pkt The packet whose length to decode.
 * \return The length that should be encoded.
 */
unsigned int decode_remaining_len(struct mqtt_packet *pkt) {
  uint8_t i = 0;
  unsigned int len = 0;
  unsigned int product = 1;
  do {
    len += (pkt->fixed->remain_len[i] & 127) * product;

    product *= 128;
    if (product > MAX_REMAIN_LEN_PRODUCT) {
      printf("Error: Malformed remaining length.\n");
      return 0;
    }

  } while ((pkt->fixed->remain_len[i] & 128) != 0 && i++ < MAX_REMAIN_LEN_BYTES);

  return len;
}

/**
 * \brief Function to encode a utf8 string.
 * \param utf8_str Pointer to the struct holding the utf8_enc_str
 * \param buf The string to encode.
 * \param len The length of str
 * \return len of encoded string
 */
int encode_utf8_string(struct utf8_enc_str *utf8_str, const char *buf,
    uint16_t len) {
  if (len > 0xfffe) {
    printf("Error: String too long to be encoded as UTF8 string\n");
    return 0;
  }

  memcpy(&utf8_str->utf8_str, buf, len);

  utf8_str->len_msb = (uint8_t)(len >> 8);
  utf8_str->len_lsb = (uint8_t)len;

  /* subtract 1 for the utf8_str placeholder */
  return (sizeof(struct utf8_enc_str) - 1)  + len;
}

/**
 * \brief Function to free memory allocated to struct mqtt_packet.
 * \param pkt The packet to free.
 */
void free_packet(struct mqtt_packet *pkt) {
  if (pkt) {
    free(pkt);
  }

  return;
}
