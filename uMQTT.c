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

#include "uMQTT.h"

/**
 * \brief Function to allocate memory for an mqtt packet.
 * \param pkt Pointer to the address of the new packet.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet(struct mqtt_packet **pkt_p) {
  struct mqtt_packet *pkt;

  if (!(pkt = calloc(1, sizeof(struct mqtt_packet)))) {
    printf("Error: Allocating space for MQTT packet failed.\n");
    free_pkt(pkt);
    return UMQTT_MEM_ERROR;
  }

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

  /* allocate fixed header memory */
  pkt->fix_len = sizeof(struct pkt_fixed_header);
  if (!(pkt->fixed = calloc(1, pkt->fix_len))) {
    printf("Error: Allocating space for fixed header failed.\n");
    free_pkt_fixed_header(pkt->fixed);

    return UMQTT_MEM_ERROR;
  }

  pkt->fixed->generic.type = type;

  encode_remaining_len(pkt, 0);

  pkt->len = pkt->fix_len;

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

  switch (type) {
    case CONNECT:

      /* variable header */
      pkt->var_len = sizeof(struct connect_variable_header);

      /* allocate variable header */
      if (!(pkt->variable = calloc(1, pkt->var_len))) {
        printf("Error: Allocating space for variable header failed.\n");
        free_pkt_variable_header(pkt->variable);

        return UMQTT_MEM_ERROR;
      }

      /* defaults */
      pkt->variable->connect.name_len = (0x04>>8) | (0x04<<8); //swap endianess
      memcpy(pkt->variable->connect.proto_name, MQTT_PROTO_NAME, 0x04);
      pkt->variable->connect.proto_level = MQTT_PROTO_LEVEL;

      break;

    case PUBLISH:
      /* variable header - default action does not include pkt_id => qos = 0 */
      pkt->var_len = (sizeof(struct utf8_enc_str) - 1) +
        (sizeof(MQTT_DEFAULT_TOPIC) - 1);

      /* allocate variable header */
      if (!(pkt->variable = calloc(1, pkt->var_len))) {
        printf("Error: Allocating space for variable header failed.\n");
        free_pkt_variable_header(pkt->variable);

        return UMQTT_MEM_ERROR;
      }

      /* defaults */
      pkt->pay_len = encode_utf8_string(&pkt->variable->publish.topic_name,
          MQTT_DEFAULT_TOPIC, (sizeof(MQTT_DEFAULT_TOPIC) - 1));

      if (pkt->fixed->publish.qos) {
        /* set packet identifier */
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

  /* Remaining length currently zero */
  encode_remaining_len(pkt, pkt->var_len);

  pkt->len = pkt->fix_len + pkt->var_len;

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
    uint8_t *payload, uint8_t pay_len) {

  switch (type) {
    case CONNECT:

      /* allocate payload memory */
      if (!(pkt->payload = calloc(1, MQTT_MAX_PAYLOAD_LEN))) {
        printf("Error: Allocating space for payload.\n");
        free_pkt_payload(pkt->payload);

        return UMQTT_MEM_ERROR;
      }

      pkt->pay_len = encode_utf8_string(
          (struct utf8_enc_str *)&pkt->payload->data, MQTT_CLIENT_ID,
          (sizeof(MQTT_CLIENT_ID) - 1));

      break;

    case PUBLISH:
      pkt->pay_len = pay_len;
      pkt->payload = (struct pkt_payload *)payload;

      break;

    default:
      printf("Error: MQTT packet type not currently supported.\n");

      return UMQTT_ERROR;
  }

  pkt->len += pkt->pay_len;

  encode_remaining_len(pkt, (pkt->var_len + pkt->pay_len));

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to construct a new default mqtt packet.
 * \param type The type of packet to be created.
 * \param *payload Pointer to payload data.
 * \param *pay_len The lenth of the attached payload data.
 * \return Pointer to new mqtt_packet struct, 0 on failurer.
 */
struct mqtt_packet *construct_default_packet(ctrl_pkt_type type,
    uint8_t *payload, uint8_t pay_len) {

  struct mqtt_packet *pkt = '\0';

  if (init_packet(&pkt)) {
    free_pkt(pkt);
    return 0;
  }

  if (init_packet_fixed_header(pkt, CONNECT)) {
    free_pkt(pkt);
    return 0;
  }

  if (init_packet_variable_header(pkt, CONNECT)) {
    free_pkt(pkt);
    return 0;
  }

  if (init_packet_payload(pkt, CONNECT, '\0', 0)) {
    free_pkt(pkt);
    return 0;
  }

  return pkt;

}

/**
 * \brief Function to encode the remaining length of an MQTT packet,
 *        after the fixed header, into the fixed packet header - see section
 *        2.2.3 of the MQTT spec.
 * \param pkt The packet whose length to encode.
 * \param len The length that should be encoded.
 */
void encode_remaining_len(struct mqtt_packet *pkt, unsigned int len) {
  int i = 0;
  do {
    pkt->fixed->remain_len[i] = len % 128;
    len /= 128;

    if (len > 0) {
      pkt->fixed->remain_len[i] |= 128;
    }
    i++;
  } while (len > 0 && i < 4);

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
  int i = 0;
  unsigned int len = 0;
  unsigned int product = 1;
  do {
    len += (pkt->fixed->remain_len[i] & 127) * product;

    if (product > 128*128*128) {
      printf("Error: Malformed remaining length.\n");
      return 0;
    }
    product *= 128;

  } while ((pkt->fixed->remain_len[i++] & 128) != 0 && i < 4);

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
void free_pkt(struct mqtt_packet *pkt) {
  if (pkt) {
    if (pkt->fixed) {
      free(pkt->fixed);
    }

    if (pkt->variable) {
      free(pkt->variable);
    }

    if (pkt->payload) {
      free(pkt->variable);
    }

    free(pkt);
  }

  return;
}
  
/**
 * \brief Function to free memory allocated to struct pkt_fixed_header.
 * \param fix The fixed header to free.
 */
void free_pkt_fixed_header(struct pkt_fixed_header *fix) {
  if (fix) {
    free(fix);
  }

  return;
}

/**
 * \brief Function to free memory allocated to struct pkt_variable_header.
 * \param var The variable header to free.
 */
void free_pkt_variable_header(struct pkt_variable_header *var) {
  if (var) {
    free(var);
  }

  return;
}

/**
 * \brief Function to free memory allocated to struct pkt_payload.
 * \param pld The payload to free.
 */
void free_pkt_payload(struct pkt_payload *pld) {
  if (pld) {
    free(pld);
  }

  return;
}
