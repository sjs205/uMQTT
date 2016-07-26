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
#include "inc/log.h"

/**
 * \brief Function to allocate memory for an mqtt packet.
 * \param pkt Pointer to the address of the new packet.
 * \return umqtt_ret return code.
 */
umqtt_ret init_packet(struct mqtt_packet **pkt_p) {
  struct mqtt_packet *pkt;

  log_std(LOG_DEBUG_FN, "fn: init_packet");

  if (!(pkt = calloc(1, sizeof(struct mqtt_packet)))) {
    log_std(LOG_ERROR, "Allocating space for MQTT packet failed");
    return UMQTT_MEM_ERROR;
  }

  if (!(pkt->raw.buf = calloc(sizeof(uint8_t), UMQTT_DEFAULT_PKT_LEN))) {
    log_std(LOG_ERROR, "Allocating space for raw packet failed");
    free_packet(pkt);
    return UMQTT_MEM_ERROR;
  }

  pkt->raw.len = UMQTT_DEFAULT_PKT_LEN;
  *pkt_p = pkt;

  log_std(LOG_DEBUG_FN, "New packet with %zu bytes allocated", pkt->raw.len);

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

  log_std(LOG_DEBUG_FN, "fn: init_packet_fixed_header");

  /* allocate initial fixed header length */
  pkt->fix_len =
    1 + MAX_REMAIN_LEN_BYTES;

  /* alloate fixed header */
  pkt->fixed = (struct pkt_fixed_header *)pkt->raw.buf;

  pkt->fixed->generic.type = type;

  pkt->len = pkt->fix_len;

  if (type == PUBREL || type == SUBSCRIBE || type == UNSUBSCRIBE ) {
    /* Reserved bytes should be 0x02 */
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
  umqtt_ret ret = UMQTT_SUCCESS;

  log_std(LOG_DEBUG_FN, "fn: init_packet_variable_header");

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
      pkt->variable->connect.flags.clean_session_flag |= 1;
      break;

    case CONNACK:
      pkt->var_len = sizeof(struct connack_variable_header);
      break;

    case PUBLISH:
      /* defaults */
      ret = set_publish_variable_header(pkt, UMQTT_DEFAULT_TOPIC,
          (sizeof(UMQTT_DEFAULT_TOPIC)));
      break;

    case SUBSCRIBE:
    case UNSUBSCRIBE:
      pkt->var_len = sizeof(struct generic_variable_header);

      /* set packet identifier */
      *(uint16_t *)&pkt->raw.buf[pkt->fix_len + pkt->var_len -
        sizeof(struct generic_variable_header)] = generate_packet_id(0);

      break;

    case PUBACK:
    case PUBREC:
    case PUBREL:
    case PUBCOMP:
    case SUBACK:
    case UNSUBACK:
      pkt->var_len = sizeof(struct generic_variable_header);

      break;

    case PINGREQ:
    case PINGRESP:
    case DISCONNECT:
      break;

    default:
      log_std(LOG_ERROR, "Init variable: MQTT packet type not supported: %s",
          type);

      ret = UMQTT_ERROR;
      break;
  }

  /* recalculate pay->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  return ret;
}

/**
 * \brief Function to set the fixed header flags of a publish packet
 * \param pkt Pointer to the address of the packet.
 * \param retain The retain flag.
 * \param qos The quality of service for the message.
 * \param dup The duplicate flag.
 */
umqtt_ret set_publish_fixed_flags(struct mqtt_packet *pkt, uint8_t retain,
    qos_t qos, uint8_t dup) {
  log_std(LOG_DEBUG_FN, "fn: set_publish_fixed_flags");
  if (pkt) {
    if (retain) {
      pkt->fixed->publish.retain = 1;
    } else {
      pkt->fixed->publish.retain = 0;
    }

    if (qos && qos <= 3) {
      pkt->fixed->publish.qos = qos;
    } else {
      pkt->fixed->publish.qos = 0;
    }

    if (dup) {
      pkt->fixed->publish.dup = 1;
    } else {
      pkt->fixed->publish.dup = 0;
    }

    return UMQTT_SUCCESS;
  } else {
    log_std(LOG_ERROR, "Invalid packet");
    return UMQTT_PACKET_ERROR;
  }
}

/**
 * \brief Function to generate a new packet identifier
 * \param pkt_id Packet identifier to set, if zero, the current packet
 *          identifier value is incremented.
 * \return big-endian 16-bit packet identifier.
 */
uint16_t generate_packet_id(uint16_t pkt_id) {
  static uint16_t packet_id = 1;
  log_std(LOG_DEBUG_FN, "fn: generate_packet_id");

  if (pkt_id > 0) {
    /* set pkt_id */
    log_std(LOG_DEBUG, "Setting packet Id generator to %d", pkt_id);
    packet_id = pkt_id;

    return ((packet_id >> 8) | (packet_id << 8));

  } else {
    pkt_id = packet_id++;
    return ((pkt_id >> 8) | (pkt_id << 8));
  }
}

/**
 * \brief Function to set the packet identifier of a packet.
 * \param pkt The mxtt_packet.
 * \param pkt_id The packet id value to set.
 * \return Host format 16-bit packet identifier.
 */
uint16_t set_packet_pkt_id(struct mqtt_packet *pkt, uint16_t pkt_id) {
  log_std(LOG_DEBUG_FN, "fn: set_packet_pkt_id");

  if ((pkt->fixed->generic.type == CONNECT) ||
      (pkt->fixed->generic.type == CONNACK) ||
      (pkt->fixed->generic.type == PINGREQ) ||
      (pkt->fixed->generic.type == PINGRESP) ||
      (pkt->fixed->generic.type == DISCONNECT) ||
      (pkt->fixed->generic.type == PUBLISH &&
       pkt->fixed->publish.qos == QOS_AT_MOST_ONCE)) {
    /* No pkt_id */
    return 0;

  } else {
    log_std(LOG_DEBUG, "Setting packet Id to %d", pkt_id);
#ifdef BIG_ENDIAN_HOST

#else
    *(uint16_t *)&pkt->raw.buf[pkt->fix_len + pkt->var_len -
      sizeof(struct generic_variable_header)] =
      ((pkt_id >> 8) | (pkt_id << 8));
    return pkt_id;
#endif
  }
  return 0;
}

/**
 * \brief Function to return the packet identifier of a packet.
 * \param pkt The mxtt_packet.
 * \return Host format 16-bit packet identifier.
 */
uint16_t get_packet_pkt_id(struct mqtt_packet *pkt) {
  log_std(LOG_DEBUG_FN, "fn: get_packet_pkt_id");

  if ((pkt->fixed->generic.type == CONNECT) ||
      (pkt->fixed->generic.type == CONNACK) ||
      (pkt->fixed->generic.type == PINGREQ) ||
      (pkt->fixed->generic.type == PINGRESP) ||
      (pkt->fixed->generic.type == DISCONNECT) ||
      (pkt->fixed->generic.type == PUBLISH &&
       pkt->fixed->publish.qos == QOS_AT_MOST_ONCE)) {
    /* No pkt_id */
    return 0;
  } else {

    /* pkt_id is always the last 2 bytes of the variable header */
#ifdef BIG_ENDIAN_HOST

#else
    return (uint16_t)(*(uint16_t *)(&pkt->raw.buf[pkt->fix_len +
          (pkt->var_len - sizeof(struct generic_variable_header))]) >> 8)
      | (*(uint16_t *)(&pkt->raw.buf[pkt->fix_len +
            (pkt->var_len - sizeof(struct generic_variable_header))]) << 8);
#endif
  }
  return 0;
}

/**
 * \brief Function to set the variable header of a PUBLISH packet.
 * \param pkt Pointer to the address of the packet.
 * \param topic The topic for which the message should be published.
 * \param topic_len The length of the topic.
 */
umqtt_ret set_publish_variable_header(struct mqtt_packet *pkt,
    const char *topic, size_t topic_len) {

  log_std(LOG_DEBUG_FN, "fn: set_publish_packet_variable_header");

  if (topic && topic[0] != '\0') {
    pkt->var_len = encode_utf8_string(&pkt->variable->publish.topic, topic,
        topic_len);
  } else {
    pkt->var_len = encode_utf8_string(&pkt->variable->publish.topic,
        UMQTT_DEFAULT_TOPIC, sizeof(UMQTT_DEFAULT_TOPIC));
  }

  if (pkt->fixed->publish.qos) {
    /* set packet identifier */
    *(uint16_t *)&pkt->raw.buf[pkt->fix_len + pkt->var_len]
      = generate_packet_id(0);

    pkt->var_len += sizeof(uint16_t);
  }

  /* recalculate pay->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to set the variable header of a CONNECT packet.
 * \param pkt Pointer to the address of the packet.
 */
umqtt_ret set_connect_variable_header(struct mqtt_packet *pkt,
    struct connect_flags flags, uint16_t keep_alive) {

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
  log_std(LOG_DEBUG_FN, "fn: init_packet_payload");

  umqtt_ret ret = UMQTT_SUCCESS;

  /* Ensure packet type supports a payload */
  if ((pkt->fixed->generic.type == CONNECT) ||
      (pkt->fixed->generic.type == PUBLISH) ||
      (pkt->fixed->generic.type == SUBSCRIBE) ||
      (pkt->fixed->generic.type == SUBACK) ||
      (pkt->fixed->generic.type == UNSUBSCRIBE)) {

    /* allocate payload */
    pkt->payload =
      (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];

    if (pay_len > 0 && payload) {
      /* ensure payload is less that mqtt max */
      if (pay_len <= MAX_REMAIN_LEN_PRODUCT) {

        /* increase packet size? */
        if ((pay_len + pkt->fix_len + pkt->var_len) > pkt->raw.len) {
          size_t new_len = pay_len + pkt->fix_len + pkt->var_len;
          ret = resize_packet(&pkt, new_len);
          if (ret) {
            log_std(LOG_ERROR, "Payload resize failed");
            return UMQTT_PAYLOAD_ERROR;
          }
        }

        /* copy payload data */
        pkt->pay_len = pay_len;
        memcpy(&pkt->payload->data, payload, pay_len);

      } else {
        log_std(LOG_ERROR,
            "Payload length causes remaining length overflow");
        return UMQTT_PAYLOAD_ERROR;
      }

    } else {

      /* defaults */
      switch (type) {
        case CONNECT:
          /* The clientid set here should always be overloaded */
          ret = set_connect_payload(pkt, UMQTT_DEFAULT_CLIENTID,
              NULL, NULL, NULL, NULL);
          break;

        case SUBSCRIBE:
        case UNSUBSCRIBE:
          ret = set_un_subscribe_payload(pkt, UMQTT_DEFAULT_TOPIC,
              sizeof(UMQTT_DEFAULT_TOPIC), UMQTT_DEFAULT_QOS);
          break;

        case SUBACK:
          /* single byte return code */
          pkt->pay_len++;
          break;

        case PUBLISH:
          /* payload optional, so if none specified, make length 0 */
          pkt->pay_len = 0;
          break;

        default:
          log_std(LOG_DEBUG,
              "Init packet: MQTT packet type does not support a payload", type);
      }
    }
  } else {

    if (!pay_len) {
      /* probably just initialising packet */
      ret = UMQTT_SUCCESS;
    } else {
      log_std(LOG_ERROR,
          "Init packet: MQTT packet type does not support a payload", type);
      ret = UMQTT_PACKET_ERROR;
    }
  }

  /* recalculate pay->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  return ret;
}

/**
 * \brief Function to set the clientid of a CONNECT packet.
 * \param clientid The client ID.
 * \param len The length of the Client ID.
 */

umqtt_ret set_connect_payload(struct mqtt_packet *pkt, const char *clientid,
    const char *username, const char *password, const char *topic,
    const char *message) {
  log_std(LOG_DEBUG_FN, "fn: set_connect_payload");

  /* set clientid */
  if (clientid && clientid[0] != '\0') {

    pkt->pay_len = encode_utf8_string(
        (struct utf8_enc_str *)&pkt->payload->data, clientid, strlen(clientid));
  }

  /* set last will */
  if (pkt->variable->connect.flags.will_flag) {

    /* will topic */
    if (topic) {
      pkt->pay_len += encode_utf8_string(
          (struct utf8_enc_str *)(&pkt->payload->data + pkt->pay_len),
          topic, strlen(topic));
    }

    /* will message */
    if (message) {
      pkt->pay_len += encode_utf8_string(
          (struct utf8_enc_str *)(&pkt->payload->data + pkt->pay_len), message,
          strlen(message));
    }
  }

  /* set username */
  if (username) {
    pkt->pay_len += encode_utf8_string(
        (struct utf8_enc_str *)(&pkt->payload->data + pkt->pay_len), username,
        strlen(username));
  }

  /* set password */
  if (password) {
    pkt->pay_len += encode_utf8_string(
        (struct utf8_enc_str *)(&pkt->payload->data + pkt->pay_len), password,
        strlen(password));
  }

  /* recalculate pay->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to resize mqtt_pkt
 * \param pkt The mxtt_packet to finalise.
 * \param len The new packet length.
 * \return the number of bytes saved
 */
umqtt_ret resize_packet(struct mqtt_packet **pkt_p, size_t len) {
  log_std(LOG_DEBUG_FN, "fn: resize_packet");

  umqtt_ret ret = UMQTT_SUCCESS;

  uint8_t *buf = realloc((*pkt_p)->raw.buf, len * sizeof(uint8_t));
  if (!buf) {
    log_std(LOG_ERROR, "Packet resize failed");
    ret = UMQTT_MEM_ERROR;
  } else {

    if ((*pkt_p)->raw.len < len) {
      memset(&(*pkt_p)->raw.buf[(*pkt_p)->raw.len + 1], 0,
          len - (*pkt_p)->raw.len);
    }
    (*pkt_p)->raw.len = len;
    (*pkt_p)->raw.buf = buf;

    /* ensure packet is aligned with raw packet */
    realign_packet(*pkt_p);

    log_std(LOG_DEBUG_FN, "Packet resize sucessfull, new length: %zu", len);
  }

  return ret;
}

/**
 * \brief Function to set the topics of a SUBSCRIBE or UNSUBSCRIBE packet.
 * \param topic The topic to subscribe or unsubscribe to.
 * \param topic_len The length of the topic.
 * \param qos The subscription QOS - SUBSCRIBE only.
 */
umqtt_ret set_un_subscribe_payload(struct mqtt_packet *pkt, const char *topic,
    size_t topic_len, uint8_t qos) {
  log_std(LOG_DEBUG_FN, "fn: set_un_subscribe_payload");

  /* set topic */
  /* should guard against buffer overflow */
  pkt->pay_len += encode_utf8_string(
      (struct utf8_enc_str *)(&pkt->payload->data + pkt->pay_len), topic,
      topic_len);

  if (pkt->fixed->generic.type == SUBSCRIBE) {
    /* set topic QOS */
    *(&pkt->payload->data + pkt->pay_len++) = (0x03 & qos);
  }

  /* recalculate pkt->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to construct new default mqtt packet headers.
 * \param type The type of packet headers to be created.
 * \return Pointer to new mqtt_packet struct, 0 on failurer.
 */
struct mqtt_packet *construct_packet_headers(ctrl_pkt_type type) {
  log_std(LOG_DEBUG_FN, "fn: construct_packet_headers");

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
  log_std(LOG_DEBUG_FN, "fn: construct_default_packet");

  struct mqtt_packet *pkt = construct_packet_headers(type);

  if (init_packet_payload(pkt, type, payload, pay_len)) {
    free_packet(pkt);
    return NULL;
  }

  return pkt;
}

/**
 * \brief Function to cleanup mqtt_pkt removing any unused space and
 *        ensuring memory is packed.
 * \param pkt The mxtt_packet to finalise.
 * \return the number of bytes saved
 */
size_t finalise_packet(struct mqtt_packet *pkt) {
  log_std(LOG_DEBUG_FN, "fn: finalise_packet");

  size_t fix_len = pkt->fix_len;
  size_t delta = 0;

  encode_remaining_len(pkt, (pkt->var_len + pkt->pay_len));

  delta = fix_len - pkt->fix_len;
  if (delta) {
    /* need to shift data backwards to ensure packet is packed */
    memmove_back(&pkt->raw.buf[pkt->fix_len], delta, pkt->var_len);
    memmove_back(&pkt->raw.buf[pkt->fix_len + pkt->var_len], delta,
        pkt->pay_len);

    realign_packet(pkt);
  }

  /* recalculate pay->len */
  pkt->len = pkt->fix_len + pkt->var_len + pkt->pay_len;

  /* Free unused space */
  if (pkt->len < UMQTT_DEFAULT_PKT_LEN) {
    resize_packet(&pkt, pkt->len);
  }

  return delta;
}

/**
 * \brief Function to realign struct mqtt_pkt to struct raw_pkt based on the
 *        pkt->raw.buf address and current packet section lengths.
 * \param pkt The mxtt_packet to realign.
 */
void realign_packet(struct mqtt_packet *pkt) {
  log_std(LOG_DEBUG_FN, "fn: realign_packet");

  /* align fixed header */
  pkt->fixed = (struct pkt_fixed_header *)pkt->raw.buf;

  /* align variable header */
  pkt->variable = (struct pkt_variable_header *)&pkt->raw.buf[pkt->fix_len];

  /* align payload */
  pkt->payload =
    (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];

  return;
}

/**
 * \brief Function to disect incoming raw packet into struct mqtt_pkt
 * \param pkt The mxtt_packet to disect.
 */
umqtt_ret disect_raw_packet(struct mqtt_packet *pkt) {
  umqtt_ret ret = UMQTT_SUCCESS;
  log_std(LOG_DEBUG_FN, "fn: disect_raw_packet");

  /* assign fixed header */
  pkt->fixed = (struct pkt_fixed_header *)pkt->raw.buf;

  /* size of fixed header */
  pkt->len = decode_remaining_len(pkt);
  pkt->fix_len = 1 + required_remaining_len_bytes(pkt->len);

  pkt->len += pkt->fix_len;

  /* assign variable header */
  pkt->variable = (struct pkt_variable_header *)&pkt->raw.buf[pkt->fix_len];

  switch (pkt->fixed->generic.type) {
    case CONNECT:
      pkt->var_len = sizeof(struct connect_variable_header);
      /* validate reserved nibble */
      if (pkt->fixed->generic.reserved != 0x0 ) {
        log_std(LOG_ERROR, "Malformed packet - reserved nibble: 0x%X",
            pkt->fixed->generic.reserved);
        ret = UMQTT_PACKET_ERROR;
      }
      break;

    case CONNACK:
      pkt->var_len = sizeof(struct connack_variable_header);
      /* validate reserved nibble */
      if (pkt->fixed->generic.reserved != 0x0 ) {
        log_std(LOG_ERROR, "Malformed packet - reserved nibble: 0x%X",
            pkt->fixed->generic.reserved);
        ret = UMQTT_PACKET_ERROR;
      }
      break;

    case PUBLISH:
      /* topic string length */
      pkt->var_len = (uint16_t)((pkt->variable->publish.topic.len_msb << 8)
          | (pkt->variable->publish.topic.len_lsb));

      /* utf8 encoded string length */
      pkt->var_len += 2;

      if (pkt->fixed->publish.qos == QOS_AT_LEAST_ONCE ||
          pkt->fixed->publish.qos == QOS_EXACTLY_ONCE) {
        /* packet id length */
        pkt->var_len += sizeof(uint16_t);
      }
      break;

    case PUBACK:
    case PUBCOMP:
    case PUBREC:
    case SUBACK:
    case UNSUBACK:
      pkt->var_len = sizeof(struct generic_variable_header);
      /* validate reserved nibble */
      if (pkt->fixed->generic.reserved != 0x00 ) {
        log_std(LOG_ERROR, "Malformed packet - reserved nibble: 0x%X",
            pkt->fixed->generic.reserved);
        ret = UMQTT_PACKET_ERROR;
      }
      break;
    case PUBREL:
    case SUBSCRIBE:
    case UNSUBSCRIBE:
      pkt->var_len = sizeof(struct generic_variable_header);
      /* validate reserved nibble */
      if (pkt->fixed->generic.reserved != 0x2 ) {
        log_std(LOG_ERROR, "Malformed packet - reserved nibble: 0x%X",
            pkt->fixed->generic.reserved);
        ret = UMQTT_PACKET_ERROR;
      }
      break;

    case PINGREQ:
    case PINGRESP:
    case DISCONNECT:
      pkt->var_len = 0;
      /* validate reserved nibble */
      if (pkt->fixed->generic.reserved != 0x0 ) {
        log_std(LOG_ERROR, "Malformed packet - reserved nibble: 0x%X",
            pkt->fixed->generic.reserved);
        ret = UMQTT_PACKET_ERROR;
      }
      break;

    default:
      log_std(LOG_ERROR, "MQTT packet not supported: %s",
          pkt->fixed->generic.type);
      ret = UMQTT_PKT_NOT_SUPPORTED;
  }

  /* check fixed and variable header sizes */
  if ((pkt->fix_len > sizeof(struct pkt_fixed_header)) ||
      ((pkt->var_len) >= pkt->len)) {
    log_std(LOG_ERROR, "Malformed packet, invalid length");
    log_std(LOG_ERROR, "Packet length: %zu Fixed header length %zu"
        " Variable header length: %zu Payload length: %zu",
        pkt->len, pkt->fix_len, pkt->var_len, pkt->var_len);

    pkt->pay_len = 0;
    ret = UMQTT_PACKET_ERROR;

  } else if ((pkt->var_len + pkt->fix_len) >= pkt->len) {
    /* no space for a payload */
    pkt->pay_len = 0;
    pkt->payload = NULL;

  } else {
    /* assign payload */
    pkt->pay_len = pkt->len - (pkt->fix_len + pkt->var_len);
    if (pkt->pay_len) {
      pkt->payload =
        (struct pkt_payload *)&pkt->raw.buf[pkt->fix_len + pkt->var_len];
    }
  }

  return ret;
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
  log_std(LOG_DEBUG_FN, "fn: memmove_back");
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
  log_std(LOG_DEBUG_FN, "fn: required_remaining_length_bytes");
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
  log_std(LOG_DEBUG_FN, "fn: encode_remaining_len");
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
  log_std(LOG_DEBUG_FN, "fn: decode_remaining_len");
  uint8_t i = 0;
  unsigned int len = 0;
  unsigned int product = 1;
  do {
    len += (pkt->fixed->remain_len[i] & 127) * product;

    product *= 128;
    if (product > MAX_REMAIN_LEN_PRODUCT) {
      log_std(LOG_ERROR, "Malformed remaining length");
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
 * \return len of utf8 encoded string
 */
uint16_t encode_utf8_string(struct utf8_enc_str *utf8_str, const char *buf,
    uint16_t len) {
  log_std(LOG_DEBUG_FN, "fn: encode_utf8_string");

  if (len > 0xfffe) {
    log_std(LOG_ERROR, "String too long to be encoded as UTF8 string");
    return 0;
  }

  len = strnlen(buf, len);
  memcpy(&utf8_str->utf8_str, buf, len);

  utf8_str->len_lsb = (uint8_t)len;
  utf8_str->len_msb = (uint8_t)(len << 8);

  /* subtract 1 for the utf8_str placeholder */
  return (uint16_t)((sizeof(struct utf8_enc_str) - 1)  + len);
}

/**
 * \brief Function to decode a utf8 string and place the result in buffer.
 * \param utf8_str Pointer to the struct holding the utf8_enc_str
 * \param buf Buffer for the decoded string followed by \0.
 * \return len of decoded string
 */
uint16_t decode_utf8_string(char *buf, struct utf8_enc_str *utf8_str) {
  uint16_t len = 0;
  log_std(LOG_DEBUG_FN, "fn: decode_utf8_string");

  len = (uint16_t)(utf8_str->len_msb << 8) | utf8_str->len_lsb;

  if (len > 0xfffe) {
    log_std(LOG_ERROR, "Malformed UTF8 string");
    return 0;
  }

  memcpy(buf, &utf8_str->utf8_str, len);
  buf[len] = '\0';

  return len;
}

/**
 * \brief Function to return the size of a utf8 encoded string,
 *        i.e., inc len bytes.
 * \param utf8 Pointer to the utf8 encoded to be sized.
 */
uint16_t utf8_enc_str_size(struct utf8_enc_str *utf8) {

  /* string length + size of length MSB & LSB */
  return (uint16_t)(((utf8->len_msb << 8) | utf8->len_lsb)
        + sizeof(uint16_t));
}

/**
 * \brief Function to free memory allocated to struct mqtt_packet.
 * \param pkt The packet to free.
 */
void free_packet(struct mqtt_packet *pkt) {
  log_std(LOG_DEBUG_FN, "fn: free_packet");

  if (pkt->raw.buf) {
    free(pkt->raw.buf);
  }

  if (pkt) {
    free(pkt);
  }

  return;
}
