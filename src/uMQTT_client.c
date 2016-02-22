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
#include "uMQTT_helper.h"
#include "inc/log.h"

/**
 * \brief Function to allocate memory for a broker connection struct.
 * \param conn_p Pointer to the address of the new connection struct.
 */
void init_connection(struct broker_conn **conn_p) {
  log_stderr(LOG_DEBUG, "fn: init_connection");

  struct broker_conn *conn;

  if (!(conn = calloc(1, sizeof(struct broker_conn)))) {
    log_stderr(LOG_ERROR, "Allocating space for the broker connection failed");
    free_connection(conn);
  }

  if (!(conn->client.clientid = calloc(UMQTT_CLIENTID_MAX_LEN, sizeof(char)))) {
    log_stderr(LOG_ERROR, "Allocating space for the clientid failed");
    free_connection(conn);
  }

  if (!(conn->client.username = calloc(UMQTT_USERNAME_MAX_LEN, sizeof(char)))) {
    log_stderr(LOG_ERROR, "Allocating space for the username failed");
    free_connection(conn);
  }

  if (!(conn->client.password = calloc(UMQTT_PASSWORD_MAX_LEN, sizeof(char)))) {
    log_stderr(LOG_ERROR, "Allocating space for the password failed");
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
 * \param receive_method Function pointer to the receive method.
 */
void register_connection_methods(struct broker_conn *conn,
    umqtt_ret (*connect_method)(struct broker_conn *),
    umqtt_ret (*disconnect_method)(struct broker_conn *),
    umqtt_ret (*send_method)(struct broker_conn *,  struct mqtt_packet *),
    umqtt_ret (*receive_method)(struct broker_conn *, struct mqtt_packet *),
    umqtt_ret (*process_method)(struct broker_conn *, struct mqtt_packet *),
    void (*free_method)(struct broker_conn *)) {
  log_stderr(LOG_DEBUG, "fn: register_connection_methods");

  if (connect_method) {
    conn->connect_method = connect_method;
  }

  if (disconnect_method) {
    conn->disconnect_method = disconnect_method;
  }

  if (send_method) {
    conn->send_method = send_method;
  }

  if (receive_method) {
    conn->receive_method = receive_method;
  }

  if (process_method) {
    conn->process_method = process_method;
  }

  if (free_method) {
    conn->free_method = free_method;
  }

  return;
}

/**
 * \brief Function to allocate memory for an mqtt_process_methods struct.
 * \param proc Pointer to the address of the new mqtt_process_methods struct.
 * \return umqtt_ret return code.
 */
umqtt_ret init_process_methods(struct mqtt_process_methods **proc_p) {
  log_stderr(LOG_DEBUG, "fn: init_process_methods");
  struct mqtt_process_methods *proc;

  if (!(proc = calloc(1, sizeof(struct mqtt_process_methods)))) {
    log_stderr(LOG_ERROR, "Allocating space for MQTT process methods failed");
    free_process_methods(proc);
    return UMQTT_MEM_ERROR;
  }

  *proc_p = proc;

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to register implementation specific process methods.
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
umqtt_ret register_process_methods(struct mqtt_process_methods **proc_p,
  umqtt_ret (*connect_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*connack_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*publish_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*puback_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*pubrel_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*pubcomp_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*pubrec_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*subscribe_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*unsubscribe_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*suback_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*unsuback_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*pingreq_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*pingresp_method)(struct broker_conn *, struct mqtt_packet *),
  umqtt_ret (*disconnect_method)(struct broker_conn *, struct mqtt_packet *)) {
  log_stderr(LOG_DEBUG, "fn: register_process_methods");

  struct mqtt_process_methods *proc;
  if (init_process_methods(&proc)) {
    log_stderr(LOG_ERROR, "Allocating memory");
    return UMQTT_MEM_ERROR;
  }

  if (connect_method) {
    proc->connect_method = connect_method;
  }

  if (connack_method) {
    proc->connack_method = connack_method;
  }

  if (publish_method) {
    proc->publish_method = publish_method;
  }

  if (puback_method) {
    proc->puback_method = puback_method;
  }

  if (pubrel_method) {
    proc->pubrel_method = pubrel_method;
  }

  if (pubcomp_method) {
    proc->pubcomp_method = pubcomp_method;
  }

  if (pubrec_method) {
    proc->pubrec_method = pubrec_method;
  }

  if (subscribe_method) {
    proc->subscribe_method = subscribe_method;
  }

  if (unsubscribe_method) {
    proc->unsubscribe_method = unsubscribe_method;
  }

  if (suback_method) {
    proc->suback_method = suback_method;
  }

  if (unsuback_method) {
    proc->unsuback_method = unsuback_method;
  }

  if (pingreq_method) {
    proc->pingreq_method = pingreq_method;
  }

  if (pingresp_method) {
    proc->pingresp_method = pingresp_method;
  }

  if (disconnect_method) {
    proc->disconnect_method = disconnect_method;
  }

  *proc_p = proc;
  return UMQTT_SUCCESS;
}

/**
 * \brief Function to set the clientid.
 * \param conn Pointer to the broker_conn struct.
 * \param clientid The clientid.
 * \param len The len of clientid string.
 * \return umqtt_ret
 */
umqtt_ret broker_set_clientid(struct broker_conn *conn, const char *clientid,
    size_t len) {
  log_stderr(LOG_DEBUG, "fn: broker_set_clientid");

  if (!strncpy(conn->client.clientid, clientid, len)) {
    log_stderr(LOG_ERROR, "Failed to copy clientid");
    return UMQTT_MEM_ERROR;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to connect to broker socket and send a
 *        CONNECT packet..
 * \param conn Pointer to the broker_conn struct.
 * \return umqtt_ret
 */
umqtt_ret broker_connect(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: broker_connect");

  umqtt_ret ret = UMQTT_SUCCESS;

  if (conn->connect_method && conn->connect_method(conn)) {
    log_stderr(LOG_ERROR, "Broker connection failed");
    return UMQTT_CONNECT_ERROR;
  }

  /* build connect packet */
  struct mqtt_packet *pkt = construct_packet_headers(CONNECT);

  ret = init_packet_payload(pkt, CONNECT, 0, 0);
  if (ret) {
    free_packet(pkt);
    return ret;
  }

  if (conn->client.clientid[0]) {
    set_connect_payload(pkt, conn->client.clientid,
        strlen(conn->client.clientid));
  } else {
    /* set unique clientid */
    char buf[UMQTT_MAX_PACKET_LEN] = UMQTT_DEFAULT_TOPIC;
    int len = strlen(buf);
    buf[len++] = '-';
    gen_unique_string(&buf[len], 8);

    set_connect_payload(pkt, buf, strlen(buf));
  }

  finalise_packet(pkt);

  print_packet(pkt);

  ret = conn->send_method(conn, pkt);
  free_packet(pkt);
  if (ret) {
    log_stderr(LOG_ERROR, "Connect Packet Failed");
    return ret;
  }

  /* get response */
  struct mqtt_packet *pkt_resp;
  if (init_packet(&pkt_resp)) {
    log_stderr(LOG_ERROR, "Allocating memory");
    free_packet(pkt);
    return UMQTT_MEM_ERROR;
  }

  uint8_t count = 0;

  do {
    ret = conn->receive_method(conn, pkt_resp);
    if (ret) {
      log_stderr(LOG_ERROR, "Connect Response Packet Failed");
      break;
    }
  } while (conn->state != UMQTT_CONNECTED && count++ < MAX_RESP_PKT_RETRIES);

  free_packet(pkt_resp);

  if (conn->state != UMQTT_CONNECTED) {
    ret = UMQTT_CONNECT_ERROR;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to send packets to the broker connection.
 * \param conn The connection to send the packet through.
 * \param pkt The Packet to send to the broker
 */
umqtt_ret broker_send_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  log_stderr(LOG_DEBUG, "fn: broker_send_packet");

  umqtt_ret ret = UMQTT_SUCCESS;
  if (conn->send_method) {
    ret = conn->send_method(conn, pkt);
  } else {
    ret = UMQTT_SEND_ERROR;
  }
  return ret;
}

/**
 * \brief Function to receive packets to the broker connection.
 * \param conn The connection to receive the packet through.
 * \param pkt Pointer to the incoming packet.
 */
umqtt_ret broker_receive_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  log_stderr(LOG_DEBUG, "fn: broker_receive_packet");

  umqtt_ret ret = UMQTT_SUCCESS;

  if (conn->receive_method) {
    ret = conn->receive_method(conn, pkt);
  } else {
    ret = UMQTT_RECEIVE_ERROR;
  }

  return ret;
}

/**
 * \brief Function to process packets to the broker connection.
 * \param conn The connection to send the packet through.
 * \param pkt The packet to be processed.
 */
umqtt_ret broker_process_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  log_stderr(LOG_DEBUG, "fn: broker_process_packet");

  umqtt_ret ret = UMQTT_SUCCESS;

  switch (pkt->fixed->generic.type) {

    case CONNECT:
      if (conn->proc && conn->proc->connect_method) {
        ret = conn->proc->connect_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case CONNACK:
      if (conn->proc && conn->proc->connack_method) {
        ret = conn->proc->connack_method(conn, pkt);

      } else {
        /* Processing response */
        if (pkt->variable->connack.connect_ret == CONN_ACCEPTED) {
          conn->state = UMQTT_CONNECTED;
        } else {
          conn->state = UMQTT_DISCONNECTED;
          log_stderr(LOG_ERROR, "MQTT connect failed");
          ret = UMQTT_CONNECT_ERROR;
        }
      }
      break;

    case PUBLISH:
      if (conn->proc && conn->proc->publish_method) {
        ret = conn->proc->publish_method(conn, pkt);

      } else {
        print_publish_packet(pkt);
      }
      break;

    case PUBACK:
      if (conn->proc && conn->proc->puback_method) {
        ret = conn->proc->puback_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case PUBCOMP:
      if (conn->proc && conn->proc->pubcomp_method) {
        ret = conn->proc->pubcomp_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case PUBREL:
      if (conn->proc && conn->proc->pubrel_method) {
        ret = conn->proc->pubrel_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case PUBREC:
      if (conn->proc && conn->proc->pubrec_method) {
        ret = conn->proc->pubrec_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case SUBSCRIBE:
      if (conn->proc && conn->proc->subscribe_method) {
        ret = conn->proc->subscribe_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case UNSUBSCRIBE:
      if (conn->proc && conn->proc->unsubscribe_method) {
        ret = conn->proc->unsubscribe_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case SUBACK:
      if (conn->proc && conn->proc->suback_method) {
        ret = conn->proc->suback_method(conn, pkt);

      } else {
        int i = 0;
        for (i = 0; i < conn->sub_count; i++) {
          if (pkt->variable->generic.pkt_id == conn->subs[i]->variable->generic.pkt_id) {
            if (pkt->payload->data == 0x00) {
              pkt->fixed->generic.type = SUBACK;
            } else {
              log_stderr(LOG_ERROR, "bad SUBACK return: 0x%X", pkt->payload->data);
              ret = UMQTT_CONNECT_ERROR;
            }
            break;
          }
        }
      }
      break;

    case UNSUBACK:
      if (conn->proc && conn->proc->unsuback_method) {
        ret = conn->proc->unsuback_method(conn, pkt);

      } else {
        ret = UMQTT_PKT_NOT_SUPPORTED;
      }
      break;

    case PINGREQ:
      if (conn->proc && conn->proc->pingreq_method) {
        ret = conn->proc->pingreq_method(conn, pkt);

      } else {
        /* send PINGRESP */
        struct mqtt_packet *pkt_resp = construct_default_packet(PINGRESP, 0, 0);
        if (conn->send_method(conn, pkt)) {
          log_stderr(LOG_ERROR, "Failed to send PINGRESP packet");
          if (log_level(LOG_NONE) == LOG_DEBUG) {
            print_packet(pkt);
          }
          ret = UMQTT_PACKET_ERROR;
        }
        free_packet(pkt_resp);
      }
      break;

    case PINGRESP:
      if (conn->proc && conn->proc->pingresp_method) {
        ret = conn->proc->pingresp_method(conn, pkt);

      } else {
        conn->state = UMQTT_CONNECTED;
      }
      break;

    case DISCONNECT:
      if (conn->proc && conn->proc->disconnect_method) {
        ret = conn->proc->disconnect_method(conn, pkt);

      } else {
        conn->state = UMQTT_DISCONNECTED;
      }
      break;

    default:
      ret = UMQTT_PKT_NOT_SUPPORTED;
  }

  if (ret == UMQTT_PKT_NOT_SUPPORTED) {
    log_stderr(LOG_ERROR, "MQTT packet not currently supported: %s",
        get_type_string(pkt->fixed->generic.type));
    if (log_level(LOG_NONE) == LOG_DEBUG) {
      print_packet(pkt);
    }
  }

  return ret;
}

/**
 * \brief Function to send PUBLISH packet to broker.
 * \param conn The connection to close.
 * \param topic The topic for which the message should be published.
 * \param topic_len The length of the topic.
 * \param *payload Pointer to payload data.
 * \param *pay_len The lenth of the attached payload data.
 * \param flags fixed header flags - (DUP|QoS|RETAIN)
 */
umqtt_ret broker_publish(struct broker_conn *conn, const char *topic,
    uint8_t retain, uint8_t qos, uint8_t dup, size_t topic_len, uint8_t
    *payload, size_t pay_len, uint8_t flags) {
  log_stderr(LOG_DEBUG, "fn: broker_publish");

  struct mqtt_packet *pkt = construct_default_packet(PUBLISH, payload,
      pay_len);
  if (!pkt) {
    log_stderr(LOG_ERROR, "PUBLISH packet failed");
    return UMQTT_ERROR;
  }

  if (set_publish_fixed_flags(pkt, retain, qos, dup)) {
    log_stderr(LOG_ERROR, "Failed to set packet flags");
    return UMQTT_ERROR;
  }

  if (conn->send_method(conn, pkt)) {
    log_stderr(LOG_ERROR, "Failed to send packet");
    return UMQTT_ERROR;
  }

  return UMQTT_SUCCESS;
}

/**
 * \brief Function to send SUBSCRIBE packet to broker.
 * \param conn The connection to SUBSCRIBE on.
 * \param topic The topic for which the message should be published.
 * \param topic_len The length of the topic.
 */
umqtt_ret broker_subscribe(struct broker_conn *conn, const char *topic,
    size_t topic_len) {
  log_stderr(LOG_DEBUG, "fn: broker_subscribe");
  umqtt_ret ret = UMQTT_SUCCESS;

  /* send subscribe packet */
  struct mqtt_packet *pkt = construct_default_packet(SUBSCRIBE, 0, 0);
  if (!pkt) {
    log_stderr(LOG_ERROR, "Creating subscribe packet");
    return UMQTT_PACKET_ERROR;
  }

  set_subscribe_payload(pkt, topic, topic_len, UMQTT_DEFAULT_QOS);
  finalise_packet(pkt);

  /* register subscription */
  conn->subs[conn->sub_count] = pkt;

  ret = conn->send_method(conn, pkt);
  if (ret) {
    log_stderr(LOG_ERROR, "Broker connection failed");
    free_packet(pkt);
    return ret;
  }

  /* get response */
  struct mqtt_packet *pkt_resp;
  if (init_packet(&pkt_resp)) {
    log_stderr(LOG_ERROR, "Allocating memory");
    return UMQTT_MEM_ERROR;
  }

  uint8_t count = 0;

  do {
    ret = conn->receive_method(conn, pkt_resp);
    if (ret) {
      log_stderr(LOG_ERROR, "Subscribe Response Packet Failed");
      free_packet(pkt_resp);
      return ret;
    }
  } while (pkt_resp->fixed->generic.type != SUBACK && count++ < MAX_RESP_PKT_RETRIES);

  if (pkt_resp->fixed->generic.type != SUBACK) {
    ret = UMQTT_SUBSCRIBE_ERROR;
  }

  free_packet(pkt_resp);

  return ret;
}

/**
 * \brief Function to send DISCONNECT packet and close the connection.
 * \param conn The connection to close.
 */
umqtt_ret broker_disconnect(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: broker_disconnect");

  umqtt_ret ret = UMQTT_SUCCESS;

  if (conn->state) {
    /* disconnect from active session */
    struct mqtt_packet *pkt = construct_default_packet(DISCONNECT, 0, 0);

    if (!pkt) {
      return UMQTT_DISCONNECT_ERROR;
    }

    ret = conn->send_method(conn, pkt);
    if (ret) {
      free_packet(pkt);
      return UMQTT_PACKET_ERROR;
    }

    free_packet(pkt);
  }

  if (conn->disconnect_method(conn)) {
    return UMQTT_DISCONNECT_ERROR;
  }

  conn->state = UMQTT_DISCONNECTED;
  return UMQTT_SUCCESS;
}

/**
 * \brief Function to free memory allocated to struct mqtt_packet.
 * \param pkt The packet to free.
 */
void free_process_methods(struct mqtt_process_methods *proc) {
  log_stderr(LOG_DEBUG, "fn: free_process_methods");
  if (proc) {
    free(proc);
  }

  return;
}

/**
 * \brief Function to free memory allocated to struct broker_conn.
 * \param conn The connection to free.
 */
void free_connection(struct broker_conn *conn) {
  log_stderr(LOG_DEBUG, "fn: free_connection");

  if (conn->free_method) {
    conn->free_method(conn);
  }

  free_process_methods(conn->proc);

  if (conn->client.clientid) {
    free(conn->client.clientid);
  }

  if (conn->client.username) {
    free(conn->client.username);
  }

  if (conn->client.password) {
    free(conn->client.password);
  }

  if (conn) {
    free(conn);
  }
  
  return;
}
