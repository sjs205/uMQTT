/******************************************************************************
 * File: uMQTT_UDP_relay.c
 * Description: MicroMQTT (uMQTT) sublish application using linux based sockets
 *              to connect to the broker.
 *              constrained environments.
 * Author: Steven Swann - swannonline@googlemail.com
 *
 * Copyright (c) swannonline, 2013-2014
 *
 * This file is part of uMQTT.
 *
 * uMQTT is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as sublished by
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_helper.h"
#include "uMQTT_linux_client.h"
#include "../inc/log.h"

#define MAX_TOPIC_LEN         1024
#define MAX_MSG_LEN           1024
#define UDP_DEFAULT_BIND_IP   "127.0.0.1"
#define UDP_DEFAuLT_BIND_PORT 8181

#define SELECT_TIMEOUT        10

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_UDP_relay is an application that connects to an MQTT broker\n"
      "and allows clients to connect and interact with the broker over a UDP\n"
      "connection, thus allowing connectionless/sleepy nodes to connect with\n"
      "a broker.\n"
      "\n"
      "Usage: uMQTT_UDP_relay [options]\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      "\n"
      //"Subscribe options:\n"
      //" -t [--topic] <topic>     : Change the default topic. Default: uMQTT_PUB\n"
      //"\n"
      "Broker options:\n"
      " -b [--broker] <broker-IP>: Change the default broker IP - only IP\n"
      "                            addresses are currently supported.\n"
      "                            Default ip: localhost\n"
      " -p [--port] <port>       : Change the default port. Default: 1883\n"
      " -c [--clientid] <id>     : Change the default clientid\n"
      "\n"
      "UDP options:\n"
      " -P [--UDP-port <port>    : Port to open for UDP connections\n"
      " -B [--UDP-ip] <IP addr>  : The address to bind to\n"
      "Output options:\n"
      " -d [--detail]            : Output detailed packet information\n"
      "                            Default: output publish packet summary\n"
      " -x [--hex]               : Output hex packet\n"
      " -C [--counts]            : Print packet counts\n"
      "\n"
      "Debug options:\n"
      " -v [--verbose] <LEVEL>   : set verbose level to LEVEL\n"
      "                               Levels are:\n"
      "                                 SILENT\n"
      "                                 ERROR\n"
      "                                 WARN\n"
      "                                 INFO (default)\n"
      "                                 DEBUG\n"
      "                                 DEBUG_FN\n"
      "\n");

  return 0;
}

/**
 * \brief Function to receive packet from the UDP socket.
 * \param conn Pointer to the croker_conn struct.
 * \param pkt Pointer to the receiver buffer/packet.
 * \return Number of bytes read.
 */
umqtt_ret read_udp_socket_packet(struct broker_conn *conn, struct mqtt_packet *pkt) {
  LOG_DEBUG_FN("fn: read_socket_packet");

  umqtt_ret ret = UMQTT_SUCCESS;
  ssize_t len = 0;
  size_t read_len = 0;
  struct sockaddr src_addr = { 0 };
  socklen_t addrlen;

#if DEBUG
  static ssize_t largest = 0;
#endif

  struct linux_broker_socket *skt = (struct linux_broker_socket *)conn->context;

  /* Peek the packet fixed header to determine the packet length */
  do {
    len = recvfrom(skt->sockfd, pkt->raw.buf, sizeof(struct pkt_fixed_header),
        MSG_PEEK, &src_addr, &addrlen);
  } while (len < MQTT_MIN_PKT_LEN && len > 0);

  if (len == -1) {
    LOG_ERROR("Reading from socket %s", strerror(errno));
    ret = UMQTT_RECEIVE_ERROR;
    goto exit;
  }

  pkt->fixed = (struct pkt_fixed_header *)pkt->raw.buf;

  /* Get size of packet */
  pkt->len = decode_remaining_len(pkt);
  pkt->len += required_remaining_len_bytes(pkt->len) + 1;
  LOG_DEBUG("Detected packet length: %zu", pkt->len);

#if DEBUG
  if (pkt->len > largest) {
    largest = pkt->len;
  }
  LOG_DEBUG("Largest packet detected: %zu", largest);
#endif

  if (pkt->len > pkt->raw.len) {
    LOG_DEBUG("Resizing packet from: %zu to: %zu bytes", pkt->raw.len, pkt->len);
    ret = resize_packet(&pkt, pkt->len);
    if (ret) {
      goto exit;
    }
  }

  /* Ensure we read all bytes of the packet */
  while (read_len < pkt->len) {
    len = 0;
    len = recvfrom(skt->sockfd, pkt->raw.buf, sizeof(struct pkt_fixed_header),
        0, &src_addr, &addrlen);
    if (len < 0) {
      LOG_ERROR("Reading from socket %s", strerror(errno));
      ret = UMQTT_RECEIVE_ERROR;
      break;
    }

    read_len += len;
    LOG_DEBUG("Bytes expected: %zu, received: %zu, total: %zu", pkt->len,
        len, read_len);
  }

  /* Ensure read was sucessful */
  if (!ret && read_len >= MQTT_MIN_PKT_LEN) {

    pkt->len = read_len;
    print_packet_raw_debug(pkt);

    ret = disect_raw_packet(pkt);
    if (ret) {
      LOG_ERROR("Failed to decode %s packet.",
          get_type_string(pkt->fixed->generic.type));
      conn->fail_count++;

    } else {
      LOG_DEBUG("RX: %s - %zu bytes",
          get_type_string(pkt->fixed->generic.type), pkt->len);

      /* Update packet counts */
      conn->success_count++;
      if (pkt->fixed->generic.type == PUBLISH) {
        conn->publish_count++;
      }

      /* Can we process the message? */
      if (conn->process_method) {
        ret = conn->process_method(conn, pkt);
      }
    }
  }

exit:
  return ret;
}
int main(int argc, char **argv) {

  umqtt_ret ret;
  int c, option_index = 0;
  uint8_t detail = 0, hex = 0, error = 0, counts = 0;
  char topic[MAX_TOPIC_LEN] = UMQTT_DEFAULT_TOPIC;
  char broker_ip[16] = MQTT_BROKER_IP;
  int broker_port = MQTT_BROKER_PORT;
  char udp_ip[16] = UDP_DEFAULT_BIND_IP;
  int udp_port = UDP_DEFAuLT_BIND_PORT;
  char clientid[UMQTT_CLIENTID_MAX_LEN] = "\0";

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"verbose", required_argument,      0, 'v'},
    {"detail", no_argument,             0, 'd'},
    {"hex", no_argument,                0, 'x'},
    {"counts", no_argument,             0, 'C'},
    {"error", no_argument,              0, 'e'},
    {"topic", required_argument,        0, 't'},
    {"broker", required_argument,       0, 'b'},
    {"port", required_argument,         0, 'p'},
    {"UDP-ip", required_argument,       0, 'B'},
    {"UDP-port", required_argument,     0, 'P'},
    {"clientid", required_argument,     0, 'c'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hCdexv:t:b:p:B:P:c:", long_options,
            &option_index)) != -1) {

      switch (c) {
        case 'h':
          return print_usage();
          break;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 'x':
          /* set hex output */
          hex = 1;
          break;

        case 'C':
          /* print packet counts */
          counts = 1;
          break;

        case 'd':
          /* set detailed output */
          detail = 1;
          break;

        case 't':
          /* Set topic */
          if (optarg) {
            strcpy(topic, optarg);
          } else {
            LOG_ERROR("The topic flag should be followed by a topic.");
            return print_usage();
          }
          break;

        case 'b':
          /* change the default broker ip */
          if (optarg) {
            strcpy(broker_ip, optarg);
          } else {
            LOG_ERROR("The broker flag should be followed by an IP address.");
            return print_usage();
          }
          break;

        case 'B':
          /* change the default UDP bind address */
          if (optarg) {
            strcpy(udp_ip, optarg);
          } else {
            LOG_ERROR("The UDP-ip flag should be followed by an IP address.");
            return print_usage();
          }
          break;

        case 'e':
          /* Break on error */
          error = 1;
          break;

        case 'p':
          /* change the default broker port */
          if (optarg) {
            broker_port = *optarg;
          } else {
            LOG_ERROR("The port flag should be followed by a port.");
            return print_usage();
          }
          break;

        case 'P':
          /* change the default UDP port */
          if (optarg) {
            udp_port = atoi(optarg);
          } else {
            LOG_ERROR("The UDP-port flag should be followed by a port.");
            return print_usage();
          }
          break;

        case 'c':
          /* Set clientid */
          if (optarg) {
            strcpy(clientid, optarg);
          } else {
            LOG_ERROR("The clientid flag should be followed by a clientid");
            return print_usage();
          }
          break;
      }
    } else {
      break;
    }
  }

  struct broker_conn *conn, *udp_conn;

  LOG_INFO("Initialising socket connection");

  init_linux_socket_connection(&conn, broker_ip, sizeof(broker_ip), broker_port);
  if (!conn) {
    LOG_ERROR("Initialising socket connection");
    return -1;
  }

  if (clientid[0]) {
    broker_set_clientid(conn, clientid, sizeof(clientid));
  }

  /* register a new connection method that allows connect packets from
     clients to be received */

  LOG_INFO("Initialising UDP connection");

  init_linux_socket_connection(&udp_conn, udp_ip, sizeof(udp_ip), udp_port);
  if (!conn) {
    LOG_ERROR("Initialising UDP connection");
    return -1;
  }

  LOG_INFO("Connecting to broker");

  struct linux_broker_socket *broker_skt = NULL;
  struct linux_broker_socket *udp_skt = NULL;
  broker_skt = (struct linux_broker_socket *)conn->context;
  udp_skt = (struct linux_broker_socket *)udp_conn->context;

  /* Set connection type to UDP */
  udp_skt->type = SOCK_DGRAM;

  ret = broker_connect(conn);
  if (ret) {
    LOG_ERROR("Connecting to broker");
    free_connection(conn);
    return ret;
  } else {
    LOG_INFO("Connected to broker:\nip: %s port: %d", broker_skt->ip,
        broker_skt->port);
  }

  LOG_INFO("Binding to UDP socket");
  ret = linux_socket_bind(udp_conn);
  if (ret) {
    LOG_ERROR("Binding to socket");
    free_connection(udp_conn);
    return ret;
  } else {
    LOG_INFO("Bound to address: %s on port: %d", udp_skt->ip, udp_skt->port);
  }

  /* Just need to relay packets and not do much else... */
  //LOG_INFO("Subscribing to the following topics:");
  //LOG_INFO("Topic: %s", topic);

  /* Find length of topic and subscribe */
  //const char *end = strchr(topic, '\0');
  //if (!end || (ret = broker_subscribe(conn, topic, end - topic))) {

  //  LOG_ERROR("Subscribing to topic.");
  //  return UMQTT_ERROR;
  //}

  /* Start listening for packets */
  struct mqtt_packet *pkt = NULL;
  int nfds = (udp_skt->sockfd > broker_skt->sockfd
      ? udp_skt->sockfd : broker_skt->sockfd) + 1;
  fd_set fds;
  struct timeval sel_tout = {0};
  int sel_ret;

  while (1) {

  if (init_packet(&pkt)) {
    LOG_ERROR("Initialising packet");
    ret = UMQTT_ERROR;
    goto free;
  }

    sel_ret = 0;
    FD_ZERO(&fds);
    FD_SET(broker_skt->sockfd, &fds);
    FD_SET(udp_skt->sockfd, &fds);

    while (1) {
      sel_tout.tv_sec = SELECT_TIMEOUT;

      sel_ret = select(nfds, &fds, NULL, NULL, &sel_tout);
      LOG_DEBUG("select return: %d", sel_ret);

      if (sel_ret == -1) {
        LOG_ERROR("Select failed");
      } else if (sel_ret) {
        LOG_DEBUG("Select sucessful");
        break;

      } else if (!sel_ret) {
        LOG_DEBUG("Select timeout");
      }
    };

    if (sel_ret) {
      /* packet border */
      LOG_INFO("------------------------------------------------------------");
      if (counts) {
        LOG_INFO("Packet counts: Successful: %d Failed: %d, Publish: %d",
            conn->success_count, conn->fail_count, conn->publish_count);
      }

      if (FD_ISSET(broker_skt->sockfd, &fds)) {
        LOG_DEBUG("Broker data available");

      } else if (FD_ISSET(udp_skt->sockfd, &fds)) {
        LOG_DEBUG("UDP data available");
        ret = read_udp_socket_packet(udp_conn, pkt);

      } else {
        /* shouldn't really be here */
        continue;
      }

      if (!ret) {
        if (detail) {
          print_packet_detailed_info(pkt);
        } else {
          print_publish_packet_info(pkt);
        }
        if (hex) {
          print_packet_raw_debug(pkt);
        }
      } else if (error) {
        printf("#ERROR\n");
        break;
      }
    }
  }

free:
  broker_disconnect(conn);
  broker_disconnect(udp_conn);
  free_connection(conn);
  free_connection(udp_conn);
  free_packet(pkt);
  return ret;
}
