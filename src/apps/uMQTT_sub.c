/******************************************************************************
 * File: uMQTT_sub.c
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
#include <string.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_helper.h"
#include "uMQTT_linux_client.h"
#include "../inc/log.h"

#define MAX_TOPIC_LEN         1024
#define MAX_MSG_LEN           1024

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_sub is an application that connects to an MQTT broker and\n"
      "subscribes to user defined topics.\n"
      "\n"
      "Usage: uMQTT_sub [options]\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      "\n"
      "Subscribe options:\n"
      " -t [--topic] <topic>     : Change the default topic. Default: uMQTT_PUB\n"
      "\n"
      "Broker options:\n"
      " -b [--broker] <broker-IP>: Change the default broker IP - only IP\n"
      "                            addresses are currently supported.\n"
      "                            Default ip: localhost\n"
      " -p [--port] <port>       : Change the default port. Default: 1883\n"
      "\n"
      "Output options:\n"
      " -d [--detail]            : Output detailed packet information\n"
      "                            Default: output publish packet summary\n"
      " -x [--hex]               : Output hex packet\n"
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

int main(int argc, char **argv) {

  int ret;
  int c, option_index = 0, detail = 0;
  char topic[MAX_TOPIC_LEN] = UMQTT_DEFAULT_TOPIC;
  char broker_ip[16] = MQTT_BROKER_IP;
  int broker_port = MQTT_BROKER_PORT;
  char clientid[UMQTT_CLIENTID_MAX_LEN] = "\0";

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"verbose", required_argument,      0, 'v'},
    {"detail", no_argument,             0, 'd'},
    {"topic", required_argument,        0, 't'},
    {"broker", required_argument,       0, 'b'},
    {"port", required_argument,         0, 'p'},
    {"clientid", required_argument,     0, 'c'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hdv:t:b:p:c:", long_options, &option_index)) != -1) {

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

        case 'p':
          /* change the default port */
          if (optarg) {
            broker_port = *optarg;
          } else {
            LOG_ERROR("The port flag should be followed by a port.");
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

  struct broker_conn *conn;

  LOG_INFO("Initialising socket connection");

  init_linux_socket_connection(&conn, broker_ip, sizeof(broker_ip), broker_port);
  if (!conn) {
    LOG_ERROR("Initialising socket connection");
    return -1;
  }

  if (clientid[0]) {
    broker_set_clientid(conn, clientid, sizeof(clientid));
  }

  LOG_INFO("Connecting to broker");

  struct linux_broker_socket *skt = '\0';
  if ((ret = broker_connect(conn))) {
    LOG_ERROR("Initialising socket connection");
    free_connection(conn);
    return ret;
  } else {
    skt = (struct linux_broker_socket *)conn->context;
    LOG_INFO("Connected to broker:\nip: %s port: %d", skt->ip, skt->port);
  }

  LOG_INFO("Subscribing to the following topics:");
  LOG_INFO("Topic: %s", topic);

  /* Find actual length of topic and subscribe */
  const char *end = strchr(topic, '\0');
  if (!end || (ret = broker_subscribe(conn, topic, end - topic))) {

    LOG_ERROR("Subscribing to topic.");
    ret = UMQTT_ERROR;
    goto free;
  }

  /* Start listening for packets */
  struct mqtt_packet *pkt = NULL;
  if (init_packet(&pkt)) {
    LOG_ERROR("Initialising packet");
    ret = UMQTT_ERROR;
    goto free;
  }

  while (1) {
    ret = conn->receive_method(conn, pkt);

    if (!ret) {
      if (detail) {
        print_packet_detailed(pkt);
      } else {
        print_publish_packet(pkt);
      }
    }
  }

free:
  broker_disconnect(conn);
  free_connection(conn);
  free_packet(pkt);
  return ret;
}
