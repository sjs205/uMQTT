/******************************************************************************
 * File: uMQTT_pub.c
 * Description: MicroMQTT (uMQTT) publish application using linux based sockets
 *              to connect to the broker.
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
#include <string.h>
#include <string.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_linux_client.h"
#include "../inc/log.h"

/* ip of test.mosquitto.org */
#define MQTT_BROKER_IP        "85.119.83.194\0"
#define MQTT_BROKER_PORT      1883

#define MAX_TOPIC_LEN         1024
#define MAX_MSG_LEN           1024

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_pub is an application that connects to an MQTT broker and sends a user defined\n"
      "publish pocket before disconnecting\n"
      ""
      "Usage: uMQTT_pub [options] -m <PUBLISH message>\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      "\n"
      "Publish options:\n"
      " -t [--topic] <topic>     : Change the default topic. Default: uMQTT_PUB\n"
      " -m [--message] <message> : Set the message for the publish packet\n"
      " -r [--retain]            : Set the retain flag\n"
      "\n"
      "Broker options:\n"
      " -b [--broker] <broker-IP>: Change the default broker IP - only IP addresses are\n"
      "                            currently supported. Default: test.mosquitto.org\n"
      " -p [--port] <port>       : Change the default port. Default: 1883\n"
      " -c [--clientid] <id>     : Change the default clientid\n"
      "\n"
      "Debug options:\n"
      " -v [--verbose] <LEVEL>   : set verbose level to LEVEL\n"
      "                               Levels are:\n"
      "                                 SILENT\n"
      "                                 ERROR\n"
      "                                 WARN\n"
      "                                 INFO (default)\n"
      "                                 DEBUG\n"
      "                                 DEBUG_THREAD\n"
      "\n");

  return 0;
}

int main(int argc, char **argv) {

  int ret;
  int c, option_index = 0;
  char topic[MAX_TOPIC_LEN] = UMQTT_DEFAULT_TOPIC;
  char broker_ip[16] = MQTT_BROKER_IP;
  char msg[1024] = "\0";
  int broker_port = MQTT_BROKER_PORT;
  char clientid[UMQTT_CLIENTID_MAX_LEN] = "\0";
  uint8_t retain = 0;

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"retain",   no_argument,           0, 'r'},
    {"verbose", required_argument,      0, 'v'},
    {"topic", required_argument,        0, 't'},
    {"message", required_argument,      0, 'm'},
    {"broker", required_argument,       0, 'b'},
    {"port", required_argument,         0, 'p'},
    {"clientid", required_argument,     0, 'c'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hv:rt:m:b:p:c:", long_options, &option_index)) != -1) {

      switch (c) {
        case 'h':
          return print_usage();

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 'r':
          /* set retain flag */
          retain = 1;
          break;

        case 't':
          /* Set topic */
          if (optarg) {
            strcpy(topic, optarg);
          } else {
            log_stderr(LOG_ERROR, "The topic flag should be followed by a topic");
            return print_usage();
          }
          break;

        case 'm':
          /* set the message */
          if (optarg) {
            strcpy(msg, optarg);
          } else {
            log_stderr(LOG_ERROR, "The port flag should be followed by a port");
            return print_usage();
          }
          break;

        case 'b':
          /* change the default broker ip */
          if (optarg) {
            strcpy(broker_ip, optarg);
          } else {
            log_stderr(LOG_ERROR, "The broker flag should be followed by an IP address");
            return print_usage();
          }
          break;

        case 'p':
          /* change the default port */
          if (optarg) {
            broker_port = *optarg;
          } else {
            log_stderr(LOG_ERROR, "The port flag should be followed by a port");
            return print_usage();
          }
          break;

        case 'c':
          /* Set clientid */
          if (optarg) {
            strcpy(clientid, optarg);
          } else {
            log_stderr(LOG_ERROR,
                "The clientid flag should be followed by a clientid");
            return print_usage();
          }
          break;

      }
    } else {
      /* Final arguement */
      break;
    }
  }

  if (msg[0] == '\0') {
      log_stderr(LOG_ERROR, "The PUBLISH message is missing");
      return -1;
  }

  struct broker_conn *conn;

  log_stdout(LOG_INFO, "Initialisig socket connection");

  init_linux_socket_connection(&conn, broker_ip, sizeof(broker_ip), broker_port);
  if (!conn) {
    log_stdout(LOG_INFO, "XError: Initialising socket connection");
    return -1;
  }

  if (clientid[0]) {
    broker_set_clientid(conn, clientid, sizeof(clientid));
  }

  log_stdout(LOG_INFO, "Connecting to broker");

  struct linux_broker_socket *skt = '\0';
  if ((ret = broker_connect(conn))) {
    log_stderr(LOG_ERROR, "Initialising socket connection");
    free_connection(conn);
    return ret;
  } else {
    skt = (struct linux_broker_socket *)conn->context;
    log_stdout(LOG_INFO, "Connected to broker:\nip: %s port: %d", skt->ip, skt->port);
  }

  log_stdout(LOG_INFO, "Constructiing MQTT PUBLISH packet with:");
  log_stdout(LOG_INFO, "Topic; %s", topic);
  log_stdout(LOG_INFO, "Message: %s", msg);

  struct mqtt_packet *pkt = construct_packet_headers(PUBLISH);

  if (!pkt || (ret = set_publish_variable_header(pkt, topic, strlen(topic)))) {
    log_stderr(LOG_ERROR, "Setting up packet");
    ret = UMQTT_ERROR;
    goto free;
  }

  if ((ret = set_publish_fixed_flags(pkt, retain, 0, 0))) {
    log_stderr(LOG_ERROR, "Setting publish flags");
    ret = UMQTT_ERROR;
    goto free;
  }

  if ((ret = init_packet_payload(pkt, PUBLISH, (uint8_t *)msg, strlen(msg)))) {
    log_stderr(LOG_ERROR, "Attaching payload");
    ret = UMQTT_ERROR;
    goto free;
  }

  finalise_packet(pkt);

  log_stdout(LOG_INFO, "Sending packet to broker");

  if ((ret = broker_send_packet(conn, pkt))) {
    log_stderr(LOG_ERROR, "Sending packet failed");

  } else {
    log_stdout(LOG_INFO, "Successfully sent packet");
  }

free:
  log_stdout(LOG_INFO, "Disconnecting from broker");
  broker_disconnect(conn);
  free_connection(conn);
  free_packet(pkt);
  return ret;
}
