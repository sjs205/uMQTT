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

/* ip of test.mosquitto.org */
#define MQTT_BROKER_IP        "85.119.83.194\0"
#define MQTT_BROKER_PORT      1883

#define MAX_TOPIC_LEN 1024
#define MAX_MSG_LEN 1024

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_pub is an application that connects to an MQTT broker and sends a user defined\n"
      "publish pocket before disconnecting\n"
      "\n"
      "Usage: uMQTT_pub [options] <PUBLISH message>\n\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      " -v [--verbose]           : Verbose logging\n"
      "\n"
      "Publish options:\n"
      " -t [--topic] <topic>     : Change the default topic. Default: uMQTT_PUB\n"
      "\n"
      "Broker options:\n"
      " -H [--host] <host-IP>    : Change the default host IP - only IP addresses are\n"
      "                            currently supported. Default: test.mosquitto.org\n"
      " -p [--port] <port>       : Change the default port. Default: 1883\n"
      "\n");

  return 0;
}

int main(int argc, char **argv) {

  int ret;
  int c, option_index = 0;
  char topic[MAX_TOPIC_LEN] = UMQTT_DEFAULT_TOPIC;
  char host_ip[16] = MQTT_BROKER_IP;
  char msg[1024];
  int host_port = MQTT_BROKER_PORT;
  int verbose = 0;

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"verbose", no_argument,            0, 'v'},
    {"topic", required_argument,        0, 't'},
    {"host", required_argument,         0, 'H'},
    {"port", required_argument,         0, 'p'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hvt:H:p:", long_options, &option_index)) != -1) {

      switch (c) {
        case 'h':
          return print_usage();

        case 'v':
          /* set verbose */
          verbose = 1;
          break;

        case 't':
          /* Set topic */
          if (optarg) {
            strcpy(topic, optarg);
          } else {
            printf("Error: The topic flag should be followed by a topic.\n");
            return print_usage();
          }
          break;

        case 'H':
          /* change the default host ip */
          if (optarg) {
            strcpy(host_ip, optarg);
          } else {
            printf("Error: The host flag should be followed by an IP address.\n");
            return print_usage();
          }
          break;

        case 'p':
          /* change the default port */
          if (optarg) {
            host_port = *optarg;
          } else {
            printf("Error: The port flag should be followed by a port.\n");
            return print_usage();
          }
          break;
      }

    } else {
      /* Final arguement should be the publish message */
      if (argv[argc - 1] != NULL) {
        strcpy(msg, argv[argc - 1]);
      }
      break;
    }

  }

  if (argv[argc - 1] == NULL) {
      printf("Error: The PUBLISH message is missing.\n");
      return -1;
  }

  struct broker_conn *conn;

  if (verbose) {
    printf("Initialisig socket connection\n");
  }
  init_linux_socket_connection(&conn, host_ip, sizeof(host_ip), host_port);
  if (!conn) {
    printf("XError: Initialising socket connection\n");
    return -1;
  }

  if (verbose) {
    printf("Connecting to broker\n");
  }

  struct linux_broker_socket *skt = '\0';
  if ((ret = broker_connect(conn))) {
    printf("Error: Initialising socket connection\n");
    free_connection(conn);
    return ret;
  } else {
    skt = (struct linux_broker_socket *)conn->context;
    if (verbose) {
      printf("Connected to broker:\nip: %s port: %d\n", skt->ip, skt->port);
    }
  }

  if (verbose) {
    printf("Constructiing MQTT PUBLISH packet with:\n");
    printf("Topic; %s\n", topic);
    printf("Message: %s\n", msg);
  }

  struct mqtt_packet *pkt = construct_packet_headers(PUBLISH);

  if (!pkt || (ret = set_publish_variable_header(pkt, topic, strlen(topic)))) {
    printf("Error: Setting up packet.\n");
    ret = UMQTT_ERROR;
    goto free;
  }

  if ((ret = init_packet_payload(pkt, PUBLISH, (uint8_t *)msg, strlen(msg)))) {
    printf("Error: Attaching payload.\n");
    ret = UMQTT_ERROR;
    goto free;
  }

  finalise_packet(pkt);

  if (verbose) {
    printf("Sending packet to broker\n");
  }

  if ((ret = broker_send_packet(conn, &pkt->raw))) {
    printf("Error: Sending packet failed.\n");

  } else if (verbose) {

    printf("Successfully sent packet.\n");

    printf("Disconnecting from broker.\n");
  }

free:
  broker_disconnect(conn);
  free_connection(conn);
  free_packet(pkt);
  return ret;
}
