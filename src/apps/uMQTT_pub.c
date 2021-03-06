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
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_linux_client.h"
#include "../inc/log.h"

#define MAX_TOPIC_LEN         1024
#define MAX_MSG_LEN           1024

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_pub is an application that connects to an MQTT broker and sends "
      "a user defined\n"
      "publish pocket before disconnecting\n"
      ""
      "Usage: uMQTT_pub [options] -m <PUBLISH message>\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      " -R [--repeat] <count>    : Send publish packet count times\n"
      "\n"
      "Publish options:\n"
      " -t [--topic] <topic>     : Change the default topic. Default: uMQTT_PUB\n"
      " -m [--message] <message> : Set the message for the publish packet\n"
      " -f [--file] <filename>   : Use contents of file for the publish message\n"
      " -r [--retain]            : Set the retain flag\n"
      "\n"
      "Broker options:\n"
      " -b [--broker] <broker-IP>: Change the default broker IP\n"
      "                             - only IP addresses are\n"
      "                            currently supported. Default: localhost\n"
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
      "                                 DEBUG_FN\n"
      " -R [--repeat] <count>    : Send publish packet count times\n"
      "\n");

  return 0;
}

/**
 * \brief Function to read the contents of a file into buffer.
 * \param filename The file to read.
 * \param buf The buffer for the file.
 * \param len The len of the buffer.
 */
umqtt_ret file_read_contents(const char *filename, uint8_t *buf, size_t *len) {

  umqtt_ret ret = UMQTT_SUCCESS;

  FILE *f = fopen(filename, "rb");
  fseek(f, 0, SEEK_END);
  size_t fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize > *len) {
    LOG_ERROR("The file (%zu bytes) is larger than buffer (%zu bytes)",
      fsize, *len);
    fclose(f);
    ret = UMQTT_PAYLOAD_ERROR;
  } else {
    *len = fread(buf, 1, fsize, f);
    fclose(f);
  }

  return ret;
}

int main(int argc, char **argv) {

  int ret;
  int c, option_index = 0;
  char topic[MAX_TOPIC_LEN] = UMQTT_DEFAULT_TOPIC;
  char broker_ip[16] = MQTT_BROKER_IP;
  char msg[1024] = "\0";
  char filename[1024] = "\0";
  int broker_port = MQTT_BROKER_PORT;
  char clientid[UMQTT_CLIENTID_MAX_LEN] = "\0";
  uint8_t retain = 0;
  uint32_t repeat = 1;

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"retain",   no_argument,           0, 'r'},
    {"verbose", required_argument,      0, 'v'},
    {"topic", required_argument,        0, 't'},
    {"message", required_argument,      0, 'm'},
    {"file", required_argument,         0, 'f'},
    {"broker", required_argument,       0, 'b'},
    {"port", required_argument,         0, 'p'},
    {"clientid", required_argument,     0, 'c'},
    {"repeat", required_argument,       0, 'R'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hv:rt:m:b:p:c:f:R:", long_options,
            &option_index)) != -1) {

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
            LOG_ERROR("The topic flag should be followed by a topic");
            return print_usage();
          }
          break;

        case 'm':
          /* set the message */
          if (optarg) {
            strcpy(msg, optarg);
          } else {
            LOG_ERROR("The message flag should be followed by a message");
            return print_usage();
          }
          break;

        case 'f':
          /* set the message to the file */
          if (optarg) {
            strcpy(filename, optarg);
          } else {
            LOG_ERROR("The file flag should be followed by a file");
            return print_usage();
          }
          break;

        case 'b':
          /* change the default broker ip */
          if (optarg) {
            strcpy(broker_ip, optarg);
          } else {
            LOG_ERROR("The broker flag should be followed by an IP address");
            return print_usage();
          }
          break;

        case 'p':
          /* change the default port */
          if (optarg) {
            broker_port = *optarg;
          } else {
            LOG_ERROR("The port flag should be followed by a port");
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

        case 'R':
          /* set repeat count */
          if (optarg) {
            repeat = atoi(optarg);
          }
          break;

      }
    } else {
      /* Final arguement */
      break;
    }
  }

  if (msg[0] && filename[0]) {
      LOG_ERROR("The PUBLISH message is missing");
      return -1;
  }

  struct broker_conn *conn;

  LOG_INFO("Initialisig socket connection");

  init_linux_socket_connection(&conn, broker_ip, sizeof(broker_ip), broker_port);
  if (!conn) {
    LOG_INFO("XError: Initialising socket connection");
    return -1;
  }

  if (clientid[0]) {
    broker_set_clientid(conn, clientid, sizeof(clientid));
  }

  LOG_INFO("Connecting to broker");

  struct linux_broker_socket *skt = '\0';
  if ((ret = broker_connect(conn))) {
    LOG_ERROR("Connecting to broker");
    free_connection(conn);
    return ret;
  } else {
    skt = (struct linux_broker_socket *)conn->context;
    LOG_INFO("Connected to broker:\nip: %s port: %d", skt->ip, skt->port);
  }

  LOG_INFO("Constructing MQTT PUBLISH packet with:");
  LOG_INFO("Topic: %s", topic);
  LOG_INFO("Message: %s", msg);

  struct mqtt_packet *pkt = construct_packet_headers(PUBLISH);

  if (!pkt || (ret = set_publish_variable_header(pkt, topic, strlen(topic)))) {
    LOG_ERROR("Setting up packet");
    ret = UMQTT_ERROR;
    goto free;
  }

  if ((ret = set_publish_fixed_flags(pkt, retain, 0, 0))) {
    LOG_ERROR("Setting publish flags");
    ret = UMQTT_ERROR;
    goto free;
  }

  if (filename[0]) {

    /* create new buffer - should be dynamic */
    size_t len = MAX_REMAIN_LEN_PRODUCT;
    uint8_t *buf = calloc(sizeof(uint8_t), len);
    if (!buf) {
      LOG_ERROR("File buffer allocation failed");
      ret = UMQTT_ERROR;
      goto free;
    }

    if ((ret = file_read_contents(filename, buf, &len))) {
      LOG_ERROR("Reading file failed");
      ret = UMQTT_ERROR;
      free (buf);
      goto free;
    }

    if ((ret = init_packet_payload(pkt, PUBLISH, buf, len))) {
      LOG_ERROR("Attaching payload");
      ret = UMQTT_ERROR;
      free (buf);
      goto free;
    }

    free (buf);

  } else {

    if ((ret = init_packet_payload(pkt, PUBLISH, (uint8_t *)msg, strlen(msg)))) {
      LOG_ERROR("Attaching payload");
      ret = UMQTT_ERROR;
      goto free;
    }
  }

  finalise_packet(pkt);

  LOG_INFO("Sending packet to broker");

  /* Send packets */
  do {
    ret = broker_send_packet(conn, pkt);
    if (ret) {
      LOG_ERROR("Sending packet failed");
    } else {
      LOG_INFO("Successfully sent packet");
    }
  } while (--repeat);

free:
  LOG_INFO("Disconnecting from broker");
  broker_disconnect(conn);
  free_connection(conn);
  free_packet(pkt);
  return ret;
}
