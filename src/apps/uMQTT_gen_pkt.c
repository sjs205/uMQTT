/******************************************************************************
 * File: uMQTT_pkt_gen.c
 * Description: MicroMQTT (uMQTT) packet generator.
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
#include "uMQTT_helper.h"
#include "../inc/log.h"

#define MAX_TOPIC_LEN         1024
#define MAX_MSG_LEN           1024

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_pkt_gen is a tool for generating MQTT packets based on \n"
      "   command-line arguments.\n"
      "\n"
      "Usage: uMQTT_pkt_gen <Packet Type> [options] -m <PUBLISH message>\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      "\n"
      "Packet options:\n"
      " <Packet Type>            : The Packet Type arguement must follow the\n"
      "                            command, and can be on of the following:\n"
      "                                CONNECT, CONNACK, PUBLISH, PUBACK,\n"
      "                                PUBREC, PUBREL, PUBCOMP, SUBSCRIBE,\n"
      "                                SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ,\n"
      "                                PINGRESP, DISCONNECT,\n"
      "CONNECT packet options:\n"
      " -c [--clientid] <id>     : Set the clientId. Default: none\n"
      " -p [--proto] <level>     : Protocol level: options are 1-4. Default:4 \n"
      " -u [--username] <uname>  : Set the retain flag\n"
      " -P [--password] <pword>  : Set the retain flag\n"
      " -s [--clean-session]     : Set the Clean Session flag\n"
      " Will options             : Using any of these arguments set the\n"
      "                             Will flag.\n"
      " -r [--retain]            : Set the Will retain flag\n"
      " -q [--qos] <QoS>         : Set the Will QoS\n"
      " -t [--topic] <topic>     : Set the Will topic. Default: none\n"
      " -m [--message] <message> : Set the Will message Default: none\n"
      " -k [--keepalive] <secs>  : The number of seconds to keep session alive\n"
      "\n"
      "PUBLISH packet options:\n"
      " -t [--topic] <topic>     : Change the default topic.\n"
      " -m [--message] <message> : Set the message for the publish packet\n"
      " -d [--dup]               : Set the duplicate flag\n"
      " -q [--qos] <QoS>         : Set the QoS of the PUBLISH message\n"
      " -r [--retain]            : Set the retain flag\n"
      " -p [--pkt-id] <pkt-id>   : Set the packet identifier - has no effect\n"
      "                             unless QoS > 0\n"
      "\n"
      "SUBSCRIBE/UNSUBSCRIBE packet options:\n"
      " -t [--topic] <topic>     : Add new topic to the SUBSCRIBE/UNSUBSCRIBE\n"
      "                             packet. Each instance of this flag\n"
      "                             adds a new topic.\n"
      "                             SUBSCRIBE packets: if required, each\n"
      "                             instance can be followed with a QoS flag.\n"
      " -q [--qos] <QoS>         : Set the QoS of the SUBSCRIBE topic\n"

      " -p [--pkt-id] <pkt-id>   : Set the packet identifier.\n"
      "\n"
      "Generic packet options (All other packet types):\n"
      " -r [--return]            : SUBACK or CONNACK only - Sets the return\n"
      "                             code, can be used multiple times\n"
      " -s [--session]           : CONNACK only - Sets the session present\n"
      "                             flag\n"
      " -p [--pkt-id] <pkt-id>   : Set the packet identifier\n"
      "\n"
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

/*
 * \brief function to parse CONNECT packet arguments
 * \param argc Number of arguments.
 * \param argv Arguments.
 * \param pkt Pointer to packet.
 */
umqtt_ret build_connect_pkt_getopts(int argc, char **argv,
    struct mqtt_packet *pkt) {

  int ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  char username[1024] = "\0";
  char password[1024] = "\0";
  char will_topic[MAX_TOPIC_LEN] = "\0";
  char will_msg[1024] = "\0";
  char clientid[MQTT_CLIENTID_MAX_LEN] = "\0";

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help", no_argument,             0, 'h'},
    {"verbose", required_argument,      0, 'v'},
    {"clientid", required_argument,     0, 'c'},
    {"proto", required_argument,        0, 'p'},
    {"username", required_argument,     0, 'u'},
    {"password", required_argument,     0, 'P'},
    {"clean-session", no_argument,      0, 's'},
    {"retain", no_argument,             0, 'r'},
    {"qos", required_argument,          0, 'q'},
    {"topic", required_argument,        0, 't'},
    {"message", required_argument,      0, 'm'},
    {"keepalive", required_argument,    0, 'k'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hv:u:P:sc:p:rq:t:m:k:", long_options,
            &option_index)) != -1) {

      switch (c) {
        case 'h':
            print_usage();
            ret = UMQTT_ERROR;
            goto end;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 'c':
          /* Set clientid */
          if (optarg) {
            strcpy(clientid, optarg);
          } else {
            log_std(LOG_ERROR,
                "The clientid flag should be followed by a clientid");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'p':
          /* set protocol level - this only changes the value */
          if (optarg) {
            pkt->variable->connect.proto_level = (0x0f & (uint8_t)atoi(optarg));
          }
          break;

        case 'u':
          /* Set username */
          if (optarg) {
            strcpy(username, optarg);
            /* set username flag */
            pkt->variable->connect.flags.user_flag = 1;
          } else {
            log_std(LOG_ERROR,
                "The username flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'P':
          /* Set password */
          if (optarg) {
            strcpy(password, optarg);
            /* set password flag */
            pkt->variable->connect.flags.pass_flag = 1;
          } else {
            log_std(LOG_ERROR,
                "The password flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 's':
          /* set clean session flag */
          pkt->variable->connect.flags.clean_session_flag = 1;
          break;

        case 't':
          /* Set will topic */
          if (optarg) {
            strcpy(will_topic, optarg);
            /* set will flag */
            pkt->variable->connect.flags.will_flag = 1;
          } else {
            log_std(LOG_ERROR,
                "The will topic flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'm':
          /* set the will message */
          if (optarg) {
            strcpy(will_msg, optarg);
            /* set will flag */
            pkt->variable->connect.flags.will_flag = 1;
          } else {
            log_std(LOG_ERROR,
                "The will message flag should be followed by a message");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'r':
          /* set retain flag */
          pkt->variable->connect.flags.will_retain_flag = 1;
          /* set will flag */
          pkt->variable->connect.flags.will_flag = 1;
          break;

        case 'q':
          /* set the will QoS */
          if (optarg) {
            pkt->variable->connect.flags.will_qos = (0x03 & (uint8_t)atoi(optarg));
            /* set will flag */
            pkt->variable->connect.flags.will_flag = 1;
          } else {
            log_std(LOG_ERROR,
                "The will Qos flag should be followed by a QoS (0-3)");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'k':
          /* Set keep alive */
          if (optarg) {
            pkt->variable->connect.keep_alive = (uint16_t)atoi(optarg);
          } else {
            log_std(LOG_ERROR,
                "The will topic flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
      }
    } else {
      /* Final arguement */
      break;
    }
  }

  if (clientid[0] ==  '\0') {
    log_std(LOG_INFO,
        "Automatically generating a clientID since none was specified");
  }

  if (pkt->variable->connect.flags.will_flag == 1) {
    if (will_topic[0] == '\0') {
      log_std(LOG_INFO,
        "A will topic must be specified when the will flag is set");
      ret = UMQTT_ERROR;
      goto end;
    }

    if (will_msg[0] == '\0') {
      log_std(LOG_INFO,
          "A will message must be specified when the will flag is set");
      ret = UMQTT_ERROR;
      goto end;
    }
  }

  ret = init_packet_payload(pkt, pkt->fixed->generic.type, NULL, 0);
  if (ret) {
    /* error */
    goto end;
  }

  /* CONNECT payload non optional, overide defaults */
  ret = set_connect_payload(pkt, clientid, username, password, will_topic,
      will_msg);

end:
  return ret;
}

/*
 * \brief function to parse PUBLISH packet arguments
 * \param argc Number of arguments.
 * \param argv Arguments.
 * \param pkt Pointer to packet.
 */
umqtt_ret build_publish_pkt_getopts(int argc, char **argv,
    struct mqtt_packet *pkt) {

  int ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  uint16_t pkt_id = 1;
  char topic[MAX_TOPIC_LEN] = "\0";
  char msg[1024] = "\0";


  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help", no_argument,               0, 'h'},
    {"verbose", required_argument,      0, 'v'},
    {"topic", required_argument,        0, 't'},
    {"message", required_argument,      0, 'm'},
    {"dup", no_argument,                0, 'd'},
    {"qos", required_argument,          0, 'q'},
    {"retain", no_argument,             0, 'r'},
    {"pkt-id", required_argument,       0, 'p'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hv:u:t:m:dq:rp:", long_options,
            &option_index)) != -1) {
      switch (c) {
        case 'h':
          print_usage();
          ret = UMQTT_ERROR;
          goto end;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 't':
          /* Set topic */
          if (optarg) {
            strcpy(topic, optarg);
          } else {
            log_std(LOG_ERROR,
                "The topic flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'm':
          /* set the message */
          if (optarg) {
            strcpy(msg, optarg);
          } else {
            log_std(LOG_ERROR,
                "The message flag should be followed by a message");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'd':
          /* set dup flag */
          pkt->fixed->publish.dup = 1;
          break;

        case 'r':
          /* set retain flag */
          pkt->fixed->publish.retain = 1;
          break;

        case 'q':
          /* set the QoS */
          if (optarg) {
            pkt->fixed->publish.qos = (0x03 & (uint8_t)atoi(optarg));
          } else {
            log_std(LOG_ERROR,
                "The QoS flag should be followed by a QoS (0-3)");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'p':
          /* Set Packet Identifier */
          if (optarg) {
            pkt_id = (uint16_t)atoi(optarg);
            generate_packet_id(pkt_id);
          } else {
            log_std(LOG_ERROR,
                "The packet identifier flag should be followed by a packet id");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;
      }
    } else {
      /* Final arguement */
      break;
    }
  }

  if (topic[0] == '\0') {
    log_std(LOG_INFO,
        "Automatically generating a topic since none was specified");
  }

  /* set publish variable header and message payload */
  ret = set_publish_variable_header(pkt, topic, strlen(topic));
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign PUBLISH packet variable header");
    goto end;
  }

  ret = init_packet_payload(pkt, PUBLISH, (uint8_t *)msg, strlen(msg));
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign PUBLISH packet payload");
    goto end;
  }

end:
  return ret;
}

/*
 * \brief function to parse SUBSCRIBE and UNSUBSCRIBE packet arguments
 * \param argc Number of arguments.
 * \param argv Arguments.
 * \param pkt Pointer to packet.
 */
umqtt_ret build_un_subscribe_pkt_getopts(int argc, char **argv,
    struct mqtt_packet *pkt) {

  int ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  uint16_t pkt_id = 1;
  uint8_t payload[MAX_MSG_LEN] = "\0";
  size_t pay_len = 0;

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help", no_argument,               0, 'h'},
    {"verbose", required_argument,      0, 'v'},
    {"topic", required_argument,        0, 't'},
    {"qos", required_argument,          0, 'q'},
    {"pkt-id", required_argument,       0, 'p'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hv:t:q:p:", long_options,
            &option_index)) != -1) {
      switch (c) {
        case 'h':
          print_usage();
          ret = UMQTT_ERROR;
          goto end;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 't':
          /* Set topic */
          if (optarg) {
            pay_len += encode_utf8_string((struct utf8_enc_str *)&payload[pay_len],
                optarg, strlen(optarg));

            if (pkt->fixed->generic.type == SUBSCRIBE) {
              /* QoS flag */
               pay_len += sizeof(uint8_t);
            }

          } else {
            log_std(LOG_ERROR,
                "The topic flag should be followed by a topic");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'q':
          /* set the QoS */
          if (pkt->fixed->generic.type == SUBSCRIBE) {
            if (optarg) {
              payload[pay_len - 1] = (0x03 & (uint8_t)atoi(optarg));
            } else {
              log_std(LOG_ERROR,
                  "The QoS flag should be followed by a QoS (0-3)");
              print_usage();
              ret = UMQTT_ERROR;
              goto end;
            }
          } else {
            /* UNSUBSCRIBE */
            log_std(LOG_ERROR,
                "The QoS flag has no effect with the UNSUBSCRIBE packet type");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;

        case 'p':
          /* Set Packet Identifier */
          if (optarg) {
            pkt_id = (uint16_t)atoi(optarg);
            generate_packet_id(pkt_id);

          } else {
            log_std(LOG_ERROR,
                "The packet identifier flag should be followed by a packet id");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;
      }
    } else {
      /* Final arguement */
      break;
    }
  }

/* set subscribe variable header and message payload */
  ret = init_packet_variable_header(pkt, pkt->fixed->generic.type);
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign packet variable header");
    goto end;
  }

  ret = init_packet_payload(pkt, SUBSCRIBE, (uint8_t *)&payload, pay_len);
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign SUBSCRIBE packet payload");
    goto end;
  }

end:
  return ret;
}

/*
 * \brief function to parse generic packet arguments, includes all packets
 *          except for: PUBLISH, SUBSCRIBE, UNSUBSCRIBE, CONNECT
 * \param argc Number of arguments.
 * \param argv Arguments.
 * \param pkt Pointer to packet.
 */
umqtt_ret build_generic_pkt_getopts(int argc, char **argv,
    struct mqtt_packet *pkt) {

  int ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  uint16_t pkt_id = 1;
  uint8_t session_flag = 0;
  uint8_t payload[MAX_MSG_LEN] = "\0";
  uint8_t pkt_ret = 0;
  size_t pay_len = 0;

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help", no_argument,               0, 'h'},
    {"session", no_argument,            0, 's'},
    {"verbose", required_argument,      0, 'v'},
    {"return", required_argument,       0, 'r'},
    {"pkt-id", required_argument,       0, 'p'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "hsv:r:p:", long_options,
            &option_index)) != -1) {
      switch (c) {
        case 'h':
          print_usage();
          ret = UMQTT_ERROR;
          goto end;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 'r':
          if (pkt->fixed->generic.type == SUBACK ||
              pkt->fixed->generic.type == CONNACK) {
            /* set the return code */
            if (optarg) {
              pkt_ret = (0x83 & (uint8_t)atoi(optarg));
            } else {
              log_std(LOG_ERROR,
                  "The return flag should be followed by a return code");
              print_usage();
              ret = UMQTT_ERROR;
              goto end;
            }
          } else {
              log_std(LOG_ERROR, "The return flag can only be used"
                  " with SUBACK or CONNACK packets");
          }
          break;

        case 's':
          if (pkt->fixed->generic.type == CONNACK) {
            /* set the session present flag */
            session_flag = 0x01;
          }
          break;

        case 'p':
          /* Set Packet Identifier Generator */
          if (optarg) {
            pkt_id = (uint16_t)atoi(optarg);

          } else {
            log_std(LOG_ERROR,
                "The packet identifier flag should be followed by a packet id");
            print_usage();
            ret = UMQTT_ERROR;
            goto end;
          }
          break;
      }
    } else {
      /* Final arguement */
      break;
    }
  }

  ret = init_packet_variable_header(pkt, pkt->fixed->generic.type);
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign packet variable header");
    goto end;
  }

  if (pkt_id) {
    set_packet_pkt_id(pkt, pkt_id);
  }

  /* set packet return */
  if (pkt->fixed->generic.type == SUBACK) {
    payload[pay_len++] = pkt_ret;
  } else if (pkt->fixed->generic.type == CONNACK) {
    pkt->variable->connack.connect_ret = pkt_ret;

    /* set session present flag */
    if (session_flag) {
      pkt->variable->connack.session_present_flag = 0x01;
    }
  }

  ret = init_packet_payload(pkt, pkt->fixed->generic.type, (uint8_t *)&payload,
      pay_len);
  if (ret) {
    log_std(LOG_ERROR,
        "Failed to assign packet payload");
    goto end;
  }

end:
  return ret;
}

int main(int argc, char **argv) {

  umqtt_ret ret = UMQTT_SUCCESS;

  /* initialise packet */
  struct mqtt_packet *pkt = NULL;

  if (argv[1]) {
     pkt = construct_packet_headers(get_string_type(argv[1]));
  }

  if (!pkt) {
    log_std(LOG_ERROR, "Constructing headers: Packet creation failed");
    ret = UMQTT_ERROR;
    goto free;
  } else {
    switch (pkt->fixed->generic.type) {
      case CONNECT:
        ret = build_connect_pkt_getopts(argc, argv, pkt);
        break;

      case PUBLISH:
        ret = build_publish_pkt_getopts(argc, argv, pkt);
        break;

      case SUBSCRIBE:
      case UNSUBSCRIBE:
        ret = build_un_subscribe_pkt_getopts(argc, argv, pkt);
        break;

      default:
        ret = build_generic_pkt_getopts(argc, argv, pkt);
        break;
    }
  }

  if (ret) {
    log_std(LOG_ERROR, "Building packet: Packet creation failed");
    goto free;
  }

  /* Cleanup packet */
  finalise_packet(pkt);

  /* print */
  print_packet_detailed_info(pkt);
  print_packet_hex_debug(pkt);
  print_packet_raw_debug(pkt);

free:
  if (pkt) {
    free_packet(pkt);
  }
  return ret;
}
