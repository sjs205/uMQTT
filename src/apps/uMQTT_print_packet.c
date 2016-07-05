/******************************************************************************
 * File: uMQTT_print_packet.c
 * Description: MicroMQTT (uMQTT) utility to print out MQTT packets in human 
 *              readable form. 
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
#include <ctype.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_helper.h"
#include "../inc/log.h"

#define MAX_PACKET_SIZE_BYTES     65536
#define UMQTT_TEST_PACKET_HEX     \
  "301c000d754d5154545f436f6e74696b6948656c6c6f20576f726c642100"

/*
 * \brief function to print help
 */
static int print_usage() {

  fprintf(stderr,
      "uMQTT_print_packet is a utility to print out MQTT packets in human readable form\n"
      ""
      "Usage: uMQTT_print_packet [options] -p <PACKET>\n"
      "General options:\n"
      " -h [--help]              : Displays this help and exits\n"
      "\n"
      "Input options:\n"
      " -p [--packet] <PACKET>   : Packet data\n"
      " -b [--binary]            : Packet is in binary format\n"
      "                            - Default format is ascii-HEX\n"
      " -f [--file] <filename>   : Decode file\n"
      "\n"
      "Output options:\n"
      " -x [--hex]               : Packet is in hexidecimal format\n"
      "                          : Default output format is a readable summary\n"
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
      " -t [--test]              : run unit tests\n"
      "\n");

  return 0;
}

umqtt_ret hex_char_to_uint(char *in, uint8_t *out) {
  if (in) {
    *in = toupper((int)*in);
    if (*in >= '0' && *in <= '9')  {
      /* hex: 0123456789 */
      *out = (*in - '0');

      return UMQTT_SUCCESS;
    } else if (*in >= 'A' && *in <= 'F') {
      /* hex: ABCDEF */
      *out = (*in - 0x37);

      return UMQTT_SUCCESS;
    }
  } 
  return UMQTT_ERROR;
}

size_t hex_str_to_uint(char *in, size_t len, uint8_t *out) {

  size_t count = 0;
  size_t nibbles = len / 2;
  uint8_t lnibble = 0;
  uint8_t hnibble = 0;

  if (len  % 2 == 0) {
    for (count = 0; count < len && (count / 2) < nibbles; count += 2) {

      if (hex_char_to_uint(&in[count], &hnibble)) {
        log_stderr(LOG_ERROR, "Hex conversion - high nibble");
      }
      if (hex_char_to_uint(&in[count + 1], &lnibble)) {
        log_stderr(LOG_ERROR, "Hex conversion - low nibble");
      }

      out[count / 2] = ((hnibble) << 4) | (lnibble & 0x0f);
    }
  } else {
    log_stderr(LOG_ERROR,
        "Hex packet input should be an even number of nibbles");
  }

  return count / 2;
}

umqtt_ret hex_str_to_uint_utest() {
  umqtt_ret ret;
  char in[sizeof(UMQTT_TEST_PACKET_HEX)] = UMQTT_TEST_PACKET_HEX;
  uint8_t out[sizeof(UMQTT_TEST_PACKET_HEX) / 2] = {0};

  log_stdout(LOG_INFO, "\nHex string to uint array conversion test");
  size_t len = hex_str_to_uint(in, sizeof(UMQTT_TEST_PACKET_HEX) - 1, out);

  if (len == ((sizeof(UMQTT_TEST_PACKET_HEX) - 1) / 2)) {
    log_stdout(LOG_INFO, "PASSED: Output array length test:");
    log_stdout(LOG_INFO, "   sizeof(in): %zu, sizeof(out): %zu, (in/out) = 2",
        sizeof(UMQTT_TEST_PACKET_HEX) - 1, len);

    ret = UMQTT_SUCCESS;
  } else {
    log_stderr(LOG_ERROR, "FAILED: Output array length test:");
    log_stderr(LOG_ERROR, "   sizeof(in): %zu, sizeof(out): %zu, (in/out) != 2",
        sizeof(UMQTT_TEST_PACKET_HEX) - 1, len);

    ret = UMQTT_ERROR;
  }

  return ret;
}

size_t hex_char_to_uint_utest() {
  umqtt_ret ret;

  char in = '0';
  uint8_t out = 0, i;

  log_stdout(LOG_INFO, "\nHex char to uint conversion test");

  for (i = 0; i <= 15; i++) {
    hex_char_to_uint(&in, &out);
    if (out == i) {
      log_stdout(LOG_INFO, "PASSED: i: %d: in: '%c' out: %X (i == out)",
          i, in, out);
      ret = UMQTT_SUCCESS;
    } else {
      log_stdout(LOG_INFO, "FAILED: i: %d: in: '%c' out: %X (i != out)",
          i, in, out);
      ret = UMQTT_ERROR;
    }

    in = (in == '9') ? in = 'A' : in + 1;
  }

  return ret;
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
    log_stderr(LOG_ERROR, "The file (%zu bytes) is larger than buffer (%zu bytes)",
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

  umqtt_ret ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  uint8_t cl_pkt = 0;
  char filename[1024] = "\0";
  uint8_t pkt_buf[MAX_PACKET_SIZE_BYTES] = {0};

  struct mqtt_packet *pkt = NULL;
  if (init_packet(&pkt)) {
    log_stdout(LOG_INFO, "ERROR: Packet creation failed");
    return UMQTT_ERROR;
  }

  static struct option long_options[] =
  {
    /* These options set a flag. */
    {"help",   no_argument,             0, 'h'},
    {"packet",   no_argument,           0, 'p'},
    {"hex", no_argument,                0, 'x'},
    {"binary", no_argument,             0, 'b'},
    {"file", required_argument,         0, 'f'},
    {"test", no_argument,               0, 't'},
    {"verbose", required_argument,      0, 'v'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "bhtxf:p:v:", long_options, &option_index)) != -1) {

      switch (c) {
        case 'h':
          ret = print_usage();
          goto cleanup;

        case 'v':
          /* set log level */
          if (optarg) {
            set_log_level_str(optarg);
          }
          break;

        case 'p':
          /* Set raw packet */
          cl_pkt = 1;
          if (optarg) {
            /* Need to find a reliable way of determining length.*/
            strcpy((char *)&pkt_buf, optarg);
          } else {
            log_stderr(LOG_ERROR, "The packet flag should be followed by a string");
            ret = print_usage();
            goto cleanup;
          }
          break;

        case 'b':
          /* Set input format to binary*/
            log_stderr(LOG_ERROR, "Binary input is not currently supported");
            ret = print_usage();
            goto cleanup;
          break;

        case 'x':
          /* Set output format to hex*/
            log_stderr(LOG_ERROR, "Hex output format is not currently supported");
            ret = print_usage();
            goto cleanup;
          break;

        case 'f':
          /* set the message to the file */
          if (optarg) {
            strcpy(filename, optarg);
          } else {
            log_stderr(LOG_ERROR, "The file flag should be followed by a file");
            ret = print_usage();
            goto cleanup;
          }
          break;

        case 't':

          log_stdout(LOG_INFO, "Running unti tests...");
          log_stdout(LOG_INFO, "Help test:");
          print_usage();

          log_stdout(LOG_INFO, "hex_char_to_uint_utest:"); 
          ret = hex_char_to_uint_utest();
          ret = hex_str_to_uint_utest();

          goto cleanup;

          break;
      }
    } else {
      /* Final arguement */
      /* we should capture from stdin if final arguement is '-' */
      break;
    }
  }

  if (!cl_pkt) {
    log_stderr(LOG_ERROR, "The packet is missing");
    ret = UMQTT_ERROR;
    goto cleanup;
  }

  /* process hex packet - need to add binary input */
  pkt->raw.len = hex_str_to_uint((char *)pkt_buf, strlen((const char *)pkt_buf),
          pkt->raw.buf);

  disect_raw_packet(pkt);
  log_stderr(LOG_DEBUG, "Packet converion:");
  log_stderr(LOG_DEBUG, "Packet in:\n%s", pkt_buf);
  log_stderr(LOG_DEBUG, "Packet Out:");
  print_memory_bytes_hex(pkt->raw.buf, pkt->raw.len);

cleanup:
  free_packet(pkt);
  return ret;
}

