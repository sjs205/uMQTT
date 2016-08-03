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
#include <errno.h>

#include <getopt.h>

#include "uMQTT.h"
#include "uMQTT_helper.h"
#include "../inc/log.h"

#define MAX_PACKET_SIZE_BYTES     65536

#define UMQTT_MAX_FILENAME_LEN    1024      /* 1KB */
#define UMQTT_MAX_FILE_SIZE       16384     /* 16KB */
#define UMQTT_TEST_PACKET_HEX     \
  "301C00167361626174696E692F646174692F7069312F40612F3135382E35"
#define UMQTT_TEST_PACKET_HEX_UNSANATISED     \
  "0x30 0x1C 0x00 0x16 0x73 0x61 0x62 0x61 0x74 0x69 0x6E 0x69 0x2F 0x64 0x61 0x74 0x69 0x2F 0x70 0x69 0x31 0x2F 0x40 0x61 0x2F 0x31 0x35 0x38 0x2E 0x35 "

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
      " -i [--ignore]            : ignore packet errors\n"
      " -t [--test]              : run unit tests\n"
      "\n");

  return 0;
}

void sanatise_hex_input(char *in, size_t *len) {
  char *buf = in;
  size_t olen = *len;

  /* remove spaces */
  while((buf = strstr(buf ," "))) {
    memmove(buf, buf + 1, 1 + strlen(buf + 1));
  }

  *len = strlen(in);
  if (olen != *len) {
    log_std(LOG_DEBUG, "Removed %zu spaces from string", olen - *len);
    olen = *len;
  }
  buf = in;

  /* remove "0x*/
  while((buf = strstr(buf ,"0x"))) {
    memmove(buf, buf + 2, 1 + strlen(buf + 2));
  }

  *len = strlen(in);
  if (olen != *len) {
    log_std(LOG_DEBUG, "Removed %zu instances of '0x' from string",
        olen - *len);
    log_std(LOG_DEBUG, "New string length: %zu", *len);
  }

  return;
}

umqtt_ret sanatise_hex_input_utest() {
  umqtt_ret ret = UMQTT_SUCCESS;
  size_t len = sizeof(UMQTT_TEST_PACKET_HEX_UNSANATISED);
  char in[sizeof(UMQTT_TEST_PACKET_HEX_UNSANATISED)] =
    UMQTT_TEST_PACKET_HEX_UNSANATISED;

  log_std(LOG_INFO, "\nSanatise Hex string to uint array conversion test");
  log_std(LOG_INFO, "Hex string of %zu bytes in:\n%s", len, in);
  sanatise_hex_input(in, &len);
  log_std(LOG_INFO, "\nHex string of %zu bytes out:\n%s", len, in);

  if (len == (sizeof(UMQTT_TEST_PACKET_HEX) - 1)) {
    log_std(LOG_INFO, "PASSED: sanatisation length test:");

  } else {
    log_std(LOG_ERROR, "FAILED: sanatisation length test:");
    ret = UMQTT_ERROR;
  }
  log_std(LOG_INFO, "   original sizeof(in): %zu, new sizeof(out): %zu",
      sizeof(UMQTT_TEST_PACKET_HEX_UNSANATISED) - 1, len);

  if (!strcmp(in, UMQTT_TEST_PACKET_HEX)) {
    log_std(LOG_INFO, "PASSED: sanatisation output string correct");

  } else {
    log_std(LOG_ERROR, "FAILED: sanatisation output string incorrect");
    ret = UMQTT_ERROR;
  }

  return ret;
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

  sanatise_hex_input(in, &len);

  log_std(LOG_DEBUG, "Converting HEX string of %zu bytes:\n%s", len, in);
  if (len  % 2 == 0) {
    for (count = 0; count < len && (count / 2) < nibbles; count += 2) {

      if (hex_char_to_uint(&in[count], &hnibble)) {
        log_std(LOG_ERROR, "Hex conversion - high nibble");
      }
      if (hex_char_to_uint(&in[count + 1], &lnibble)) {
        log_std(LOG_ERROR, "Hex conversion - low nibble");
      }

      out[count / 2] = ((hnibble) << 4) | (lnibble & 0x0f);
    }
  } else {
    log_std(LOG_ERROR,
        "Hex packet input should be an even number of nibbles");
  }

  return count / 2;
}

umqtt_ret hex_str_to_uint_utest() {
  umqtt_ret ret = UMQTT_SUCCESS;
  char in[sizeof(UMQTT_TEST_PACKET_HEX)] = UMQTT_TEST_PACKET_HEX;
  uint8_t out[sizeof(UMQTT_TEST_PACKET_HEX) / 2] = {0};

  log_std(LOG_INFO, "\nHex string to uint array conversion test");
  size_t len = hex_str_to_uint(in, sizeof(UMQTT_TEST_PACKET_HEX) - 1, out);

  if (len == ((sizeof(UMQTT_TEST_PACKET_HEX) - 1) / 2)) {
    log_std(LOG_INFO, "PASSED: Output array length test:");
    log_std(LOG_INFO, "   sizeof(in): %zu, sizeof(out): %zu, (in/out) = 2",
        sizeof(UMQTT_TEST_PACKET_HEX) - 1, len);

  } else {
    log_std(LOG_ERROR, "FAILED: Output array length test:");
    log_std(LOG_ERROR, "   sizeof(in): %zu, sizeof(out): %zu, (in/out) != 2",
        sizeof(UMQTT_TEST_PACKET_HEX) - 1, len);

    ret = UMQTT_ERROR;
  }

  return ret;
}

size_t hex_char_to_uint_utest() {
  umqtt_ret ret;

  char in = '0';
  uint8_t out = 0, i;

  log_std(LOG_INFO, "\nHex char to uint conversion test");

  for (i = 0; i <= 15; i++) {
    hex_char_to_uint(&in, &out);
    if (out == i) {
      log_std(LOG_INFO, "PASSED: i: %d: in: '%c' out: %X (i == out)",
          i, in, out);
      ret = UMQTT_SUCCESS;
    } else {
      log_std(LOG_INFO, "FAILED: i: %d: in: '%c' out: %X (i != out)",
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
  ssize_t rlen, b_ptr = 0;
  char *line = NULL;
  size_t llen = 0;

  FILE *f = fopen(filename, "rb");
  if (!f) {
    log_std(LOG_ERROR, "Failed to open file: %s - %s", filename,
        strerror(errno));
    return UMQTT_FILE_ERROR;
  }

  fseek(f, 0, SEEK_END);
  size_t fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize > *len) {
    log_std(LOG_ERROR, "The file size (%zu) is larger than buffer size (%zu)",
        fsize, *len);
    ret = UMQTT_PAYLOAD_ERROR;
  } else {
    while ((rlen = getline(&line, &llen, f)) != -1) {

      if (rlen > 0) {

        if (line[0] == '#') {
          /* comment - ignore */
          log_std(LOG_DEBUG, "Ignoring comment: %s", line);
          continue;
        }

        if (line[0] == 0x0A) {
          /* newline - ignore */
          log_std(LOG_DEBUG, "Ignoring newline");
          continue;
        }

        log_std(LOG_DEBUG, "Retrieved line of length %zu", rlen);
        memcpy(buf + b_ptr, line, rlen);
        b_ptr += rlen ;

        if (b_ptr >= *len) {
          log_std(LOG_DEBUG, "File buffer full: %zu bytes", *len);
          ret = UMQTT_ERROR;
          break;
        }
      }
    }
    log_std(LOG_DEBUG, "File buffer used: %zu of %zu bytes", b_ptr, *len);
    log_std(LOG_DEBUG, "Buffer:\n%s\n", buf);
    free(line);
    *len = b_ptr;

  }
  fclose(f);

  return ret;
}

int main(int argc, char **argv) {

  umqtt_ret ret = UMQTT_SUCCESS;
  int c, option_index = 0;
  uint8_t ignore_pkt_errs = 0;
  uint8_t cl_pkt = 0;
  char filename[UMQTT_MAX_FILENAME_LEN] = "\0";
  size_t file_len = UMQTT_MAX_FILE_SIZE;
  uint8_t file_buf[UMQTT_MAX_FILE_SIZE] = "\0";
  uint8_t pkt_buf[MAX_PACKET_SIZE_BYTES] = {0};

  struct mqtt_packet *pkt = NULL;
  if (init_packet(&pkt)) {
    log_std(LOG_INFO, "ERROR: Packet creation failed");
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
    {"ignore", no_argument,             0, 'i'},
    {"test", no_argument,               0, 't'},
    {"verbose", required_argument,      0, 'v'},
    {0, 0, 0, 0}
  };

  /* get arguments */
  while (1)
  {
    if ((c = getopt_long(argc, argv, "bhtxif:p:v:", long_options,
            &option_index)) != -1) {

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
            log_std(LOG_ERROR, "The packet flag should be followed by a string");
            ret = print_usage();
            goto cleanup;
          }
          break;

        case 'b':
          /* Set input format to binary*/
            log_std(LOG_ERROR, "Binary input is not currently supported");
            ret = print_usage();
            goto cleanup;
          break;

        case 'i':
          /* Ignore packet errors */
          ignore_pkt_errs = 1;
          break;

        case 'x':
          /* Set output format to hex*/
            log_std(LOG_ERROR, "Hex output format is not currently supported");
            ret = print_usage();
            goto cleanup;
          break;

        case 'f':
          /* set the message to the file */
          if (optarg) {
            strcpy(filename, optarg);
          } else {
            log_std(LOG_ERROR, "The file flag should be followed by a file");
            ret = print_usage();
            goto cleanup;
          }
          break;

        case 't':

          log_std(LOG_INFO, "Running unti tests...");
          log_std(LOG_INFO, "Help test:");
          print_usage();

          log_std(LOG_INFO, "hex_char_to_uint_utest:"); 
          ret = hex_char_to_uint_utest();
          ret = hex_str_to_uint_utest();

          sanatise_hex_input_utest();
          goto cleanup;

          break;
      }
    } else {
      /* Final arguement */
      /* we should capture from stdin if final arguement is '-' */
      break;
    }
  }

  if ((!cl_pkt && !*filename) || (cl_pkt && *filename)) {
    log_std(LOG_ERROR,
        "Must specify either a filename or a packet, not both");
    ret = UMQTT_ERROR;
    print_usage();
    goto cleanup;
  }

  if (*filename) {
    log_std(LOG_INFO, "Reading packets from file: %s", filename);
    ret = file_read_contents(filename, file_buf, &file_len);
    if (ret) {
      log_std(LOG_ERROR, "Could not read file");
      goto cleanup;
    }

    /* disect buffer */
    uint8_t *line = file_buf;
    uint8_t *eol = NULL;
    size_t len = 0;
    while ((eol = (uint8_t *)strchr((char *)line, 0x0A))) {
      /* copy line to buffer */

      /* get line length */
      len = eol - line;

      /* set NULL terminatinf string */
      *eol = '\0';

      /* should be a newline */
      pkt->raw.len = hex_str_to_uint((char *)line, len, pkt->raw.buf);

      /* update index */
      line = eol + 1;

    }
  } else {
    /* process hex packet - need to add binary input */
    pkt->raw.len = hex_str_to_uint((char *)pkt_buf,
        strlen((const char *)pkt_buf), pkt->raw.buf);
  }

  /* print packet */
  ret = disect_raw_packet(pkt);
  if (ret) {
    log_std(LOG_ERROR, "Failed to decode %s packet.",
        get_type_string(pkt->fixed->generic.type));
    if (!ignore_pkt_errs) {
      goto cleanup;
    }
  }

  print_packet_detailed(pkt);
  print_packet_hex_debug(pkt);

cleanup:
  free_packet(pkt);
  return ret;
}

