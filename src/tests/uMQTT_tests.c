/******************************************************************************
 * File: uMQTT_utests.c
 * Description: MicroMQTT (uMQTT) library unit tests.
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

#include "uMQTT.h"
#include "uMQTT_client.h"
#include "uMQTT_helper.h"

/**
 * \brief Function to test the encoding and decoding of the remaining packet
 *        length.
 * \return sucess or failurer of tests.
 */
int test_enc_dec_remaining_pkt_len() {

  int ret = 0, i;

  unsigned int lengths[8] = { 0, 127, 128, 16383,
    16384, 2097151, 2097152, 268435455 };

  struct mqtt_packet *pkt = '\0';

  printf("Testing remaining packet length encoding/decoding:\n");

  init_packet(&pkt);
  init_packet_fixed_header(pkt, CONNECT);

  for (i = 0; i < 8; i++) {
    encode_remaining_len(pkt, lengths[i]);
    printf("Length: %d\t\tEncoded: %02X %02X %02X %02X\t",
        lengths[i], pkt->fixed->remain_len[0],
        pkt->fixed->remain_len[1],
        pkt->fixed->remain_len[2],
        pkt->fixed->remain_len[3]);

    int len_dec = decode_remaining_len(pkt);
    printf("Decoded:%d\n", len_dec);
    if (len_dec != lengths[i]) {
      printf("\tDecode FAILED\n");
      ret = 1;
    }
  }

  if (ret) {
    printf("Remaining length encoding/decoding failed.\n\n");
  } else {
    printf("Remaining length encoding/decoding successful.\n\n");
  }

  return ret;
}

/**
 * \brief Function to compare two packets.
 * \param pkt1 Packet to compare.
 * \param pkt2 Packet to compare.
 * \return the difference in size between the two packets,
 */
int test_compare_packets(struct mqtt_packet *pkt1, struct mqtt_packet *pkt2) {
  int i;
  int delta = pkt1->len - pkt2->len;

  if (pkt1->fixed->generic.type != pkt1->fixed->generic.type) {
    printf("Error: Cannot compare packets of different type\n");
    return delta;
  }

  printf("Comparing %s type packets:\n",get_type_string(pkt1->fixed->generic.type));

  if (delta) {
    delta = (delta < 0) ? delta * -1 : delta;

    printf("Packet sizes differ by %d\n", delta);
    printf("pkt1 len: %zu pkt2 len: %zu\n", pkt1->len, pkt2->len);

    return delta;
  }

  for (i = 0; i <= pkt1->len; i++) {
    if (pkt1->raw.buf[i] != pkt2->raw.buf[i]) {
      printf("Byte %d differs: pkt1: %02X pkt2: %02X\n", i, pkt1->raw.buf[i],
          pkt2->raw.buf[i]);
      delta++;
    }
  }

  if (!delta) {
    printf("Packets match exactly\n");
  }

  return delta;
}

/**
 * \brief Fuction to create manual control packets with which to compare packet
 *        creation functions.
 *
 */
struct mqtt_packet *create_manual_control_pkt(ctrl_pkt_type type) {

  struct mqtt_packet *pkt;
  if (init_packet(&pkt)) {
    printf("ERROR: Packet creation failed\n");
    return 0;
  }

  switch (type) {
    case CONNECT: ;
      /* default connect packet */
      uint8_t connect[19] = {
        0x10, 0x11, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0x75, 0x4D,
        0x51, 0x54, 0x54 };
      memcpy(pkt->raw.buf, connect, sizeof(connect));
      disect_raw_packet(pkt);
      break;

    case PUBLISH: ;
      /* default publish packet */
      uint8_t publish[39] = {
        0x30, 0x25, 0x00, 0x09, 0x75, 0x4D, 0x51, 0x54,
        0x54, 0x5F, 0x50, 0x55, 0x42, 0x75, 0x4D, 0x51,
        0x54, 0x54, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20,
        0x50, 0x55, 0x42, 0x4C, 0x49, 0x53, 0x48, 0x20,
        0x70, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x00 };
      memcpy(pkt->raw.buf, publish, sizeof(publish));
      disect_raw_packet(pkt);
      break;

    case PINGREQ: ;
      /* default pingreq packet */
      uint8_t pingreq[39] = { 0xC0, 0x00 };
      memcpy(pkt->raw.buf, pingreq, sizeof(pingreq));
      disect_raw_packet(pkt);
      break;

    case PINGRESP: ;
      /* default pingresp packet */
      uint8_t pingresp[39] = { 0xD0, 0x00 };
      memcpy(pkt->raw.buf, pingresp, sizeof(pingresp));
      disect_raw_packet(pkt);
      break;

    case DISCONNECT: ;
      /* default disconnect packet */
      uint8_t disconnect[39] = { 0xE0, 0x00 };
      memcpy(pkt->raw.buf, disconnect, sizeof(disconnect));
      disect_raw_packet(pkt);
      break;

    default:
      printf("ERROR: Packet type not recognised\n");
      return 0;
      break;
  }

  return pkt;
}

int test_packet_creation() {
  ctrl_pkt_type type;
  int delta = 0, fails = 0;

  struct mqtt_packet *ctrl_pkt, *gen_pkt;

  printf("Testing packet creation:\n");

  /* CONNECT packet */
  type = CONNECT;
  ctrl_pkt = create_manual_control_pkt(type);
  gen_pkt = construct_default_packet(type, 0, 0);
  delta = test_compare_packets(ctrl_pkt, gen_pkt);
  if (delta) {
    fails++;
    printf("Creation of control packet type %d failed.\n", (int)type);
  }
  free_packet(ctrl_pkt);
  free_packet(gen_pkt);

  /* PUBLISH packet */
  type = PUBLISH;
  ctrl_pkt = create_manual_control_pkt(type);
  gen_pkt = construct_default_packet(type,
      (uint8_t *)"uMQTT test PUBLISH packet",
      sizeof("uMQTT test PUBLISH packet"));
  delta = test_compare_packets(ctrl_pkt, gen_pkt);
  if (delta) {
    fails++;
    printf("Creation of control packet type %d failed.\n", (int)type);
  }
  free_packet(ctrl_pkt);
  free_packet(gen_pkt);

  /* PINGREQ packet */
  type = PINGREQ;
  ctrl_pkt = create_manual_control_pkt(type);
  gen_pkt = construct_default_packet(type, 0, 0);
  delta = test_compare_packets(ctrl_pkt, gen_pkt);
  if (delta) {
    fails++;
    printf("Creation of control packet type %d failed.\n", (int)type);
  }
  free_packet(ctrl_pkt);
  free_packet(gen_pkt);

  /* PINGRESP packet */
  type = PINGRESP;
  ctrl_pkt = create_manual_control_pkt(type);
  gen_pkt = construct_default_packet(type, 0, 0);
  delta = test_compare_packets(ctrl_pkt, gen_pkt);
  if (delta) {
    fails++;
    printf("Creation of control packet type %d failed.\n", (int)type);
  }
  free_packet(ctrl_pkt);
  free_packet(gen_pkt);

  /* DISCONNECT packet */
  type = DISCONNECT;
  ctrl_pkt = create_manual_control_pkt(type);
  gen_pkt = construct_default_packet(type, 0, 0);
  delta = test_compare_packets(ctrl_pkt, gen_pkt);
  if (delta) {
    fails++;
    printf("Creation of control packet type %d failed.\n", (int)type);
  }
  free_packet(ctrl_pkt);
  free_packet(gen_pkt);

  if (!fails) {
    printf("Control packet creation successful for all packet types.\n\n");
  }

  return fails;
}

int main() {

  int ret = 0;

  if (test_enc_dec_remaining_pkt_len()) {
    ret = 1;
  }

  if ((test_packet_creation())) {
    ret = 1;
  }

  return ret;
}
