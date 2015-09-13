/******************************************************************************
 * File: uMQTT_test.c
 * Description: MicroMQTT (uMQTT) library tests.
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
#include "uMQTT.h"
#define BITS_BIG_ENDIAN 0

int test_encode_remaining_pkt_len(struct mqtt_packet *pkt, int len) {

  encode_remaining_pkt_len(pkt, len);
  printf("The remaining packet length of %d leads to:\n", len);
  printf("\t%0.2X %0.2X %0.2X %0.2X\n",
      pkt->fixed->remain_len[0],
      pkt->fixed->remain_len[1],
      pkt->fixed->remain_len[2],
      pkt->fixed->remain_len[3]);

  return;
}

int test_decode_remaining_pkt_len(struct mqtt_packet *pkt, int len) {

  int len_dec = decode_remaining_pkt_len(pkt);
  printf("The decoded remaining packet length leads to:\n\t%d\n", len_dec);
  if (len_dec != len) {
    printf("\tDecode FAILED\n");
    return 1;
  }

  return 0;
}

int test_enc_dec_remaining_pkt_len() {

  int ret = 0;
  /* rewrite with the above */
  struct mqtt_packet *pkt = '\0';
  init_packet(&pkt);
  init_packet_header(pkt, CONNECT);

  test_encode_remaining_pkt_len(pkt, 0);
  ret = test_decode_remaining_pkt_len(pkt, 0);
  test_encode_remaining_pkt_len(pkt, 127);
  ret = test_decode_remaining_pkt_len(pkt, 127);
  test_encode_remaining_pkt_len(pkt, 128);
  ret = test_decode_remaining_pkt_len(pkt, 128);
  test_encode_remaining_pkt_len(pkt, 16383);
  ret = test_decode_remaining_pkt_len(pkt, 16383);
  test_encode_remaining_pkt_len(pkt, 16384);
  ret = test_decode_remaining_pkt_len(pkt, 16384);
  test_encode_remaining_pkt_len(pkt, 2097151);
  ret = test_decode_remaining_pkt_len(pkt, 2097151);
  test_encode_remaining_pkt_len(pkt, 2097152);
  ret = test_decode_remaining_pkt_len(pkt, 2097152);
  test_encode_remaining_pkt_len(pkt, 268435455);
  ret = test_decode_remaining_pkt_len(pkt, 268435455);
  return ret;
}

int main() {
 test_enc_dec_remaining_pkt_len();

  struct mqtt_packet *pkt = '\0';

  init_packet(&pkt);

  init_packet_header(pkt, CONNECT);

  printf("Length of new packet = %d\n", pkt->length);
  //print_pkt_hex(pkt, 10);
  print_memory_bytes_hex((void *)pkt->fixed, 1);



  return;
}

