/******************************************************************************
 * File: uMQTT.c
 * Description: uMQTT avr hello world test application - sends hello world to
 *              a host via USART.
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
#include <avr/io.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/sleep.h>

#include "usart_async.h"
#include "uMQTT.h"

usart_buf *usart_tx_buf; 
usart_buf *usart_rx_buf; 

static void usart_load_tx_buf(uint8_t *buf, size_t size) {
  uint8_t i;

  for (i = 0; i < size; i++) {
    usart_buf_load_block(usart_tx_buf, buf[i]);
  }
  if (!tx_isenabled())
    tx_enable(TRUE);

  return;
}

int main(void)
{ 
  wdt_reset();
  wdt_disable();

  set_sleep_mode(SLEEP_MODE_IDLE);

  /* initialise USART buffers and usart */
  usart_tx_buf = usart_buf_init(USART_TX_BUF_SIZE);
  usart_rx_buf = usart_buf_init(USART_RX_BUF_SIZE);
  usart_init();
  usart_half_duplex_init();

  /* enable global interrupts */
  sei();

  /* Create Hello World packet */
  struct mqtt_packet *pkt = construct_packet_headers(PUBLISH);
  set_publish_variable_header(pkt, "uMQTT_avr", sizeof("uMQTT_avr"));
  init_packet_payload(pkt, PUBLISH, (uint8_t *)"Hello World!",
      sizeof("Hello World!"));

  finalise_packet(pkt);

  for (;;) {

    if (!usart_buf_isempty(usart_tx_buf)) {
      tx_enable(TRUE);
    }

    usart_load_tx_buf(pkt->raw.buf, *pkt->raw.len);

    _delay_ms(500); 

  }


  return 0;

}
