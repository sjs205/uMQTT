/******************************************************************************
 * File: usart_async.c
 * Description: Functions to provide access to the AVR USARTs
 * Author: Steven Swann - swannonline@googlemail.com
 *
 * Copyright (c) swannonline, 2013-2014
 * 
 * This file is part of water_meter.
 *
 * water_meter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * water_meter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with water_meter.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#include "usart_async.h"

static void max485_init(void)
{
  SETBIT(MAX485_CTRL_DDR,(1<<MAX485_RE));
  SETBIT(MAX485_CTRL_DDR,(1<<MAX485_DE));
}

static void max485_tx(void)
{	
  SETBIT(MAX485_CTRL_PORT,(1<<MAX485_RE));
  SETBIT(MAX485_CTRL_PORT,(1<<MAX485_DE));

  return;
}

static void max485_rx(void)
{	
  CLEARBIT(MAX485_CTRL_PORT,(1<<MAX485_DE));
  CLEARBIT(MAX485_CTRL_PORT,(1<<MAX485_RE));

  return;
}

static void usart_half_duplex(int tx_nrx)
{
  if (tx_nrx) {
    max485_tx();
    rx_disable();
  } else {
    max485_rx();
    rx_enable(TRUE);
  }
  return;
}

void usart_half_duplex_init()
{
  max485_init();
  usart_half_duplex(FALSE);
}

/*
 * USART buffer initalisation - circular buffer init routine
 */
usart_buf *usart_buf_init(size_t size)
{
  if (size <= USART_TX_BUF_SIZE) {
    return cbuf_init(size);  

  } else {
    return NULL;
  }
}

/*
 * USART buffer load - Load byte into USART buffer
 */
uint8_t usart_buf_load(usart_buf *buf, uint8_t byte)
{
  return cbuf_load(buf, byte);
}

/*
 * USART buffer load - Load byte into USART buffer 
 *                     blocks until buffer has space
 */
uint8_t usart_buf_load_block(usart_buf *buf, uint8_t byte)
{
  while(cbuf_isfull(buf));
  
  return cbuf_load(buf, byte);
}

/*
 * USART buffer unload - Unload byte into USART buffer
 */
uint8_t usart_buf_unload(usart_buf *buf)
{
  return cbuf_unload(buf);
}

/*
 * USART buffer isempty 
 */
uint8_t usart_buf_isempty(usart_buf *buf)
{
  return cbuf_isempty(buf);
}

/*
 * USART buffer isfull
 */
uint8_t usart_buf_isfull(usart_buf *buf)
{
  return cbuf_isfull(buf);
}

/*
 * TX is enabled? - Returns state of TXEN0
 */
uint8_t tx_isenabled(void)
{	
	return CHECKBIT(UCSR0B,(1<<TXEN0));
}

/*
 * TX enable - Enables USART TX
 */
void tx_enable(int tx_int)
{	
  if(HALF_DUPLEX)
    usart_half_duplex(TRUE);
  /* set TX enable */
  SETBIT(UCSR0B,(1<<TXEN0));

  /* TX buf empty interrupt enabled */
  if (tx_int) {
    SETBIT(UCSR0B,(1<<UDRIE0));
    SETBIT(UCSR0B,(1<<TXCIE0));
  }
  return;
}

/*
 * TX disable - Disables USART TX
 */
void tx_disable(void)
{	
  /* clear TX enable */
  CLEARBIT(UCSR0B,(1<<TXEN0));
  /* disable data register empty int */
  CLEARBIT(UCSR0B,(1<<UDRIE0));
  /* disable TX complete int */
  CLEARBIT(UCSR0B,(1<<UDRIE0));
  CLEARBIT(UCSR0B,(1<<TXCIE0));

  return;
}

/*
 * RX enable - Enables USART RX
 */
void rx_enable(int rx_int)
{	
  /* RX enable */
  SETBIT(UCSR0B,(1<<RXEN0));
  /* Receive complete interrupt enabled */
  if (rx_int)
    SETBIT(UCSR0B,(1<<RXCIE0));

  return;
}

/*
 * RX disable - Disables USART RX
 */
void rx_disable(void)
{	
  /* clear RX enable */
  CLEARBIT(UCSR0B,(1<<RXEN0));
  /* Receive complete interrupt disabled */
  CLEARBIT(UCSR0B,(1<<RXCIE0));

  return;
}


/*
 * Baud rate Initialisation Routine
 */
static void usart_baud(unsigned int ubrr)
{
  UBRR0L = ubrr;				
  UBRR0H = (ubrr>>8);	
  return;
}

/*
 * Frame set Initialisation routine
 */
static void usart_frameset(void)
{
  /* async mode UMSEL01:0 */
  CLEARBIT(UCSR0C,(1<<UMSEL01));
  CLEARBIT(UCSR0C,(1<<UMSEL00));		

  /* Parity UPM01:0; 00=disabled;10=even;11=odd */
  CLEARBIT(UCSR0C,(1<<UPM01));
  CLEARBIT(UCSR0C,(1<<UPM00));

  /* 1 stop bit USBS0; 01=2stop bits */
  CLEARBIT(UCSR0C,(1<<USBS0));

  /* 8-bit mode UCSZ01:0 */
  SETBIT(UCSR0C,(1<<UCSZ01));
  SETBIT(UCSR0C,(1<<UCSZ00));

  return;
}

/*
 * USART initilisation routine - prepares USART for comms
 */
void usart_init(void)
{	
  usart_frameset();
  usart_baud(MYUBRR);

  return;
}

/*
 * Receive Byte Routine - Polling implementation
 *									
 *  Waits for the receive complete flag and when set,
 *	returns the byte held in the UDR0 register.
 */
uint8_t usart_poll_rx()
{     
  while (!(UCSR0A & (1<<RXC0))); 

  return UDR0;
}

/*
 * Transmit Byte Routine - Polling implementation
 *									
 *  Waits for the data register empty flag and when clear, loads 
 *	the transmit data buffer with the byte stored in temp.
 */
uint8_t usart_poll_tx(uint8_t temp)
{     
  while (!(UCSR0A & (1<<UDRE0))); 

  UDR0 = temp;

  if (!tx_isenabled())
    tx_enable(FALSE);

  return SUCCESS;
}

/*
 * Transmit Byte Routine - Interrupt based implementation
 *									
 *  Loads the transmit data buffer with the byte stored in temp.
 */
uint8_t usart_tx(uint8_t temp)
{     
  UDR0 = temp;

  if (!tx_isenabled())
    tx_enable(TRUE);

  return SUCCESS;
}

/*
 * Transmit buffer empty interrupt
 */
ISR(USART_UDRE_vect)
{ 
  if (!usart_buf_isempty(usart_tx_buf)) {
    UDR0 = usart_buf_unload(usart_tx_buf);
  }  else {
    CLEARBIT(UCSR0B,(1<<UDRIE0));
  }   
  return;
}	

/*
 * Transmit buffer empty interrupt
 */
ISR(USART_TX_vect)
{ 
  if (usart_buf_isempty(usart_tx_buf)) {
    tx_disable();
    usart_half_duplex(FALSE);
  }

  return;
}	

/*
 * Receivce complete interrupt
 */
ISR(USART_RX_vect)
{ 
  uint8_t tmp = UDR0;

	if (!usart_buf_isfull(usart_rx_buf))
    usart_buf_load(usart_rx_buf, tmp);

  if (tmp == '\r')
    cmd_ready = TRUE;
  
  if(USART_ECHO) {
    if (!usart_buf_isfull(usart_tx_buf))
      usart_buf_load(usart_tx_buf, tmp);
  }
}	
