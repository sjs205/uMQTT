/******************************************************************************
 * File: usart_async.h
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

#include <stdlib.h>

#include <avr/io.h>
#include <util/delay.h>
#include <avr/interrupt.h>
#include <avr/cpufunc.h> 

#include "cbuffer.h"

/*
 *	Macro definitions
 */
#define SETBIT(x,y) (x |= (y)) 		// Set bit y in byte 
#define CLEARBIT(x,y) (x &= (~y)) 	// Clear bit y in byte x
#define CHECKBIT(x,y) (x & (y)) 	// Check bit y in byte x

/*
 *	USART definitions
 */
#if !defined BAUD
	#define BAUD 9600	
#endif
#if !defined MYBURR
	#define MYUBRR F_CPU/16/BAUD-1
#endif

#define USART_ECHO            1
/*
 *	USART Buffer definitions
 */
#define USART_TX_BUF_SIZE     32
#define USART_RX_BUF_SIZE     12

#define SUCCESS		0
#define ERROR	  	0xFF

#define FALSE 		0
#define TRUE	  	1

#define DEV_BOARD
#ifdef DEV_BOARD
#define MAX485_CTRL_PORT  PORTD
#define MAX485_CTRL_DDR   DDRD
#define MAX485_RE         PD2
#define MAX485_DE         PD3
#else
#define MAX485_CTRL_PORT  PORTC
#define MAX485_CTRL_DDR   DDRC
#define MAX485_RE         PC2
#define MAX485_DE         PC3
#endif

/* Half-duplex usart when set */
#define HALF_DUPLEX             TRUE
#define USART_LED_DUPLEX_DEBUG  0
typedef struct cbuf usart_buf;

usart_buf *usart_tx_buf;
usart_buf *usart_rx_buf;

volatile uint8_t cmd_ready;

uint8_t tx_isenabled(void);  
void tx_enable(int tx_int);
void tx_disable(void);
void rx_enable(int rx_int);
void rx_disable(void);
void usart_init(void);
uint8_t usart_poll_tx(uint8_t temp);
uint8_t usart_poll_rx(void);
uint8_t usart_tx(uint8_t temp);

void usart_half_duplex_init(void);

usart_buf *usart_buf_init(size_t size);
uint8_t usart_buf_load(usart_buf *buf, uint8_t byte);
uint8_t usart_buf_load_block(usart_buf *buf, uint8_t byte);
uint8_t usart_buf_unload(usart_buf *buf);
uint8_t usart_buf_isempty(usart_buf *buf);
uint8_t usart_buf_isfull(usart_buf *buf);

ISR(usart_UDRE_vect, ISR_BLOCK);
ISR(usart_TX_vect);
ISR(usart_RX_vect);
