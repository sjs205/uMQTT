/******************************************************************************
 * File: cbuffer.h
 * Description: Circular buffer implimentation for AVR devices
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

#if !defined(CBUF_H)
#define CBUF_H

#include <stdlib.h>
#include <util/atomic.h>

#define BUF_EMPTY	0
#define BUF_FULL	1

#if !defined(CBUF_SIZE)
  #define CBUF_SIZE	32
#endif

#define SUCCESS		0
#define ERROR		0xFF

#define FALSE 		0
#define TRUE		1

struct cbuf {
  uint8_t *buf;
  uint8_t size;
  uint8_t count;
  uint8_t front;
  uint8_t end;
};
  
/*
 * 	buffer initilisation routine
 */
struct cbuf *cbuf_init(size_t size);

/*
 *	load buffer routines
 *  
 *	end = next free space
 *	end - 1 =  Last item in cbuf
 */
uint8_t cbuf_load( struct cbuf *buf, uint8_t temp);

uint8_t cbuf_load_ptr( struct cbuf *buf, uint8_t *temp);

/*	Unload buffer routines
 *
 *	it is a good idea to call cbuf_isempty(buf)
 *	before calling this function, otherwise, we don't 
 *	know if return = 0x00 is a valid data. e.g:
 * 	
 *	if (!cbuf_isempty(buf)) 
 *		item = cbuf_decbuf(buf);
 */ 
uint8_t cbuf_unload(struct cbuf *buf);

void *cbuf_unload_ptr(struct cbuf *tmp_buf);

/*
 * 	Circular buffer helper routine
 */
uint8_t cbuf_isfull(struct cbuf *buf);
uint8_t cbuf_isempty(struct cbuf *buf);

uint8_t cbuf_read(struct cbuf *tmp_buf, uint8_t offset);

uint8_t cbuf_size(struct cbuf *buf);

uint8_t cbuf_count(struct cbuf *buf);
uint8_t cbuf_front(struct cbuf *buf);
uint8_t *cbuf_front_ptr(struct cbuf *tmp_buf);
uint8_t cbuf_front_pos(struct cbuf *buf);

uint8_t cbuf_end_pos(struct cbuf *buf);
uint8_t cbuf_end(struct cbuf *buf); 

#endif	/*CBUF_H*/
