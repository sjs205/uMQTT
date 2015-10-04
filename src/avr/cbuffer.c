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

#include "cbuffer.h"

/**
 * \brief Circular buffer initilisation routine
 */
struct cbuf *cbuf_init(size_t size)
{
  struct cbuf *q = malloc(sizeof(struct cbuf));
  if(q==NULL)
    return NULL;

  q->buf = malloc(size);
  if(q->buf==NULL)
    return NULL;

  q->count=0;
  q->front=0;
  q->end=0;
  q->size=size;
  return q;
}

/**
 * \brief	Load buffer routine
 */
uint8_t cbuf_load(struct cbuf *tmp_buf, uint8_t tmp)
{
  if (cbuf_isfull(tmp_buf)) {
    return BUF_FULL;
  } else {
    ATOMIC_BLOCK(ATOMIC_RESTORESTATE)
    {
      tmp_buf->buf[tmp_buf->end] = tmp;	
      tmp_buf->end++;
      if(tmp_buf->end>=tmp_buf->size) {
        tmp_buf->end=0;
      }

      tmp_buf->count++;
    }
    return SUCCESS;

  }
}

/**
 * \brief Unload buffer routine
 */
uint8_t cbuf_unload(struct cbuf *tmp_buf)
{
  uint8_t volatile tmp;
  if (cbuf_isempty(tmp_buf)) {
    return BUF_EMPTY;
  } else {
    ATOMIC_BLOCK(ATOMIC_RESTORESTATE)
    {
      tmp = tmp_buf->buf[tmp_buf->front];
      tmp_buf->front++;
      if(tmp_buf->front==tmp_buf->size) {
        tmp_buf->front=0;
      } 
      tmp_buf->count--;
    }
  }

  return tmp;
}

/**
 * \brief	Circular buffer test function.
 * \return True if buffer is full.
 */
uint8_t cbuf_isfull(struct cbuf *tmp_buf)
{
  return(tmp_buf->count == tmp_buf->size);
}

/**
 * \brief	Circular buffer test function.
 * \return True if buffer is empty.
 */
uint8_t cbuf_isempty( struct cbuf * volatile tmp_buf)
{
  return(tmp_buf->count == 0);
}

/**
 * \brief	Circular buffer test function.
 * \return The value of the buffer at offset
 */
uint8_t cbuf_read(struct cbuf *tmp_buf, uint8_t offset)
{
  return (tmp_buf->buf[offset]);
}

/**
 * \brief	Circular buffer test function.
 * \return The size of the buffer.
 */
uint8_t cbuf_size(struct cbuf *tmp_buf)
{
  return tmp_buf->size;
}

/**
 * \brief	Circular buffer test function.
 * \return The number of elements in the buffer.
 */
uint8_t cbuf_count(struct cbuf *tmp_buf)
{
  return tmp_buf->count;
}

/**
 * \brief	Circular buffer test function.
 * \return The value at the front of the buffer.
 */
uint8_t cbuf_front(struct cbuf *tmp_buf)
{
  return(tmp_buf->buf[tmp_buf->front]);
}

/**
 * \brief	Circular buffer test function.
 * \return The value at the end of the buffer.
 */
uint8_t cbuf_end(struct cbuf *tmp_buf)
{
  return(tmp_buf->buf[tmp_buf->end]);
}

/**
 * \brief	Circular buffer test function.
 * \return The position of the front of the buffer.
 */
uint8_t cbuf_front_pos(struct cbuf *tmp_buf)
{
  return(tmp_buf->front);
}

/**
 * \brief	Circular buffer test function.
 * \return The position of the end of the buffer.
 */
uint8_t cbuf_end_pos(struct cbuf *tmp_buf)
{
  return(tmp_buf->end);
}
