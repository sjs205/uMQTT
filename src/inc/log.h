/******************************************************************************
 * File: log.h
 * Description: Functions to handle logging
 * Author: Steven Swann - swannonline@googlemail.com
 *
 * Copyright (c) swannonline, 2013-2014
 * 
 * This file is part of sensorspace.
 *
 * sensorspace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sensorspace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sensorspace.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

typedef enum {
  LOG_NONE,

  LOG_QUIET,
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG,
  LOG_DEBUG_FN
} log_level_t;


log_level_t log_level(log_level_t level);
log_level_t set_log_level_str(char *level);
void log_stdout(log_level_t level, const char *format, ...);
void log_stderr(log_level_t level, const char *format, ...);
void log_std(log_level_t level, const char *format, ...);
void log_section(log_level_t level, FILE *stream, const char *header,
    const char *format, ...);
