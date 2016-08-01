/******************************************************************************
 * File: log.h
 * Description: Functions to handle logging
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
#include <stdarg.h>

/*
 * \brief Debug logs disabled by default
 */
#ifndef DEBUG
#define DEBUG           0
#define EN_DEBUG        0
#else
#define EN_DEBUG        DEBUG
#endif

/*
 * \brief logs enabled by default
 */
#ifndef LOG_PRINTING
#define EN_LOGGING      1
#else
#define EN_LOGGING      LOG_PRINTING
#endif

/*
 * \brief Logging macros that allow printing to be removed
 */
#define LOG_ERROR(fmt, ...) \
  do { if (EN_LOGGING) log_stderr(LOG_ERROR, fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO(fmt, ...) \
  do { if (EN_LOGGING) log_stdout(LOG_INFO, fmt, ##__VA_ARGS__); } while (0)

#define LOG_DEBUG(fmt, ...) \
  do { if (EN_DEBUG) log_stderr(LOG_DEBUG, fmt, ##__VA_ARGS__); } while (0)
#define LOG_DEBUG_FN(fmt, ...) \
  do { if (EN_DEBUG) log_stderr(LOG_DEBUG_FN, fmt, ##__VA_ARGS__); } while (0)

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
