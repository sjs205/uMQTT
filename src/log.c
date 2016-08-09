/******************************************************************************
 * File: log.c
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
#include "log.h"

/*
 * \brief function to convert log_level to user readable string
 * \param level the log level of the message to be logged
 * \param buf The log level string
 */
static void get_log_level_str(log_level_t level, char *buf) {

  switch (level) {
    case LOG_NONE:
      /* should never be here */
      strcpy(buf, "NONE");
      break;
    case LOG_QUIET:
      strcpy(buf, "QUIET");
      break;
    case LOG_INFO:
      strcpy(buf, "INFO");
      break;
    case LOG_WARN:
      strcpy(buf, "WARN");
      break;
    case LOG_ERROR:
      strcpy(buf, "ERROR");
      break;
    case LOG_DEBUG:
      strcpy(buf, "DEBUG");
      break;
    case LOG_DEBUG_FN:
      strcpy(buf, "DEBUG_FN");
      break;
  }

  return;
}

/*
 * \brief function to set the log level from getopts str
 * \param level The log level to set
 * \param set when true the log level will be set
 * \return the current log level
 */
log_level_t set_log_level_str(char *level) {

 log_level_t ret;
  if (!strcmp(level, "QUIET")) {
    ret = log_level(LOG_QUIET);
  } else if(!strcmp(level, "INFO")) {
    ret = log_level(LOG_INFO);
  } else if(!strcmp(level, "WARN")) {
    ret = log_level(LOG_WARN);
  } else if(!strcmp(level, "ERROR")) {
    ret = log_level(LOG_ERROR);
  } else if(!strcmp(level, "DEBUG_FN")) {
    ret = log_level(LOG_DEBUG_FN);
  } else if(!strcmp(level, "DEBUG")) {
    ret = log_level(LOG_DEBUG);
  } else {
    log_stderr(LOG_ERROR, "Unrecognised log level");
    ret = log_level(0);
  }

  /* print current log level */
  char lev[16];
  get_log_level_str(ret, lev);
  log_stdout(LOG_ERROR, "Log level currently set at %s", lev);

  return ret;
}

/*
 * \brief function to set/get log level
 * \param level When true the log level is set,
 * \return the current log level
 */
log_level_t log_level(log_level_t level) {

  static log_level_t l_level = LOG_INFO;

  if (level > LOG_NONE) {
    l_level = level;
  }

  return l_level;
}

/*
 * \brief function to print log messages in va_args format to stdout
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param args additional arguments for format
 */
void log_stdout_args(log_level_t level, const char *format, va_list args) {
  if (log_level(0) >= level) {

    if (level > LOG_INFO) {

      char lvl_marker[24];
      get_log_level_str(level, lvl_marker);

      fprintf(stdout, "%s: ", lvl_marker);
    }

    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
  }

  return;
}

/*
 * \brief function to print log messages in va_args format to stderr
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param args additional arguments for format
 */
void log_stderr_args(log_level_t level, const char *format, va_list args) {
  if (log_level(0) >= level) {

    /* Automatically print msg type for std_err */
    char lvl_marker[24];
    get_log_level_str(level, lvl_marker);

    fprintf(stderr, "%s: ", lvl_marker);

    /* print error */

    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
  }

  return;
}

/*
 * \brief function to print log messages to stdout
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param ... additional arguments for format
 */
void log_stdout(log_level_t level, const char *format, ...) {

  va_list args;

  va_start(args, format);

  log_stdout_args(level, format, args);

  va_end(args);

  return;
}

/*
 * \brief function to print log messages to stderr
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param ... additional arguments for format
 */
void log_stderr(log_level_t level, const char *format, ...) {

  va_list args;

  va_start(args, format);

  log_stderr_args(level, format, args);

  va_end(args);

  return;
}

/*
 * \brief function to print log messages, the file the messages
 *          are printed to depends on the level.
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param ... additional arguments for format
 */
void log_std(log_level_t level, const char *format, ...) {

  va_list args;

  va_start(args, format);

  if (log_level(0) == LOG_INFO) {
    log_stdout_args(level, format, args);
  } else {
    log_stderr_args(level, format, args);
  }

  va_end(args);

  return;
}

/*
 * \brief function to print log section to fd
 * \param level the log level of the message to be logged
 * \param format String to be logged
 * \param stream stream where the section should be printed
 * \param header string to be printed as header
 * \param ... additional arguments for format
 */
void log_section(log_level_t level, FILE *stream, const char *header,
    const char *format, ...) {

  va_list args;

  va_start(args, format);

  if (log_level(0) >= level) {

    if (level > LOG_INFO) {

      char lvl_marker[24];
      get_log_level_str(level, lvl_marker);

      fprintf(stream, "%s: ", lvl_marker);
    }

    fprintf(stream, "\n**** %s ****\n", header);
    vfprintf(stream, format, args);
    fprintf(stream, "\n");
  }

  va_end(args);

}
