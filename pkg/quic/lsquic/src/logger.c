#include <logger.h>

#include <stdarg.h>
#include <stdio.h>
#pragma once

static FILE *log_stream = NULL;

void Log(const char *fmt, ...) {
  if (log_stream) {
    va_list ap;
    fprintf(log_stream, "LOG: ");
    va_start(ap, fmt);
    (void)vfprintf(log_stream, fmt, ap);
    va_end(ap);
    fprintf(log_stream, "\n");
  }
}

void set_logger_fd(FILE *file) { log_stream = file; }