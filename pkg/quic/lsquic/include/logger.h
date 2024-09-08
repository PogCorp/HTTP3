#include <stdio.h>
#pragma once

static const char* keylog_dir = NULL;

void Log(const char* fmt, ...);
void set_logger_fd(FILE* file);
