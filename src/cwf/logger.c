
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

void logger(const char* tag, const char* message, ...) {

	time_t now;
	time(&now);

	va_list ap;

	fprintf(stderr, "%s [%s] ", ctime(&now), tag);
	va_start(ap, message);
	vfprintf(stderr, message, ap);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(ap);


}

