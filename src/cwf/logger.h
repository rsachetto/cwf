#ifndef __LOGGER_H
#define __LOGGER_H

#define LOG_ERROR(format, ...)                                                                                                                                 \
    fprintf(stderr, "\033[1;31m");                                                                                                                             \
    logger("ERR", format, __VA_ARGS__);                                                                                                                        \
    fprintf(stderr, "\033[0m");

#define LOG_INFO(format, ...)                                                                                                                                  \
    fprintf(stderr, "\033[1;34m");                                                                                                                             \
    logger("INFO", format, __VA_ARGS__);                                                                                                                       \
    fprintf(stderr, "\033[0m");

#define LOG_WARN(format, ...)                                                                                                                                  \
    fprintf(stderr, "\033[1;33m");                                                                                                                             \
    logger("WARN", format, __VA_ARGS__);                                                                                                                       \
    fprintf(stderr, "\033[0m");


void logger(const char *tag, const char *message, ...);

#endif /* __LOGGER_H */
