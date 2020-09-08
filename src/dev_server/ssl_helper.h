//
// Created by sachetto on 08/09/2020.
//

#ifndef CWF_SSL_HELPERS_H
#define CWF_SSL_HELPERS_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void initialize_SSL();
void destroy_SSL();
void shutdown_SSL(SSL *cSSL);
SSL_CTX * new_SSL_CTX(char * cert_file, char *key_file);

#endif // CWF_SSL_HELPERS_H
