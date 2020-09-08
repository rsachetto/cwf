//
// Created by sachetto on 08/09/2020.
//

#include "ssl_helper.h"

void initialize_SSL() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void destroy_SSL() {
    ERR_free_strings();
    EVP_cleanup();
}

void shutdown_SSL(SSL *cSSL) {
    SSL_shutdown(cSSL);
    SSL_free(cSSL);
}

SSL_CTX * new_SSL_CTX(char *cert_path, char *key_path) {

    SSL_CTX *sslctx;

    sslctx = SSL_CTX_new(TLS_server_method());

    if (!sslctx) {
        fprintf(stderr, "Error creating the context.\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);

    if(SSL_CTX_use_certificate_file(sslctx, cert_path, SSL_FILETYPE_PEM) <=0){
        printf("Error setting the certificate file %s.\n", cert_path);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(sslctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        printf("Error setting the key file %s.\n", key_path);
        exit(EXIT_FAILURE);
    }

    return sslctx;

}