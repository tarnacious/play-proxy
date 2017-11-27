#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <strings.h>
#include "certificates.h"
#include "utils.h"

#define BUFFER_SIZE 1024


#include <openssl/rsa.h>
#include <openssl/pem.h>

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cert.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    printf("\r\nStart Server\r\n");

    int sock;
    SSL_CTX *ctx;

    init_openssl();

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        char buffer[BUFFER_SIZE];
        int bytes_read;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        // lets just assume, we can read the whole thing and it fits in the buffer :)
        bzero(buffer, BUFFER_SIZE);
        fprintf(stderr, "Reading header\n");
        read(client, buffer, BUFFER_SIZE - 1);
        fprintf(stderr, "%s\r\n", buffer);

        char *result = find_re("^CONNECT ([^:]*)", buffer, 1);
        printf("\r\nHost Found: %s\r\n", result);

        RSA *rsa = generate_rsa();
        generate_csr(rsa, result);
        char *mybuffer = read_file("csr.pem");
        sign(mybuffer);

        // lets just assume it was a HTTP/1.1 request and write a response
        const char message[] = "HTTP/1.1 200 OK\r\n\r\n";
        write(client, message, strlen(message));

        ctx = create_context();
        configure_context(ctx);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            bzero(buffer, BUFFER_SIZE);
            bytes_read = SSL_read(ssl, buffer, 100);
            fprintf(stderr, "bytes read: %d\r\n\r\n", bytes_read);
            fprintf(stderr, "%s\r\n\r\n", buffer);
            bzero(buffer, BUFFER_SIZE);

            const char reply[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            fprintf(stderr, "writing response:\r\n%s", reply);
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_CTX_free(ctx);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    cleanup_openssl();
}
