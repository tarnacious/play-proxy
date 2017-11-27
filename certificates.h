#ifndef CERTIFICATES_H
#define CERTIFICATES_H

#include <openssl/rsa.h>
#include <openssl/pem.h>

RSA* generate_rsa();
int generate_csr(RSA *rsa, char* host);
int sign(char* request_str);

#endif
