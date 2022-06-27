#ifndef __RSA_H_
#define __RSA_H_
#include <openssl/bn.h>
#include <string.h>
BIGNUM *getRSAPrivateKey(BIGNUM *p, BIGNUM *q, BIGNUM *e);
BIGNUM *RSAEncrypt(BIGNUM *message, BIGNUM *modulo, BIGNUM *publicKey);
BIGNUM *RSADecrypt(BIGNUM *encryptedMessage, BIGNUM *privateKey, BIGNUM *publicKey);
void printBigNum(char *message, BIGNUM *number);
void printHexString(char* string);
int hex_to_int(char c);
int hex_to_ascii(const char c, const char d);
#endif
