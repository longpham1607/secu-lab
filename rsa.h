#ifndef __RSA_H_
#define __RSA_H_
#include <openssl/bn.h>
BIGNUM *getRSAPrivateKey(BIGNUM *p, BIGNUM *q, BIGNUM *e);
BIGNUM *RSAEncrypt(BIGNUM *message, BIGNUM *modulo, BIGNUM *publicKey);
BIGNUM *RSADecrypt(BIGNUM *encrypted_message, BIGNUM *priv_key, BIGNUM *pub_key);
void printBigNum(char *msg, BIGNUM *a);
#endif
