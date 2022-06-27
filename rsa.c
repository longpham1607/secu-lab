#include "rsa.h"

///////////////////////////////////////////////////// Supported function////////////////////////////////////////////
void printBigNum(char* msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}


BIGNUM* getRSAPrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* pMinusOne = BN_new();
	BIGNUM* qMinusOne = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* productOfTwoNum = BN_new();
	BIGNUM* result = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(productOfTwoNum, pMinusOne, qMinusOne, ctx);

	BN_mod_inverse(result, e, productOfTwoNum, ctx);

	//Free temporary variable
	BN_CTX_free(ctx);

	return result;
}

BIGNUM* RSAEncrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* enc = BN_new();
	BN_mod_exp(enc, message, mod, pub_key, ctx);
	BN_CTX_free(ctx);
	return enc;
}

BIGNUM* RSADecrypt(BIGNUM* enc, BIGNUM* priv_key, BIGNUM* pub_key)
{

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* dec = BN_new();
	BN_mod_exp(dec, enc, priv_key, pub_key, ctx);
	BN_CTX_free(ctx);
	return dec;
}

