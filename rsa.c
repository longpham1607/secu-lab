#include "rsa.h"

/********************************************* Supported Function *********************************************/
void printBigNum(char *message, BIGNUM *number)
{
    char * numberString = BN_bn2hex(number);
    printf("%s 0x%s\n", message, numberString);
    OPENSSL_free(numberString);
}

void printHexString(char* string)
{
	int length = strlen(string);
	char buffer = 0;
	if (length % 2 != 0) {
		printf("%s\n", "The length is invalid");
		return;
	}
	for(int i = 0; i < length; i++) {
		if(i % 2 != 0)
			printf("%c", hex_to_ascii(buffer, string[i]));
		else
		    buffer = string[i];
	}
	printf("\n");
}

int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

int hex_to_ascii(const char c, const char d)
{
	int high = hex_to_int(c) * 16;
	int low = hex_to_int(d);
	return high+low;
}
/********************************************* Required Function *********************************************/

BIGNUM* getRSAPrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* pMinusOne = BN_new();
	BIGNUM* qMinusOne = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* productOfTwoNum = BN_new();
	BIGNUM* result = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(pMinusOne, p, one);
	BN_sub(qMinusOne, q, one);
	BN_mul(productOfTwoNum, pMinusOne, qMinusOne, ctx);

	BN_mod_inverse(result, e, productOfTwoNum, ctx);

	//Free temporary variable
	BN_CTX_free(ctx);

	return result;
}

BIGNUM *RSAEncrypt(BIGNUM *message, BIGNUM *modulo, BIGNUM *publicKey)
{
	//Temporary variable to store BIGNUM
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM* encryptedMessage = BN_new();

	BN_mod_exp(encryptedMessage, message, modulo, publicKey, ctx);

	//Free temporary variable
	BN_CTX_free(ctx);

	return encryptedMessage;
}

BIGNUM *RSADecrypt(BIGNUM *encryptedMessage, BIGNUM *privateKey, BIGNUM *publicKey)
{
	//Temporary variable to store BIGNUM
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM* decryptedMessage = BN_new();

	BN_mod_exp(decryptedMessage, encryptedMessage, privateKey, publicKey, ctx);

	//Free temporary variable
	BN_CTX_free(ctx);
	return decryptedMessage;
}

