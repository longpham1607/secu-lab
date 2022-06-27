#include "rsa.c"

int main () 
{
	// Task 1: Deriving the Private Key

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	// Assign p value
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	
	// Assign q value
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	// Assign e value
	BN_hex2bn(&e, "0D88C3");

	BIGNUM* private_key = getRSAPrivateKey(p, q, e);
	printBigNum("The private key task 1: ", private_key);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// Task 2: Encrypting a Message
	
    return 0;
}