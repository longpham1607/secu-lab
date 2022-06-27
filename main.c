#include "rsa.c"

int main () 
{
/********************************************* Task 1: Deriving the Private Key *********************************************/
	// Initialize variable for task 1
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	// Assign p value
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	
	// Assign q value
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	// Assign e value
	BN_hex2bn(&e, "0D88C3");

	BIGNUM* privateKeyTask1 = getRSAPrivateKey(p, q, e);
	printBigNum("The private key task 1: ", privateKeyTask1);
	printf("\n");


/********************************************* Task 2: Encrypting a Message *********************************************/

	// Private Key, Public Key, Modulo for all task
	BIGNUM* privateKey = BN_new();
	BIGNUM* publicKey = BN_new();
	BIGNUM* modulo = BN_new();	

	// Initialize variable for task 2
	BIGNUM* messageTask2 = BN_new();
	BIGNUM* encodedMessageTask2 = BN_new();
	BIGNUM* decodedMessageTask2 = BN_new();

	// Assign value to the private key
	BN_hex2bn(&privateKey, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign value to the public key
	BN_hex2bn(&publicKey, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Assign value to the modulus 
	BN_hex2bn(&modulo, "010001");

	/*
	According to the RSA algorithm, first we need to convert this message into hex. 
	Then we convert the hex into a BIGNUM. After using the script python this is what we 
	get: "4120746f702073656372657421" from a text message: "A top secret!"
	*/
	BN_hex2bn(&messageTask2, "4120746f702073656372657421");

	// Encrypt the message 
	encodedMessageTask2 = RSAEncrypt(messageTask2, modulo, publicKey);
	printBigNum("The encrypted message for task 2: ", encodedMessageTask2);
	printf("\n");
	
	// Decrypt the message 
	decodedMessageTask2 = RSADecrypt(encodedMessageTask2, privateKey, publicKey);
	printf("The decrypted message for task 2: ");
	printHexString(BN_bn2hex(decodedMessageTask2));
	printf("\n");

/********************************************* Task 3: Decrypting a message *********************************************/

	// Initialize variable for task 3
	BIGNUM* encodedMessageTask3 = BN_new();
	BIGNUM* decodedMessageTask3 = BN_new();

	// The ciphertext was given in hexadecimal format. We need to convert it to a BIGNUM. 
	BN_hex2bn(&encodedMessageTask3, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	
	// Decrypt the message
	decodedMessageTask3 = RSADecrypt(encodedMessageTask3, privateKey, publicKey);
	printf("The decrypted message for task 3: ");
	printHexString(BN_bn2hex(decodedMessageTask3));
	printf("\n");

/********************************************* Task 4: Signing a Message *********************************************/

	// Initialize variable for task 3
	BIGNUM* encodedMessageOriginTask4 = BN_new();
	BIGNUM* encodedMessageModifiedTask4 = BN_new();
	

	BIGNUM* messageOriginTask4 = BN_new();
	BIGNUM* messageModifiedTask4 = BN_new();


	BIGNUM* decodedMessageOriginTask4 = BN_new();
	BIGNUM* decodedMessageModifiedTask4 = BN_new();

	// After converting the message into hex. We need to convert it to a BIGNUM.
	BN_hex2bn(&messageOriginTask4, "49206f776520796f752024333030302e");
	BN_hex2bn(&messageModifiedTask4, "49206f776520796f752024323030302e");
	
	
	// Encrypt the origin message by using the given privateKey and publicKey from task 2
	encodedMessageOriginTask4 = RSAEncrypt(messageOriginTask4, privateKey, publicKey);
	printBigNum("The signature for origin message task 4: ", encodedMessageOriginTask4);
	printf("\n");

	// Encrypt the modified message by using the given privateKey and publicKey from task 2
	encodedMessageModifiedTask4 = RSAEncrypt(messageModifiedTask4, privateKey, publicKey);
	printBigNum("The signature for modified message task 4: ", encodedMessageModifiedTask4);
	printf("\n");


	// We decrypt the message to verify it correct or wrong.

	// Decrypt the origin message
	decodedMessageOriginTask4 = RSADecrypt(encodedMessageOriginTask4, modulo, publicKey);
	printf("The message for task 4: ");
	printHexString(BN_bn2hex(decodedMessageOriginTask4));
	printf("\n");

	// Decrypt the modified message
	decodedMessageModifiedTask4 = RSADecrypt(encodedMessageModifiedTask4, modulo, publicKey);
	printf("The message for task 4: ");
	printHexString(BN_bn2hex(decodedMessageModifiedTask4));
	printf("\n");

/********************************************* Task 5: Verifying a Signature *********************************************/


/********************************************* Task 6: Manually Verifying an X.509 Certificate *********************************************/



    return 0;
}