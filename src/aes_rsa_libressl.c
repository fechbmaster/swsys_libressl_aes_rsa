#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <locale.h>

//Mbed LibreSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#define LENGTH 128
#define SIZE (LENGTH * sizeof(char))
#define DEBUG 0

#define AES_GCM
#define RSA

#define RSA_KEY_LENGTH 2048

#define MEASURE_TIME

struct timespec start = { 0, 0 };
struct timespec end = { 0, 0 };

extern unsigned int OPENSSL_ia32cap_P[];
# define AESNI_CAPABLE (OPENSSL_ia32cap_P[1]&(1<<(57-32)))

void disableIntelNI() {

}

void readRandomData(unsigned char* buffer, size_t size, int bytes) {
    int fileDescriptor = open("/dev/urandom", O_RDONLY);
    read(fileDescriptor, buffer, size);
    close(fileDescriptor);
    int i;
    for (i = 0; i < bytes; i++) {
        buffer[i] = (buffer[i] % 93) + 33;
    }
    buffer[bytes - 1] = '\0';
}

unsigned char* encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx;

    int len = plaintext_len + AES_BLOCK_SIZE;

    int ciphertext_len;

    unsigned char* ciphertext = malloc(len);

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the encryption */
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    /* Encrypt */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    /* Finalise */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx;

    int len = ciphertext_len;

    int plaintext_len;

    unsigned char* decryptedtext = malloc(len);

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedtext;
}

EVP_PKEY* createRSA(unsigned char* filename, int public) {
    EVP_PKEY *pkey = NULL;
    FILE *file = fopen(filename,"rt");
    if (file == NULL) {
        printf("Unable to open file %s \n",filename);
        return 0;
    }

    if (public) {
        if (!(pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL)))
            printSSLError("Error setting public key to EVP_KEY");

    }
    else {
        if (!(pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL)))
            printSSLError("Error setting private key to EVP_KEY");
    }

    return pkey;
}

unsigned char* encryptRSA(unsigned char *plaintext, int plaintext_len, unsigned char *key, int padding, int *encrypt_len) {
    EVP_PKEY_CTX *ctx;

    EVP_PKEY * pb_key = createRSA(key, 1);

    ctx = EVP_PKEY_CTX_new(pb_key, NULL);
    if (!ctx)
        printSSLError("Error in creating encrypt context");

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        printSSLError("Error in initialising encrypt");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
        printSSLError("Error in setting padding");

    size_t outlen = 0;

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0)
        printSSLError("Error in setting encrypt outlen");

    unsigned char* ciphertext = malloc(outlen);

    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, plaintext_len) <= 0)
        printSSLError("Error in encrypting message");

    *encrypt_len = outlen;

    /* cleanup */
    EVP_PKEY_free(pb_key);
    EVP_PKEY_CTX_free(ctx);

    return ciphertext;

}

unsigned char* decryptRSA(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, int padding) {
    EVP_PKEY_CTX *ctx;

    EVP_PKEY * p_key = createRSA(key, 0);

    ctx = EVP_PKEY_CTX_new(p_key, NULL);
    if (!ctx)
        printSSLError("Error in creating encrypt context");

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        printSSLError("Error in initialising encrypt");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
        printSSLError("Error in setting padding");

    size_t outlen = 0;

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0)
        printSSLError("Error setting decrypt outlen");

    unsigned char* decryptedtext = malloc(outlen);

    if (EVP_PKEY_decrypt(ctx, decryptedtext, &outlen, ciphertext, ciphertext_len) <= 0)
        printSSLError("Error in decrypting message");

    /* cleanup */
    EVP_PKEY_free(p_key);
    EVP_PKEY_CTX_free(ctx);

    return decryptedtext;
}

void printSSLError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

int main(int arc, char *argv[]) {
    int length = LENGTH;
    double duration = 0;

    unsigned char* plaintext = malloc(SIZE);
    unsigned char* ciphertext;
    unsigned char* decryptedtext;

    readRandomData(plaintext, SIZE, LENGTH);

    disableIntelNI();

    /*Initialise Key for AES_GCM */
    #ifdef AES_GCM
    const EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher;
    const EVP_MD *digest;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *password = "password";
    const unsigned char salt[] = {1234, 5678};


    cipher = EVP_aes_192_gcm();
    digest = EVP_sha256();

    if(!EVP_BytesToKey(cipher, digest, salt,
        password, strlen(password), 5, key, iv))
    {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    int i;

    if (DEBUG) {
        printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
        printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");
    }

    #ifdef MEASURE_TIME
    for (i = 0; i < 10000; i ++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    #endif // MEASURE_TIME

    ciphertext = encrypt(plaintext, length, key, iv, cipher);

    decryptedtext = decrypt(ciphertext, length, key, iv, cipher);

    #ifdef MEASURE_TIME
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration += (double)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000);
    }
    printf("AES average duration: %f us\n", duration / 10000);
    #endif // MEASURE_TIME

    if (DEBUG) {
    	printf("Plaintext:\n");
        BIO_dump_fp (stdout, plaintext, LENGTH);
    }

    if (DEBUG) {
    	printf("Ciphertext:\n");
        BIO_dump_fp (stdout, ciphertext, LENGTH);
    }

    if (DEBUG) {
    	printf("Decrypted text:\n");
        BIO_dump_fp (stdout, decryptedtext, LENGTH);
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(decryptedtext);

    #endif // AES_GCM

    #ifdef RSA
    int padding = RSA_PKCS1_PADDING;
    unsigned char *private_key;
    unsigned char *public_key;
    if (RSA_KEY_LENGTH == 2048) {
        if (LENGTH > (RSA_KEY_LENGTH / 8 - 11)) {
            printf("Length of message is not supported in RSA encryption. Must be less than (256-11)! \n");
            abort();
        }
        private_key = "private_2048.pem";
        public_key = "public_2048.pem";
    }
    else if (RSA_KEY_LENGTH == 4096) {
        if (LENGTH > (RSA_KEY_LENGTH / 8 -11)) {
            printf("Length of message is not supported in RSA encryption. Must be less than (512-11)! \n");
            abort();
        }
        private_key = "private_4096.pem";
        public_key = "public_4096.pem";
    }
    else {
        printf("RSA_KEY_LENGTH not supported. Supported are 2048 and 4096! \n");
        abort();
    }
    int encrypt_len = 0;

    #ifdef MEASURE_TIME
    for (i = 0; i < 1000; i ++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    #endif // MEASURE_TIME

    ciphertext = encryptRSA(plaintext, length, public_key, padding, &encrypt_len);

    decryptedtext = decryptRSA(ciphertext, encrypt_len, private_key, padding);

    #ifdef MEASURE_TIME
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration += (double)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000);
    }
    printf("RSA average duration: %f us\n", duration / 1000);
    #endif // MEASURE_TIME

    if (DEBUG) {
    	printf("Plaintext:\n");
        BIO_dump_fp (stdout, plaintext, LENGTH);
    }

    if (DEBUG) {
    	printf("Ciphertext:\n");
        BIO_dump_fp (stdout, ciphertext, LENGTH);
    }


    if (DEBUG) {
    	printf("Decrypted text:\n");
        BIO_dump_fp (stdout, decryptedtext, LENGTH);
    }


    /* Clean up */
    free(ciphertext);
    free(decryptedtext);

    #endif // RSA

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    free(plaintext);

    if(AESNI_CAPABLE)
        printf("Used intel aes-ni. \n");

    return 0;
}
