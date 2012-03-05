#include "shared.h"
#ifndef NULL
#define NULL ((void*) 0)
#endif
//#define UINT32_C(x) ((uint32_t) x)
//#define UINT64_C(x) ((uint64_t) x)

//#ifndef UINT32_MAX
//#define UINT32_MAX (UINT32_C(0xffffffffU))
//#endif

//#ifndef UINT64_MAX
//#define UINT64_MAX (UINT64_C(0xffffffffffffffffULL))
//#endif

//padding.h
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
//typedef signed long long int64_t;
typedef unsigned int size__t;
#define UINT32_C(x) ((uint32_t) x)
#define UINT64_C(x) ((uint64_t) x)
#ifndef UINT32_MAX
#define UINT32_MAX (UINT32_C(0xffffffffU))
#endif 

#ifndef UINT64_MAX
#define UINT64_MAX (UINT64_C(0xffffffffffffffffULL))
#endif

#define UINT64_RSHIFT(v, shiftby) (((uint64_t)(v)) >> (shiftby))
#define UINT64_MULT32(v, multby)  (((uint64_t)(v)) * ((uint32_t)(multby)))



extern const uint8_t paddingRSA1024_SHA1[];
extern const uint8_t paddingRSA1024_SHA256[];
extern const uint8_t paddingRSA1024_SHA512[];
extern const uint8_t paddingRSA2048_SHA1[];
extern const uint8_t paddingRSA2048_SHA256[];
extern const uint8_t paddingRSA2048_SHA512[];
extern const uint8_t paddingRSA4096_SHA1[];
extern const uint8_t paddingRSA4096_SHA256[];
extern const uint8_t paddingRSA4096_SHA512[];
extern const uint8_t paddingRSA8192_SHA1[];
extern const uint8_t paddingRSA8192_SHA256[];
extern const uint8_t paddingRSA8192_SHA512[];

extern const int kNumAlgorithms;

extern const int digestinfo_size_map[];
extern const int siglen_map[];
extern const uint8_t* padding_map[];
extern const int padding_size_map[];
extern const int hash_type_map[];
extern const int hash_size_map[];
extern const int hash_blocksize_map[];
extern const uint8_t* hash_digestinfo_map[];
extern const char* algo_strings[];


//rsa.h

/* Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */


//#include "sysincludes.h"
#define RSA1024NUMBYTES 128  /* 1024 bit key length */
#define RSA2048NUMBYTES 256  /* 2048 bit key length */
#define RSA4096NUMBYTES 512  /* 4096 bit key length */
#define RSA8192NUMBYTES 1024  /* 8192 bit key length */

#define RSA1024NUMWORDS (RSA1024NUMBYTES / sizeof(uint32_t))
#define RSA2048NUMWORDS (RSA2048NUMBYTES / sizeof(uint32_t))
#define RSA4096NUMWORDS (RSA4096NUMBYTES / sizeof(uint32_t))
#define RSA8192NUMWORDS (RSA8192NUMBYTES / sizeof(uint32_t))

typedef struct RSAPublicKey {
	uint32_t len;  /* Length of n[] in number of uint32_t */
	uint32_t n0inv;  /* -1 / n[0] mod 2^32 */
	uint32_t n[32];  /* modulus as little endian array */
	uint32_t rr[32]; /* R^2 as little endian array */
	unsigned int algorithm; /* Algorithm to use when verifying with the key */
} RSAPublicKey;

/* Verify a RSA PKCS1.5 signature [sig] of [sig_type] and length [sig_len]
 * against an expected [hash] using [key]. Returns 0 on failure, 1 on success.
 */
int RSAVerify(const RSAPublicKey key,
		const uint8_t* sig,
		const uint32_t sig_len,
		const uint8_t sig_type,
		const uint8_t* hash);

/* Perform RSA signature verification on [buf] of length [len] against expected
 * signature [sig] using signature algorithm [algorithm]. The public key used
 * for verification can either be in the form of a pre-process key blob
 * [key_blob] or RSAPublicKey structure [key]. One of [key_blob] or [key] must
 * be non-NULL, and the other NULL or the function will fail.
 *
 * Returns 1 on verification success, 0 on verification failure or invalid
 * arguments.
 *
 * Note: This function is for use in the firmware and assumes all pointers point
 * to areas in the memory of the right size.
 *
 */
/*int RSAVerifyBinary_f(const uint8_t* key_blob,
  const RSAPublicKey* key,
  const uint8_t* buf,
  uint64_t len,
  const uint8_t* sig,
  unsigned int algorithm);*/

/* Version of RSAVerifyBinary_f() where instead of the raw binary blob
 * of data, its digest is passed as the argument. */
/*int RSAVerifyBinaryWithDigest_f(const uint8_t* key_blob,
  const RSAPublicKey* key,
  const uint8_t* digest,
  const uint8_t* sig,
  unsigned int algorithm);*/


/* ----Some additional utility functions for RSA.---- */

/* Returns the size of a pre-processed RSA public key in
 * [out_size] with the algorithm [algorithm].
 *
 * Returns 1 on success, 0 on failure.
 */
//uint64_t RSAProcessedKeySize(uint64_t algorithm, uint64_t* out_size);

/* Allocate a new RSAPublicKey structure and initialize its pointer fields to
 * NULL */
//RSAPublicKey* RSAPublicKeyNew(void);

/* Deep free the contents of [key]. */
//void RSAPublicKeyFree(RSAPublicKey* key);

/* Create a RSAPublic key structure from binary blob [buf] of length
 * [len].
 *
 * Caller owns the returned key and must free it.
 */
RSAPublicKey RSAPublicKeyFromBuf(const uint8_t* buf, uint64_t len);




/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Helper functions/wrappers for memory allocations, manipulation and
 * comparison.
 */



/* Track remaining data to be read in a buffer. */
typedef struct MemcpyState {
	uint8_t* remaining_buf;
	uint64_t remaining_len;  /* Remaining length of the buffer. */
	uint8_t overrun;  /* Flag set to 1 when an overrun occurs. */
} MemcpyState;

/* Initialize a stateful buffer struct to point to the buffer, with
 * the specified remaining length in bytes. */
void StatefulInit(MemcpyState* state, void* buf, uint64_t len);

/* Skip [len] bytes only if there's enough data to skip according
 * to [state].
 * On success, return a meaningless but non-NULL pointer and updates [state].
 * On failure, return NULL, set state->overrun to 1.
 *
 * Useful for iterating through a binary blob to populate a struct. After the
 * first failure (buffer overrun), successive calls will always fail.
 */
void* StatefulSkip(MemcpyState* state, uint64_t len);

/* Copy [len] bytes into [dst] only if there's enough data to read according
 * to [state].
 * On success, return [dst] and update [state].
 * On failure, return NULL, set state->overrun to 1.
 *
 * Useful for iterating through a binary blob to populate a struct. After the
 * first failure (buffer overrun), successive calls will always fail.
 */
void* StatefulMemcpy(MemcpyState* state, void* dst, uint64_t len);

/* Like StatefulMemcpy() but copies in the opposite direction, populating
 * data from [src] into the buffer encapsulated in state [state].
 * On success, return [src] and update [state].
 * On failure, return NULL, set state->overrun to 1.
 *
 * Useful for iterating through a structure to populate a binary blob. After the
 * first failure (buffer overrun), successive calls will always fail.
 */
const void* StatefulMemcpy_r(MemcpyState* state, const void* src, uint64_t len);

/* Like StatefulMemcpy_r() but fills a portion of the encapsulated buffer with
 * a constant value.
 * On success, return a meaningless but non-NULL pointer and updates [state].
 * On failure, return NULL, set state->overrun to 1.
 *
 * After the first failure (buffer overrun), successive calls will always fail.
 */
const void* StatefulMemset_r(MemcpyState* state, const uint8_t val,
		uint64_t len);









/* Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Helper functions/wrappers for memory allocations, manipulation and
 * comparison.
 */


//#include "sysincludes.h"


/* Combine [msw] and [lsw] uint16s to a uint32_t with its [msw] and
 * [lsw] forming the most and least signficant 16-bit words.
 */
#define CombineUint16Pair(msw,lsw) (((uint32_t)(msw) << 16) |   \
		(((lsw)) & 0xFFFF))
/* Return the minimum of (a) or (b). */
#define Min(a, b) (((a) < (b)) ? (a) : (b))

/* Compare [n] bytes in [src1] and [src2]
 * Returns an integer less than, equal to, or greater than zero if the first [n]
 * bytes of [src1] is found, respectively, to be less than, to match, or be
 * greater than the first n bytes of [src2]. */
int Memcmp(const void* src1, const void* src2, size__t n);

/* Copy [n] bytes from [src] to [dest]. */
void* Memcpy(void* dest, const void* src, uint64_t n);


/* Implementations of the functions below must be built as part of the firmware
 * and defined in lib/utility.c */

/* Set [n] bytes starting at [s] to [c].  Returns dest. */
void* Memset(void* dest, const uint8_t c, uint64_t n);

/* Compare [n] bytes starting at [s1] with [s2] and return 0 if they
 * match, 1 if they don't.  Returns 0 if n=0, since no bytes mismatched.
 * Time taken to perform the comparison is only dependent on [n] and
 * not on the relationship of the match between [s1] and [s2].
 *
 * Note that unlike Memcmp(), this only indicates inequality, not
 * whether s1 is less than or greater than s2.
 */
int SafeMemcmp(const void* s1, const void* s2, size__t n);

/* Buffer size required to hold the longest possible output of
 * Uint64ToString() - that is, Uint64ToString(~0, 2). */
#define UINT64_TO_STRING_MAX 65

/* Convert a value to a string in the specified radix (2=binary, 10=decimal,
 * 16=hex) and store it in <buf>, which is <bufsize> chars long.  If
 * <zero_pad_width>, left-pads the string to at least that width with '0'.
 * Returns the length of the stored string, not counting the terminating
 * null. */
uint32_t Uint64ToString(char *buf, uint32_t bufsize, uint64_t value,
		uint32_t radix, uint32_t zero_pad_width);

/* Concatenate <src> onto <dest>, which has space for <destlen> characters
 * including the terminating null.  Note that <dest> will always be
 * null-terminated if <destlen> > 0.  Returns the number of characters
 * used in <dest>, not counting the terminating null. */
uint32_t Strncat(char *dest, const char *src, uint32_t destlen);

/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* SHA-1, 256 and 512 functions. */


//#include "sysincludes.h"
/*Enable/Disable the log flag*/
#define debuglog 0

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

typedef struct SHA1_CTX {
	uint64_t count;
	uint32_t state[5];
#if defined(HAVE_ENDIAN_H) && defined(HAVE_LITTLE_ENDIAN)
	union {
		uint8_t b[64];
		uint32_t w[16];
	} buf;
#else
	uint8_t buf[64];
#endif
} SHA1_CTX;

typedef struct {
	uint32_t h[8];
	uint32_t tot_len;
	uint32_t len;
	uint8_t block[2 * SHA256_BLOCK_SIZE];
	uint8_t buf[SHA256_DIGEST_SIZE];  /* Used for storing the final digest. */
} SHA256_CTX;

typedef struct {
	uint64_t h[8];
	uint32_t tot_len;
	uint32_t len;
	uint8_t block[2 * SHA512_BLOCK_SIZE];
	uint8_t buf[SHA512_DIGEST_SIZE];  /* Used for storing the final digest. */
} SHA512_CTX;


void SHA1_init(SHA1_CTX* ctx);
void SHA1_update(SHA1_CTX* ctx, const uint8_t* data, uint64_t len);
uint8_t* SHA1_final(SHA1_CTX* ctx);

void SHA256_init(SHA256_CTX* ctx);
void SHA256_update(SHA256_CTX* ctx, const uint8_t* data, uint32_t len);
uint8_t* SHA256_final(SHA256_CTX* ctx);

void SHA512_init(SHA512_CTX* ctx);
void SHA512_update(SHA512_CTX* ctx, const uint8_t* data, uint32_t len);
uint8_t* SHA512_final(SHA512_CTX* ctx);

/* Convenience function for SHA-1.  Computes hash on [data] of length [len].
 * and stores it into [digest]. [digest] should be pre-allocated to
 * SHA1_DIGEST_SIZE bytes.
 */
uint8_t* SHA1(const uint8_t* data, uint64_t len, uint8_t* digest);

/* Convenience function for SHA-256.  Computes hash on [data] of length [len].
 * and stores it into [digest]. [digest] should be pre-allocated to
 * SHA256_DIGEST_SIZE bytes.
 */
uint8_t* SHA256(const uint8_t* data, uint64_t len, uint8_t* digest);

/* Convenience function for SHA-512.  Computes hash on [data] of length [len].
 * and stores it into [digest]. [digest] should be pre-allocated to
 * SHA512_DIGEST_SIZE bytes.
 */
uint8_t* SHA512(const uint8_t* data, uint64_t len, uint8_t* digest);

/* Function to calculate sha1 of a file */
void hash_calculate(char *filename,uint8_t sha1_result[],uint8_t hashbuf[],uint8_t sig[]);

/* Function to calculate sha1 of a buffer of any lengtg */
void hashbuf_calculate(uint8_t *buf);


/*---- Utility functions/wrappers for message digests. */

#define SHA1_DIGEST_ALGORITHM 0
#define SHA256_DIGEST_ALGORITHM 1
#define SHA512_DIGEST_ALGORITHM 2

/* A generic digest context structure which can be used to represent
 * the SHA*_CTX for multiple digest algorithms.
 */
typedef struct DigestContext {
	SHA1_CTX* sha1_ctx;
	SHA256_CTX* sha256_ctx;
	SHA512_CTX* sha512_ctx;
	int algorithm;  /* Hashing algorithm to use. */
} DigestContext;

/* Wrappers for message digest algorithms. These are useful when the hashing
 * operation is being done in parallel with something else. DigestContext tracks
 * and stores the state of any digest algorithm (one at any given time).
 */

/* Initialize a digest context for use with signature algorithm [algorithm]. */
void DigestInit(DigestContext* ctx, int sig_algorithm);
void DigestUpdate(DigestContext* ctx, const uint8_t* data, uint32_t len);

/* Caller owns the returned digest and must free it. */
uint8_t* DigestFinal(DigestContext* ctx);

/* Returns the appropriate digest for the data in [input_file]
 * based on the signature [algorithm].
 * Caller owns the returned digest and must free it.
 */
uint8_t* DigestFile(char* input_file, int sig_algorithm);

/* Returns the appropriate digest of [buf] of length
 * [len] based on the signature [algorithm].
 * Caller owns the returned digest and must free it.
 */
uint8_t* DigestBuf(const uint8_t* buf, uint64_t len, int sig_algorithm);


