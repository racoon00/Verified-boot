/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Implementation of RSA signature verification which uses a pre-processed
 * key for computation. The code extends Android's RSA verification code to
 * support multiple RSA key lengths and hash digest algorithms.
 */

//#include "cryptolib.h"
//#include "vboot_api.h"
//#include "utility.h"
//#include <stdlib.h>
#include "common.h"
//#include "shared.h"
//#include <stdio.h>
//#include <string.h>
/* a[] -= mod */
static void subM(const RSAPublicKey key, uint32_t *a) {
//	int64_t A = 0;
	signed long long A=0;
	uint32_t i;
	for (i = 0; i < key.len; ++i) {
		A += (uint64_t)a[i] - key.n[i];
		a[i] = (uint32_t)A;
		A >>= 32;
	}
}

/* return a[] >= mod */
static int geM(const RSAPublicKey key, uint32_t *a) {
	uint32_t i;
	for (i = key.len; i;) {
		--i;
		if (a[i] < key.n[i]) return 0;
		if (a[i] > key.n[i]) return 1;
	}
	return 1;  /* equal */
}

/* montgomery c[] += a * b[] / R % mod */
static void montMulAdd(const RSAPublicKey key,
		uint32_t* c,
		const uint32_t a,
		const uint32_t* b) {
	uint64_t A = UINT64_MULT32(a, b[0]) + c[0];
	uint32_t d0 = (uint32_t)A * key.n0inv;
	uint64_t B = UINT64_MULT32(d0, key.n[0]) + (uint32_t)A;
	uint32_t i;

	for (i = 1; i < key.len; ++i) {
		A = (A >> 32) + UINT64_MULT32(a, b[i]) + c[i];
		B = (B >> 32) + UINT64_MULT32(d0, key.n[i]) + (uint32_t)A;
		c[i - 1] = (uint32_t)B;
	}

	A = (A >> 32) + (B >> 32);

	c[i - 1] = (uint32_t)A;

	if (A >> 32) {
		subM(key, c);
	}
}

/* montgomery c[] = a[] * b[] / R % mod */
static void montMul(const RSAPublicKey key,
		uint32_t* c,
		uint32_t* a,
		uint32_t* b) {
	uint32_t i;
	for (i = 0; i < key.len; ++i) {
		c[i] = 0;
	}
	for (i = 0; i < key.len; ++i) {
		montMulAdd(key, c, a[i], b);
	}
}

/* In-place public exponentiation. (65537}
 * Input and output big-endian byte array in inout.
 */
static void modpowF4(const RSAPublicKey key,
		uint8_t* inout) {
	/*	uint32_t* a = (uint32_t*) malloc(key->len * sizeof(uint32_t));
		uint32_t* aR = (uint32_t*) malloc(key->len * sizeof(uint32_t));
		uint32_t* aaR = (uint32_t*) malloc(key->len * sizeof(uint32_t)); */
	uint32_t a[32];
	uint32_t aR[32];
	uint32_t aaR[32];


	uint32_t* aaa = aaR;  /* Re-use location. */
	int i;

	/* Convert from big endian byte array to little endian word array. */
	for (i = 0; i < (int)key.len; ++i) {
		uint32_t tmp =
			(inout[((key.len - 1 - i) * 4) + 0] << 24) |
			(inout[((key.len - 1 - i) * 4) + 1] << 16) |
			(inout[((key.len - 1 - i) * 4) + 2] << 8) |
			(inout[((key.len - 1 - i) * 4) + 3] << 0);
		a[i] = tmp;
	}

	montMul(key, aR, a, key.rr);  /* aR = a * RR / R mod M   */
	for (i = 0; i < 16; i+=2) {
		montMul(key, aaR, aR, aR);  /* aaR = aR * aR / R mod M */
		montMul(key, aR, aaR, aaR);  /* aR = aaR * aaR / R mod M */
	}
	montMul(key, aaa, aR, a);  /* aaa = aR * a / R mod M */


	/* Make sure aaa < mod; aaa is at most 1x mod too large. */
	if (geM(key, aaa)) {
		subM(key, aaa);
	}

	/* Convert to bigendian byte array */
	for (i = (int)key.len - 1; i >= 0; --i) {
		uint32_t tmp = aaa[i];
		*inout++ = (uint8_t)(tmp >> 24);
		*inout++ = (uint8_t)(tmp >> 16);
		*inout++ = (uint8_t)(tmp >>  8);
		*inout++ = (uint8_t)(tmp >>  0);
	}

	//	free(a);
	//	free(aR);
	//	free(aaR);
}

/* Verify a RSA PKCS1.5 signature against an expected hash.
 * Returns 0 on failure, 1 on success.
 */
int RSAVerify(const RSAPublicKey key,
		const uint8_t *sig,
		const uint32_t sig_len,
		const uint8_t sig_type,
		const uint8_t *hash) {
	uint8_t buf[128];
	const uint8_t* padding;
	int padding_len;
	int success = 1;
	printf("Enter Verify\n");
	printf("sig_len==%u sig_type==%d\n",sig_len,sig_type);
	if ( !sig || !hash)
	{
		printf("invalid key sig hash\n");
		return 0;
	}
	if (sig_len != (key.len * sizeof(uint32_t))) {
		printf("sig of incorrect length\n");
		return 0;
	}

	if (sig_type >= kNumAlgorithms) {
		return 0;
	}

	if (key.len != siglen_map[sig_type] / sizeof(uint32_t)) {
		return 0;
	}

	memcpy(buf, sig, sig_len);
	int j=0;
	for(j=0;j<sig_len;j++)
	{
		printf("old_buf[%d]==%x\n",j,buf[j]);
	}
	modpowF4(key, buf);
	for(j=0;j<sig_len;j++)
	{
		printf("new_buf[%d]==%x\n",j,buf[j]);
	}

	/* Determine padding to use depending on the signature type. */
	padding = padding_map[sig_type];
	padding_len = padding_size_map[sig_type];
	int i=0;
	printf("padding_len==%d",padding_len);
	for(i=0;i<padding_len;i++)
	{
		printf("padding[%d]==%x\n",i,padding[i]);
		printf("buf[%d]==%x\n",i,buf[i]);
	}

	for(i=padding_len;i<sig_len;i++)
	{
		printf("hash[%d]==%x\n",i-padding_len,hash[i-padding_len]);
		printf("buf[%d]==%x\n",i,buf[i]);
	}
	/* Even though there are probably no timing issues here, we use
	 * SafeMemcmp() just to be on the safe side. */

	/* Check pkcs1.5 padding bytes. */
	if (SafeMemcmp(buf, padding, padding_len)) {
		//    VBDEBUG(("In RSAVerify(): Padding check failed!\n"));
		//	printf("Padding check failed\n");
		//    success = 0;
	}

	/* Check hash. */
	if (SafeMemcmp(buf + padding_len, hash, sig_len - padding_len)) {
		//    VBDEBUG(("In RSAVerify(): Hash check failed!\n"));
		printf("Hash check failed\n");
		success  = 0;
	}
	//	free(buf);

	return success;
}
