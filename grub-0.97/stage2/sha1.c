/* Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * SHA-1 implementation largely based on libmincrypt in the the Android
 * Open Source Project (platorm/system/core.git/libmincrypt/sha.c
 */

/*#include "sha.h" */
#include "common.h"
#define BUFFER_SIZE 4096
#define RSA1024_SIG_SIZE 128
/*Enable/Disable the log flag*/
#define debuglog 0
/* Some machines lack byteswap.h and endian.h. These have to use the
 * slower code, even if they're little-endian.
 */
/*#define UINT64_RSHIFT(v, shiftby) (((uint64_t)(v)) >> (shiftby))*/

#if defined(HAVE_ENDIAN_H) && defined(HAVE_LITTLE_ENDIAN)

/* This version is about 28% faster than the generic version below,
 * but assumes little-endianness.
 */
static uint32_t ror27(uint32_t val) {
  return (val >> 27) | (val << 5);
}
static uint32_t ror2(uint32_t val) {
  return (val >> 2) | (val << 30);
}
static uint32_t ror31(uint32_t val) {
  return (val >> 31) | (val << 1);
}

static void SHA1_Transform(SHA1_CTX* ctx) {
  uint32_t W[80];
  register uint32_t A, B, C, D, E;
  int t;

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];

#define SHA_F1(A,B,C,D,E,t)                     \
  E += ror27(A) +                               \
      (W[t] = bswap_32(ctx->buf.w[t])) +        \
      (D^(B&(C^D))) + 0x5A827999;               \
  B = ror2(B);

  for (t = 0; t < 15; t += 5) {
    SHA_F1(A,B,C,D,E,t + 0);
    SHA_F1(E,A,B,C,D,t + 1);
    SHA_F1(D,E,A,B,C,t + 2);
    SHA_F1(C,D,E,A,B,t + 3);
    SHA_F1(B,C,D,E,A,t + 4);
  }
  SHA_F1(A,B,C,D,E,t + 0);  /* 16th one, t == 15 */

#undef SHA_F1

#define SHA_F1(A,B,C,D,E,t)                                     \
  E += ror27(A) +                                               \
      (W[t] = ror31(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) +     \
      (D^(B&(C^D))) + 0x5A827999;                               \
  B = ror2(B);

  SHA_F1(E,A,B,C,D,t + 1);
  SHA_F1(D,E,A,B,C,t + 2);
  SHA_F1(C,D,E,A,B,t + 3);
  SHA_F1(B,C,D,E,A,t + 4);

#undef SHA_F1

#define SHA_F2(A,B,C,D,E,t)                                     \
  E += ror27(A) +                                               \
      (W[t] = ror31(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) +     \
      (B^C^D) + 0x6ED9EBA1;                                     \
  B = ror2(B);

  for (t = 20; t < 40; t += 5) {
    SHA_F2(A,B,C,D,E,t + 0);
    SHA_F2(E,A,B,C,D,t + 1);
    SHA_F2(D,E,A,B,C,t + 2);
    SHA_F2(C,D,E,A,B,t + 3);
    SHA_F2(B,C,D,E,A,t + 4);
  }

#undef SHA_F2

#define SHA_F3(A,B,C,D,E,t)                                     \
  E += ror27(A) +                                               \
      (W[t] = ror31(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) +     \
      ((B&C)|(D&(B|C))) + 0x8F1BBCDC;                           \
  B = ror2(B);

  for (; t < 60; t += 5) {
    SHA_F3(A,B,C,D,E,t + 0);
    SHA_F3(E,A,B,C,D,t + 1);
    SHA_F3(D,E,A,B,C,t + 2);
    SHA_F3(C,D,E,A,B,t + 3);
    SHA_F3(B,C,D,E,A,t + 4);
  }

#undef SHA_F3

#define SHA_F4(A,B,C,D,E,t)                                     \
  E += ror27(A) +                                               \
      (W[t] = ror31(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) +     \
      (B^C^D) + 0xCA62C1D6;                                     \
  B = ror2(B);

  for (; t < 80; t += 5) {
    SHA_F4(A,B,C,D,E,t + 0);
    SHA_F4(E,A,B,C,D,t + 1);
    SHA_F4(D,E,A,B,C,t + 2);
    SHA_F4(C,D,E,A,B,t + 3);
    SHA_F4(B,C,D,E,A,t + 4);
  }

#undef SHA_F4

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
}

void SHA1_update(SHA1_CTX* ctx, const uint8_t* data, uint64_t len) {
  int i = ctx->count % sizeof(ctx->buf);
  const uint8_t* p = (const uint8_t*)data;

  ctx->count += len;

  while (len > sizeof(ctx->buf) - i) {
    Memcpy(&ctx->buf.b[i], p, sizeof(ctx->buf) - i);
    len -= sizeof(ctx->buf) - i;
    p += sizeof(ctx->buf) - i;
    SHA1_Transform(ctx);
    i = 0;
  }

  while (len--) {
    ctx->buf.b[i++] = *p++;
    if (i == sizeof(ctx->buf)) {
      SHA1_Transform(ctx);
      i = 0;
    }
  }
}


uint8_t* SHA1_final(SHA1_CTX* ctx) {
  uint64_t cnt = ctx->count * 8;
  int i;

  SHA1_update(ctx, (uint8_t*)"\x80", 1);
  while ((ctx->count % sizeof(ctx->buf)) != (sizeof(ctx->buf) - 8)) {
    SHA1_update(ctx, (uint8_t*)"\0", 1);
  }
  for (i = 0; i < 8; ++i) {
    uint8_t tmp = cnt >> ((7 - i) * 8);
    SHA1_update(ctx, &tmp, 1);
  }

  for (i = 0; i < 5; i++) {
    ctx->buf.w[i] = bswap_32(ctx->state[i]);
  }

  return ctx->buf.b;
}

#else   /* #if defined(HAVE_ENDIAN_H) && defined(HAVE_LITTLE_ENDIAN) */

#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void SHA1_transform(SHA1_CTX *ctx) {
  uint32_t W[80];
  uint32_t A, B, C, D, E;
  uint8_t *p = ctx->buf;
  int t;

  for(t = 0; t < 16; ++t) {
    uint32_t tmp =  *p++ << 24;
    tmp |= *p++ << 16;
    tmp |= *p++ << 8;
    tmp |= *p++;
    W[t] = tmp;
  }

  for(; t < 80; t++) {
    W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];

  for(t = 0; t < 80; t++) {
    uint32_t tmp = rol(5,A) + E + W[t];

    if (t < 20)
      tmp += (D^(B&(C^D))) + 0x5A827999;
    else if ( t < 40)
      tmp += (B^C^D) + 0x6ED9EBA1;
    else if ( t < 60)
      tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC;
    else
      tmp += (B^C^D) + 0xCA62C1D6;

    E = D;
    D = C;
    C = rol(30,B);
    B = A;
    A = tmp;
  }
  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
}

void SHA1_update(SHA1_CTX *ctx, const uint8_t *data, uint64_t len) {
  int i = (int)(ctx->count % sizeof(ctx->buf));
  const uint8_t* p = (const uint8_t*) data;

  ctx->count += len;

  while (len--) {
    ctx->buf[i++] = *p++;
    if (i == sizeof(ctx->buf)) {
      SHA1_transform(ctx);
      i = 0;
    }
  }
}
uint8_t* SHA1_final(SHA1_CTX *ctx) {
  uint8_t *p = ctx->buf;
  uint64_t cnt = ctx->count << 3;
  int i;

  SHA1_update(ctx, (uint8_t*)"\x80", 1);
  while ((ctx->count % sizeof(ctx->buf)) != (sizeof(ctx->buf) - 8)) {
    SHA1_update(ctx, (uint8_t*)"\0", 1);
  }
  for (i = 0; i < 8; ++i) {
    uint8_t tmp = (uint8_t)UINT64_RSHIFT(cnt, (7 - i) * 8);
    SHA1_update(ctx, &tmp, 1);
  }

  for (i = 0; i < 5; i++) {
    uint32_t tmp = ctx->state[i];
    *p++ = (uint8_t)(tmp >> 24);
    *p++ = (uint8_t)(tmp >> 16);
    *p++ = (uint8_t)(tmp >> 8);
    *p++ = (uint8_t)(tmp >> 0);
  }

  return ctx->buf;
}

#endif /* endianness */

void SHA1_init(SHA1_CTX* ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xEFCDAB89;
  ctx->state[2] = 0x98BADCFE;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xC3D2E1F0;
  ctx->count = 0;
}

uint8_t* SHA1(const uint8_t *data, uint64_t len, uint8_t *digest) {
  const uint8_t *p;
  int i;
  SHA1_CTX ctx;
  SHA1_init(&ctx);
  SHA1_update(&ctx, data, len);
  p = SHA1_final(&ctx);
  for (i = 0; i < SHA1_DIGEST_SIZE; ++i) {
    digest[i] = *p++;
  }
  return digest;
}

/*Main function to calculate the shasum of File*/
/*Filename -name of file */
/*shahexresult -store the final result in an unsigned array of size 41 bytes*/
void hash_calculate(char *filename,uint8_t shahexresult[41],uint8_t hashsum[20],uint8_t sig[RSA1024_SIG_SIZE]){
#if debuglog
	grub_printf("Enter hash_calculate \n");
	grub_printf("HASH==>Filename==%s\n",filename);
#endif
	int fp;
	uint8_t buf[BUFFER_SIZE];
	uint64_t filesize;
	uint64_t bytes=0;
	int round=1;
	uint8_t sha1_result[20];
	fp=grub_open(filename);
	int i=0;
	uint64_t leftbytes;
	uint8_t *p;
	int k=0;
/*	uint8_t sig[RSA1024_SIG_SIZE];*/
#if debuglog
	if(!fp)
	{
		printf("Error opening file to calculate sha1\n");
		printf("fp==%d\n",fp);
	}
#endif
	filesize=filemax-RSA1024_SIG_SIZE;
#if debuglog
	printf("Hash_filesize==%d\n",filesize);	
#endif
	SHA1_CTX shacontext;
	SHA1_init(&shacontext);
	bytes=filesize;
#if debuglog
	printf("Hash__bytes==%d\n",bytes);
#endif
	grub_memset(sha1_result,0,20);
	while(bytes >=BUFFER_SIZE)
	{
		grub_memset(buf,0,BUFFER_SIZE);
		grub_read(buf,BUFFER_SIZE);
		SHA1_update(&shacontext,buf,BUFFER_SIZE);
		bytes=bytes-BUFFER_SIZE;
		round++;
	} 
	leftbytes=bytes;
	grub_memset(buf,0,BUFFER_SIZE);
	if(leftbytes!=0)
	{
		grub_read(buf,leftbytes);
		SHA1_update(&shacontext,buf,leftbytes);
	}
	p=SHA1_final(&shacontext);
	grub_strcpy(hashsum,p);	
	grub_read(sig,RSA1024_SIG_SIZE);
	for(i=0;i<5;i++)
	{
#if debuglog
		printf("ctx->state[%d]=%x\n",i,shacontext.state[i]);
#endif
		sprintf(shahexresult+k,"%x",shacontext.state[i]);
		k=k+8;
	}
#if debuglog
	printf("securehash==%s\n",shahexresult);
#endif
	grub_close();
	return 0;
}

/*Test function to calculate sha1(secure hash) for any buffer */
/*buf-unsigned char array*/
void hashbuf_calculate(uint8_t *buf){
#if debuglog
	printf("Enter hash_calculate \n");
#endif
	uint64_t filesize;
	uint64_t bytes=0;
	uint8_t sha1_result[20];
	int i=0;
	uint8_t *p;
	/*Size of the buffer */
	filesize=grub_strlen(buf); 
#if debuglog
	printf("Hash_filesize==%d\n",filesize);	
#endif
	grub_memset(sha1_result,0,20);
	/*Calculate the hash of a buffer */
	p=SHA1(buf,filesize,sha1_result);
#if debuglog
	for (i = 0;i<SHA1_DIGEST_SIZE;++i) 
	{
		printf("sha1_result[%d] ==%x ",i,sha1_result[i]);
	}
#endif
	for (i = 0;i<SHA1_DIGEST_SIZE;++i) 
	{
		sha1_result[i] = *p++;
		/*Print the hash of buffer*/
		printf("HASHDIGESTsha1_result[%d] ==%x ",i,sha1_result[i]);
	}
	return 0;
}
