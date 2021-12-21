#include "common_fn.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t  buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

static void	SHA1_Transform(uint32_t	state[5], const	uint8_t	buffer[64]);

#define	rol(value, bits) (((value) << (bits)) |	((value) >>	(32	- (bits))))

/* blk0() and blk()	perform	the	initial	expand.	*/
/* I got the idea of expanding during the round	function from SSLeay */
/* FIXME: can we do	this in	an endian-proof	way? */
#ifdef WORDS_BIGENDIAN
#define	blk0(i)	block.l[i]
#else
#define	blk0(i)	(block.l[i]	= (rol(block.l[i],24)&0xFF00FF00) \
	|(rol(block.l[i],8)&0x00FF00FF))
#endif
#define	blk(i) (block.l[i&15] =	rol(block.l[(i+13)&15]^block.l[(i+8)&15] \
	^block.l[(i+2)&15]^block.l[i&15],1))

/* (R0+R1),	R2,	R3,	R4 are the different operations	used in	SHA1 */
#define	R0(v,w,x,y,z,i)	z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define	R1(v,w,x,y,z,i)	z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define	R2(v,w,x,y,z,i)	z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define	R3(v,w,x,y,z,i)	z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define	R4(v,w,x,y,z,i)	z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash	a single 512-bit block.	This is	the	core of	the	algorithm. */
static void	SHA1_Transform(uint32_t	state[5], const	uint8_t	buffer[64])
{
	uint32_t a, b, c, d, e;
	typedef	union {
		uint8_t	c[64];
		uint32_t l[16];
	} CHAR64LONG16;
	CHAR64LONG16 block;

	memcpy(&block, buffer, 64);

	/* Copy	context->state[] to	working	vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds	of 20 operations each. Loop	unrolled. */
	R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1);	R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5);	R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9);	R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13);	R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17);	R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);
	R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21);	R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25);	R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29);	R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33);	R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37);	R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);
	R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41);	R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45);	R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49);	R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53);	R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57);	R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);
	R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61);	R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65);	R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69);	R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73);	R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77);	R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

	/* Add the working vars	back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	/* Wipe	variables */
	a = b = c = d = e = 0;
}


/* SHA1Init	- Initialize new context */
static void sat_SHA1_Init(SHA1_CTX* context)
{
	/* SHA1	initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


/* Run your	data through this. */
static void sat_SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len)
{
	size_t i, j;

#ifdef VERBOSE
	SHAPrintContext(context, "before");
#endif

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64 - j));
		SHA1_Transform(context->state, context->buffer);
		for (; i + 63 < len; i += 64) {
			SHA1_Transform(context->state, data + i);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);

#ifdef VERBOSE
	SHAPrintContext(context, "after	");
#endif
}


/* Add padding and return the message digest. */
static void sat_SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE])
{
	uint32_t i;
	uint8_t	 finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
			>> ((3 - (i & 3)) * 8)) & 255);	 /*	Endian independent */
	}
	sat_SHA1_Update(context, (uint8_t*)"\200", 1);
	while ((context->count[0] & 504) != 448) {
		sat_SHA1_Update(context, (uint8_t*)"\0", 1);
	}
	sat_SHA1_Update(context, finalcount, 8);  /* Should	cause a	SHA1_Transform() */
	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		digest[i] = (uint8_t)
			((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}

	/* Wipe	variables */
	i = 0;
	memset(context->buffer, 0, 64);
	memset(context->state, 0, 20);
	memset(context->count, 0, 8);
	memset(finalcount, 0, 8);	/* SWR */
}

char* cf_sha1(uint8_t* buffer, int sz, char* out_buf) {
	//static uint8_t digest[SHA1_DIGEST_SIZE];
	SHA1_CTX ctx;
	sat_SHA1_Init(&ctx);
	sat_SHA1_Update(&ctx, buffer, sz);
	//sat_SHA1_Final(&ctx, digest);
	sat_SHA1_Final(&ctx, out_buf);
	//memcpy(out_buf, digest, SHA1_DIGEST_SIZE);
	return out_buf;
}

uint8_t* cf_base64_encode_r(uint8_t* data, uint32_t len, uint8_t* out_buf, uint32_t buf_len) {
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t encode_sz = (len + 2) / 3 * 4;
	if (encode_sz >= buf_len)
		return 0;

	uint8_t* buffer = out_buf;
	int i, j;
	j = 0;
	for (i = 0; i < (int)len - 2; i += 3) {
		uint32_t v = data[i] << 16 | data[i + 1] << 8 | data[i + 2];
		buffer[j] = encoding[v >> 18];
		buffer[j + 1] = encoding[(v >> 12) & 0x3f];
		buffer[j + 2] = encoding[(v >> 6) & 0x3f];
		buffer[j + 3] = encoding[(v) & 0x3f];
		j += 4;
	}
	int padding = len - i;
	uint32_t v;
	switch (padding) {
	case 1:
		v = data[i];
		buffer[j] = encoding[v >> 2];
		buffer[j + 1] = encoding[(v & 3) << 4];
		buffer[j + 2] = '=';
		buffer[j + 3] = '=';
		break;
	case 2:
		v = data[i] << 8 | data[i + 1];
		buffer[j] = encoding[v >> 10];
		buffer[j + 1] = encoding[(v >> 4) & 0x3f];
		buffer[j + 2] = encoding[(v & 0xf) << 2];
		buffer[j + 3] = '=';
		break;
	}
	buffer[encode_sz] = 0;
	return out_buf;
}

uint32_t cf_hash_func(const char* char_key, int32_t klen) {
	uint32_t hash = 0;
	const unsigned char* key = (const unsigned char*)char_key;
	const unsigned char* p;
	int i;
	if (!key) return hash;

	if (klen == -1) {
		for (p = key; *p; p++) {
			hash = hash * 33 + tolower(*p);
		}
		klen = p - key;
	}
	else {
		for (p = key, i = klen; i; i--, p++) {
			hash = hash * 33 + tolower(*p);
		}
	}

	return hash;
}