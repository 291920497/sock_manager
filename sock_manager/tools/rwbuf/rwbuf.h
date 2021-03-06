#ifndef _RWBUF_H_
#define _RWBUF_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

;

//#define RWBUF_START_PTR(ptr) ((ptr)->buf + (ptr)->offset)
//#define RWBUF_GET_UNUSELEN(ptr) ((ptr)->size - (ptr)->offset - (ptr)->len)
//#define RWBUF_GET_LEN(ptr) ((ptr)->len)
//#define RWBUF_GET_SIZE(ptr) ((ptr)->size)

typedef struct rwbuf {
	uint32_t offset;		
	uint32_t len;		//data len
	uint32_t size;		//buffer size
	int8_t*  buf;		//data buffer
}rwbuf_t;

void rwbuf_init(rwbuf_t* rwb);

int32_t rwbuf_mlc(rwbuf_t* rwb, uint32_t capacity);

int32_t rwbuf_relc(rwbuf_t* rwb, uint32_t capacity);

void rwbuf_free(rwbuf_t* rwb);

int32_t rwbuf_enough(rwbuf_t* rwb, uint32_t wlen);

int32_t rwbuf_append(rwbuf_t* rwb, const void* data, uint32_t data_len);

int32_t rwbuf_append_complete(rwbuf_t* rwb, const void* data, uint32_t data_len);

int32_t rwbuf_aband_front(rwbuf_t* rwb, uint32_t aband_len);

int32_t rwbuf_replan(rwbuf_t* rwb);

void rwbuf_swap(rwbuf_t* l, rwbuf_t* r);

void rwbuf_clear(rwbuf_t* rwb);

static inline
int8_t* rwbuf_start_ptr(const rwbuf_t* rwb) {
	return ((rwb)->buf + (rwb)->offset);
}

static inline
uint32_t rwbuf_unused_len(const rwbuf_t* rwb) {
	return ((rwb)->size - (rwb)->offset - (rwb)->len);
}

static inline
uint32_t rwbuf_len(const rwbuf_t* rwb) {
	return ((rwb)->len);
}

static inline
uint32_t rwbuf_capcity(const rwbuf_t* rwb) {
	return ((rwb)->size);
}

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_RWBUF_H_