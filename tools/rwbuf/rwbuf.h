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

#define RWBUF_START_PTR(obj) ((obj)->buf + (obj)->offset)

typedef struct rwbuf {
	uint32_t offset;		
	uint32_t len;		//data len
	uint32_t size;		//buffer size
	int8_t*  buf;		//data buffer
}rwbuf_t;

int32_t rwbuf_mlc(rwbuf_t* rwb, uint32_t capacity);

int32_t rwbuf_relc(rwbuf_t* rwb, uint32_t capacity);

void rwbuf_free(rwbuf_t* rwb);

int32_t rwbuf_append(rwbuf_t* rwb, void* data, uint32_t data_len);

int32_t rwbuf_aband_front(rwbuf_t* rwb, uint32_t aband_len);

void rwbuf_clear(rwbuf_t* rwb);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_RWBUF_H_