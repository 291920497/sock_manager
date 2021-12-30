#ifndef _HASH_FUNC_H_
#define _HASH_FUNC_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

uint32_t cf_hash_func(const char* char_key, int32_t klen);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_HASH_FUNC_H_