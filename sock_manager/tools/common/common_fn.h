#ifndef _COMMON_FN_H_
#define _COMMON_FN_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
;

//char* sz_sha1(uint8_t* buffer, int sz, char* out_buf);

//uint8_t* base64_encode_r(uint8_t* data, uint32_t len, uint8_t* out_buf, uint32_t buf_len);

char* cf_sha1(uint8_t* buffer, int sz, char* out_buf);

uint8_t* cf_base64_encode_r(uint8_t* data, uint32_t len, uint8_t* out_buf, uint32_t buf_len);

uint32_t cf_hash_func(const char* char_key, int32_t klen);

int32_t cf_closesocket(int32_t fd);

int32_t cf_socketpair(int __domain, int __type, int __protocol, int __fds[2]);

#ifdef __cplusplus
}
#endif

#endif//_COMMON_FN_H_