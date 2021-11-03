#ifndef __BASE64_ENCODE_H__
#define __BASE64_ENCODE_H__

#include <stdint.h>

//char* base64_encode(uint8_t* text, int sz, int* encode_sz);
#ifdef __cplusplus
extern "C"
{
#endif

uint8_t* base64_encode_r(uint8_t* data, uint32_t len, uint8_t* out_buf, uint32_t buf_len);

#ifdef __cplusplus
}
#endif

#endif

