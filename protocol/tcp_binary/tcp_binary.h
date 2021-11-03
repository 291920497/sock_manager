#ifndef _TCP_BINARY_H_
#define _TCP_BINARY_H_

#include "../../sock_manager.h"
#include "../../tools/rwbuf/rwbuf.h"

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

//解码函数只会在读写线程调用
int32_t tcp_binary_decode_cb(sock_session_t* ss, char* data, uint32_t len, rcv_decode_mod_t* mod, uint32_t* offset);

int32_t tcp_binary_encode_fn(const char* data, uint32_t len, rwbuf_t* out_buf);


#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_TCP_BINARY_H_