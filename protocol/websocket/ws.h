#ifndef _WS_H_
#define _WS_H_

#include "../../sock_manager.h"
#include "../../tools/rwbuf/rwbuf.h"

typedef struct ws_header {
	char url[256];
	uint8_t opcode;
}ws_header_t;

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;
//void web_protocol_recv(sock_session_t* ss);

int32_t ws_decode_cb(sock_session_t* ss, char* data, uint32_t len, rcv_decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset);

int32_t ws_encode_fn(const char* data, uint32_t len, rwbuf_t* out_buf);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_WS_H_