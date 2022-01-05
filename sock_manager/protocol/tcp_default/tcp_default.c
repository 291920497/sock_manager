#include "tcp_default.h"
#include "../../types.h"

int32_t tcp_default_decode_cb(sock_session_t* ss, char* data, uint32_t len, decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset, uint32_t* data_type) {
	//收到数据即回调
	mod->lenght_tirgger = 1;
	return len;
}

int32_t tcp_default_encode_fn(const char* data, uint32_t len, rwbuf_t* out_buf) {
	return 0;
}