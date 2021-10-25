#include "tcp_binary.h"

#define TBINARY_LENGTH_TYPE uint32_t
#define BINARY_MAX_RECV 16384

int32_t tcp_binary_decode_cb(sock_session_t* ss, char* data, uint32_t len, rcv_decode_mod_t* mod, uint32_t* offset) {
	int type_length = sizeof(TBINARY_LENGTH_TYPE);

	//长度标志不完整
	if (len < type_length)
		return 0;

	TBINARY_LENGTH_TYPE pkg_len = *((TBINARY_LENGTH_TYPE*)(data));
	if (pkg_len > BINARY_MAX_RECV) {
		printf("binary decode pkg_len: [%d]\n", pkg_len);
		return -1;
	}

	//如果这能满足一个完整的包, 那么需要告知库, 下一次回调的时机,这是必须的,否则将按照默认的, 有数据即回调
	if (len >= (pkg_len + type_length)) {
		//偏移量, 去掉包头
		*offset = type_length;

		//没有已经预处理的数据
		mod->processed = 0;

		//这里如果能提前读到一个头的大小, 也可以预处理跳过等待一个包头
		if ((len - (pkg_len + type_length)) >= type_length) {
			TBINARY_LENGTH_TYPE next_pkg_len = *((TBINARY_LENGTH_TYPE*)(data + pkg_len + type_length));
			if (next_pkg_len > BINARY_MAX_RECV) {
				printf("binary decode pkg_len: [%d]\n", pkg_len);
				return -1;
			}

			//下次回调的时机变为预读到的包头+包长
			mod->lenght_tirgger = next_pkg_len + type_length;
		}
		else {
			//下一次回调的时机是, 满足一个包头的长度
			mod->lenght_tirgger = type_length;
		}

		return pkg_len + type_length;
	}

	//如果不能满足一个完整的包, 那么修改回调时机为满足包头+包体长度
	mod->lenght_tirgger = type_length + pkg_len;
	mod->processed = 0;

	return 0;
}