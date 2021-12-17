#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint8_t* base64_encode_r(uint8_t* data, uint32_t len, uint8_t* out_buf, uint32_t buf_len) {
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