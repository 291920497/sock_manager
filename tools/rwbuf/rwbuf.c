#include "rwbuf.h"
#include "../../serror.h"

#define _rwbuf_malloc malloc
#define _rwbuf_realloc realloc
#define _rwbuf_free free

int32_t rwbuf_mlc(rwbuf_t* rwb, uint32_t capacity) {
	memset(rwb, 0, sizeof(rwbuf_t));
	return rwbuf_relc(rwb, capacity);
}

int32_t rwbuf_relc(rwbuf_t* rwb, uint32_t capacity) {
	if (capacity <= 0)
		return SERROR_INPARAM_ERR;

	if (rwb->size < capacity) {
		void* buf = _rwbuf_realloc(rwb->buf, capacity);
		if (!buf)
			return SERROR_SYSAPI_ERR;

		rwb->buf = buf;
		rwb->size = capacity;
	}
	return SERROR_OK;
}

void rwbuf_free(rwbuf_t* rwb) {
	if (rwb->buf) {
		_rwbuf_free(rwb->buf);
		memset(rwb, 0, sizeof(rwbuf_t));
	}
}

int32_t rwbuf_append(rwbuf_t* rwb, void* data, uint32_t data_len) {
	if (!rwb)
		return SERROR_INPARAM_ERR;

	//剩余的缓冲区足够
	if ((rwb->size - rwb->offset - rwb->len) >= data_len) {
		//将数据拷贝到 buf + 偏移位 + 数据长度
		memcpy(rwb->buf + rwb->offset + rwb->len, data, data_len);
		rwb->len += data_len;
		return data_len;
	}

	//将原有数据拷贝到buf头,避免数据覆盖使用cpy
	if (rwb->offset && rwb->len)
		memcpy(rwb->buf, rwb->buf + rwb->offset, rwb->len);

	//将剩余的数据拷贝到末尾
	int32_t len = rwb->size - rwb->len;
	
	if (data_len < len) {
		len = data_len;
	}

	memcpy(rwb->buf + rwb->len, data, len);
	rwb->offset = 0;
	rwb->len += len;

	//返回完成的拷贝
	return len;
}

int32_t rwbuf_aband_front(rwbuf_t* rwb, uint32_t aband_len) {
	if (!rwb || aband_len < 0 || aband_len > rwb->len)
		return SERROR_INPARAM_ERR;

	rwb->len -= aband_len;

	if (rwb->len)
		rwb->offset += aband_len;
	else
		rwb->offset = 0;

	return SERROR_OK;
}

void rwbuf_clear(rwbuf_t* rwb) {
	if (rwb) {
		rwb->offset = 0;
		rwb->len = 0;
	}
}