#include "ws.h"

#include "../../types.hpp"
#include "../../internal/internal_fn.h"

#include "../../tools/common/sha1.h"
#include "../../tools/common/base64_encoder.h"

#include "../../serror.h"
#include "../../tools/common/hash_func.h"


#define RFC6455 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

//函数的实现在sock_manager.c, 但是不方便暴露出来
//extern uint32_t sf_send_fn(sock_session_t* ss, const char* data, uint32_t len);
//extern void sf_set_ws_handshake(sock_session_t* ss, uint8_t ready);
//extern uint8_t sf_get_ws_handshake(sock_session_t* ss);
//extern rwbuf_t* sf_get_wbuf(sock_session_t* ss);

struct ws_frame_protocol {
	char fin;
	char opcode;
	char mask;
	char mask_code[4];
	char head_len;
	char* data;
	uint32_t payload_len;
};

//解码数据
static void sf_ws_decode_data(const char* mask_arr, char* data, uint32_t data_len) {
	for (int i = 0; i < data_len; ++i)
		data[i] ^= mask_arr[i & 3];
}

//解析一个协议头
static void sf_ws_decode_protocol(const char* frame, struct ws_frame_protocol* out_buf) {
	unsigned char fin_opcode = *(frame);
	unsigned char msk_paylen = *(frame + 1);
	out_buf->fin = fin_opcode & 0x80;
	out_buf->mask = msk_paylen & 0x80;
	out_buf->opcode = fin_opcode & 0x7F;
	out_buf->payload_len = msk_paylen & 0x7F;
	out_buf->head_len = 2;

	//按理此处是不需要的直接赋值6
	if (out_buf->mask) {
		out_buf->head_len += 4;
	}

	if (out_buf->payload_len == 126) {
		out_buf->head_len += 2;
	}
	else if (out_buf->payload_len > 126) {
		out_buf->head_len += 4;
	}

	out_buf->data = (char*)(frame + out_buf->head_len);

	if (out_buf->payload_len == 126) {
		out_buf->payload_len = ntohs(*((unsigned short*)(frame + 2)));
	}
	else if (out_buf->payload_len > 126) {
		out_buf->payload_len = ntohl(*((unsigned int*)(frame + 2)));
	}

	if (out_buf->mask) {
		memcpy(out_buf->mask_code, frame + out_buf->head_len - 4, 4);
	}
}

static void sf_ws_encode_protocol(char* frame, struct ws_frame_protocol* in_buf) {
	unsigned char fin_opcode = 0;
	unsigned char msk_paylen = 0;
	char* encode = frame;

	fin_opcode |= (in_buf->opcode);
	if (in_buf->fin) {
		fin_opcode |= 0x80;
	}
	*encode++ = fin_opcode;

	if (in_buf->mask) {
		msk_paylen |= 0x80;
	}

	if (in_buf->payload_len < 126) {
		msk_paylen |= in_buf->payload_len;
		*encode++ = msk_paylen;
	}
	else if (in_buf->payload_len < 0xFFFF) {
		msk_paylen |= 126;
		*encode++ = msk_paylen;
		*((unsigned short*)encode) = ntohs(in_buf->payload_len);
		encode += 2;
	}
	else {
		msk_paylen |= 127;
		*encode++ = msk_paylen;
		*((unsigned int*)encode) = ntohl(in_buf->payload_len);
		encode += 4;
	}

	if (in_buf->mask) {
		memcpy(encode, in_buf->mask_code, sizeof(char) * 4);
	}
	in_buf->head_len = encode - frame;
}

//合并2个协议头为同一个, 仅用于上一帧不为fin, 等待fin帧到来的情况
static int sf_ws_merge_protocol(struct ws_frame_protocol* in_prev_buf, struct ws_frame_protocol* in_cur_buf, unsigned char is_fin) {
	unsigned char new_head_len = 2;
	unsigned int new_data_len = in_prev_buf->payload_len + in_cur_buf->payload_len;

	if (in_prev_buf->mask) {
		new_head_len += 4;
	}

	if (new_data_len > 126 && new_data_len < 0xFFFF) {
		new_head_len += 2;
	}
	else if (new_data_len > 0xFFFF) {
		new_head_len += 4;
	}

	memmove(in_prev_buf->data + in_prev_buf->payload_len, in_cur_buf->data, in_cur_buf->payload_len);
	in_prev_buf->payload_len += (in_cur_buf->payload_len);

	if (new_head_len > in_prev_buf->head_len) {
		memmove(in_prev_buf->data + new_head_len - in_prev_buf->head_len, in_prev_buf->data, in_prev_buf->payload_len);
	}

	if (is_fin) {
		in_prev_buf->fin |= 0x80;
	}

	in_prev_buf->head_len = new_head_len;
	sf_ws_encode_protocol(in_prev_buf->data - in_prev_buf->head_len, in_prev_buf);
	return 0;
}

//握手函数
static int sf_ws_handshake(sock_session_t* ss, const char* url, const char* host, const char* origin, const char* sec_key, const char* sec_version) {
	char sec_ws_key[128];
	char sha1[32] = { 0 };
	char b64[64] = { 0 };
	char handshake[512];
	uint32_t rt, len;

	strcpy(sec_ws_key, sec_key);
	strcat(sec_ws_key, RFC6455);
	sz_sha1((uint8_t*)sec_ws_key, strlen(sec_ws_key), sha1);
	base64_encode_r((uint8_t*)sha1, 20, (uint8_t*)b64, sizeof(b64));

	sprintf(handshake, "HTTP/1.1 101 Switching Protocols\r\n" \
		"Upgrade: websocket\r\n" \
		"Connection: Upgrade\r\n" \
		"Sec-WebSocket-Accept: %s\r\n" \
		"\r\n", b64);

	len = strlen(handshake);
	//这只会在连接刚创建的时候发生, 缓冲区一定够, 如果写入失败那么一定是哪里错了
	if (rwbuf_enough(&ss->wbuf, len)) {
		rt = rwbuf_append(&ss->wbuf, handshake, len);
		if (rt == len) {
			sf_add_event(ss->sm, ss, EV_WRITE);
			return SERROR_OK;
		}
	}

	rt = sf_uncoded_send_fn(ss, handshake, len);

	if(rt == len)
		return SERROR_OK;

	/*rt = sf_send_fn(ss, handshake, len);
	if (rt == len)
		return SERROR_OK;*/

	return SERROR_SYSAPI_ERR;
}

int32_t sf_ws_parse_head(sock_session_t* ss, char* data, unsigned short len) {
	unsigned int total = 0, head_idx = 0, tail_idx = 0, line_len, key_hash;
	const char* fs_ptr = 0, * fe_ptr = 0;

	char key[128];
	char var[1024];
	char host[128];
	char origin[128];
	char secwskey[128];
	char secwsver[32];

	char url[256] = { 0 };
	char base64buf[32] = { 0 };
	char sec_accept[32] = { 0 };

	fs_ptr = data + total;
	fe_ptr = strstr(fs_ptr, "\r\n");
	line_len = fe_ptr - fs_ptr + sizeof(char) * 2;

	if (strncmp(fs_ptr, "GET", 3)) {
		goto handshake_failed;
	}
	else {
		total += (line_len);
		fs_ptr = strchr(fs_ptr, ' ');
		fe_ptr = strchr(++fs_ptr, ' ');
		if ((fe_ptr - fs_ptr) < line_len) {
			strncpy(url, fs_ptr, fe_ptr - fs_ptr);
		}
		else {
			goto handshake_failed;
		}
	}

	while (total < len - 2) {
		fs_ptr = data + total;
		fe_ptr = strchr(fs_ptr, ':');
		if (!fs_ptr || !fe_ptr) { goto handshake_failed; }
		strncpy(key, fs_ptr, fe_ptr - fs_ptr);
		key[fe_ptr - fs_ptr] = 0;

		fs_ptr = fe_ptr + sizeof(char) * 2;
		fe_ptr = strstr(fs_ptr, "\r\n");
		if (!fs_ptr || !fe_ptr) { goto handshake_failed; }
		strncpy(var, fs_ptr, fe_ptr - fs_ptr);
		var[fe_ptr - fs_ptr] = 0;

		//printf("key: [%s], var: [%s]\n", key, var);
		total += (fe_ptr - data - total + sizeof(char) * 2);

		key_hash = hash_func(key, -1);
		switch (key_hash) {
		case 0x3B2793A8://Upgrade
			if (strcmp(var, "websocket"))
				goto handshake_failed;
			break;
		case 0x9CB49D90://Connection
			if (strcmp(var, "Upgrade"))
				goto handshake_failed;
			break;
		case 0x003AEEDE://Host
			strcpy(host, var);
			break;
		case 0x0B36DF28://Origin
			strcpy(origin, var);
			break;
		case 0x6B183CE5://Sec-WebSocket-Key
			strcpy(secwskey, var);
			break;
		case 0xD388F522://Sec-WebSocket-Version
			strcpy(secwsver, var);
			break;
		}//switch	
	}

	/*
		此处可能后续需要对url, origin做出校验或增加url对应不同的处理回调。这将需要在sock_session或者实现一个多态的url->cb 映射
	*/

	//此处完成回执
	if (sf_ws_handshake(ss, url, host, origin, secwskey, secwsver) != SERROR_OK) {
		goto handshake_failed;
	}
	else {
		//sf_set_ws_handshake(ss, 1);
		ss->flag.ws_handshake = ~0;
	}

	return 1;

handshake_failed:
	sm_del_session(ss);
	return 0;
}

int32_t sf_ws_parse_frame(struct sock_session* ss, char* data, uint32_t data_len, rcv_decode_mod_t* mod, uint32_t* offset) {
	if ((data_len - mod->processed) < 2) {
		mod->lenght_tirgger = mod->processed + 2;
		return 0;
	}

	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));

	rwbuf_t* wbuf = 0;
	uint32_t wbuf_size;
	uint32_t fin_opcode = *(data + mod->processed);
	uint32_t msk_paylen = *(data + mod->processed + 1);
	wfp.fin = fin_opcode & 0x80;
	wfp.mask = msk_paylen & 0x80;
	wfp.opcode = fin_opcode & 0x7F;
	wfp.payload_len = msk_paylen & 0x7F;
	wfp.head_len = 6;	//头2字节 + 至少4字节的掩码

	if (wfp.opcode == 0x08)
		return SERROR_WS_FIN;

	if (!(wfp.mask))
		return SERROR_WS_NO_MASK;

	//查看报文头是否需要增大
	if (wfp.payload_len == 126)
		wfp.head_len += 2;
	else if (wfp.payload_len > 126)
		wfp.head_len += 4;

	//找到data的指针
	wfp.data = data + mod->processed + wfp.head_len;

	//开始校验, 收到的数据是否满足一个整包

	//如果不满足一个协议头
	if (wfp.head_len > (data_len - mod->processed)) {
		//等待一个头的长度
		//mod->lenght_tirgger = wfp.head_len;
		mod->lenght_tirgger = mod->processed + wfp.head_len;
		return 0;
	}

	//如果至少已经满足一个协议头, 那么下次回调的时机改为满足一个整包
	if (wfp.payload_len == 126) {
		wfp.payload_len = ntohs(*((uint16_t*)(data + 2)));
	}
	else if (wfp.payload_len > 126) {
		wfp.payload_len = ntohl(*((uint32_t*)(data + 2)));
	}

	//此处对一个完整帧的长度做出判断

	//wbuf = sf_get_wbuf(ss);
	wbuf = &ss->wbuf;
	wbuf_size = rwbuf_capcity(wbuf);
	if ((wfp.payload_len + wfp.head_len) > wbuf_size)
		return SERROR_WS_OVERFLOW;

	//如果包并不完整
	if ((wfp.head_len + wfp.payload_len) > (data_len - mod->processed)) {
		mod->lenght_tirgger = mod->processed + wfp.head_len + wfp.payload_len;
		return 0;
	}

	memcpy(wfp.mask_code, data + mod->processed + wfp.head_len - 4, 4);
	sf_ws_decode_data(wfp.mask_code, wfp.data, wfp.payload_len);

	//到这里缓冲区已经满足一个整包,但是此时需要判断, 是否为最后一帧
	if (wfp.fin) {
		struct ws_frame_protocol twfp, * pwfp;
		pwfp = &twfp;

		//如果是需要合并后再处理的
		if (mod->processed) {
			//第一帧只能在头部
			sf_ws_decode_protocol(data, pwfp);
			sf_ws_merge_protocol(pwfp, &wfp, wfp.fin);
		}
		else
			pwfp = &wfp;
		

		switch (pwfp->opcode) {
		case 0x01:
		case 0x02:
		{
			//解码
			

			*offset = pwfp->head_len;
			mod->lenght_tirgger = 6;	//等待下一个包头+掩码
			mod->processed = 0;			//清理索引
			return pwfp->payload_len + pwfp->head_len;
			break;
		}
		case 0x0A:
		{
			//是否回应心跳包
			break;
		}
			
		}
	}
	else {
		//如果是第二帧, 那么合并
		if (mod->processed) {
			struct ws_frame_protocol prev_wfp;
			sf_ws_decode_protocol(data, &prev_wfp);
			sf_ws_merge_protocol(&prev_wfp, &wfp, wfp.fin);

			mod->processed = prev_wfp.head_len + prev_wfp.payload_len;
			mod->lenght_tirgger = mod->processed + 6;	//下一次触发的时机是头+掩码到达的时候
		}
		else {
			//等待下一个包头+掩码的到达
			mod->lenght_tirgger = wfp.head_len + wfp.payload_len + 6;
		}
	}
	

	return 0;
}




int32_t ws_decode_cb(sock_session_t* ss, char* data, uint32_t data_len, rcv_decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset) {
	uint32_t total = 0, wbuf_size;
	uint32_t len = mod->processed;
	rwbuf_t* wbuf;


	//如果已经完成握手
	//if (sf_get_ws_handshake(ss)) {
	if (ss->flag.ws_handshake) {
		return sf_ws_parse_frame(ss, data, data_len, mod, front_offset);
	}
	else {
		if (data_len > 4) {
			while ((total + len) < data_len - 3) {
				if (*((int*)(data + total + len)) == 0x0A0D0A0D) {
					//printf("begin handshake\n");
					//sf_ws_parse_head(ss, data + total, len + 4);
					//printf("end handshake\n");
					total += (len + 4);
					len = 0;
					break;
				}
				++len;
			}

			if (total) {
				//如果解析头并握手失败,
				if (!ss->flag.is_connect) {
					if (sf_ws_parse_head(ss, data, total) == 0)
						return SERROR_WS_HANDSHAKE_ERR;
				}
				else {
					if(total < 9 || strncmp(data + 9,"101",3) != 0)
						return SERROR_WS_HANDSHAKE_ERR;
				}

				//下一帧数据满足2字节
				mod->lenght_tirgger = 2;
				mod->processed = 0;

				//偏移当前头的长度, 外部消息为0则不需要发送
				*front_offset = total;
				//删除total长度的数据
				printf("%s:%d ws handshake done\n", ss->ip, ss->port);
				return total;
			}
			else {
				mod->processed = len;
				//wbuf = sf_get_wbuf(ss);
				wbuf = &ss->wbuf;
				wbuf_size = rwbuf_capcity(wbuf);
				if (len >= wbuf_size)
					return SERROR_WS_OVERFLOW;
			}
		}
		else {
			//满足4字节再次回调
			mod->lenght_tirgger = 4;
		}
	}
	//什么都不做
	return 0;
}

int32_t ws_encode_fn(const char* data, uint32_t data_len, rwbuf_t* out_buf) {
	uint32_t head_len = 0, rt, total;
	if (data_len < 126) 
		head_len += 2;
	else if (data_len < 0xFFFF) 
		head_len += 4;
	else
		head_len += 6;

	char ws_head[16];
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.mask = 0;
	wfp.payload_len = data_len;
	wfp.opcode = 0x01;
	sf_ws_encode_protocol(ws_head, &wfp);

#if 1
	total = wfp.head_len + wfp.payload_len;

	if (!rwbuf_enough(out_buf, total)) {
		rt = rwbuf_relc(out_buf, rwbuf_capcity(out_buf) + total);
		if (rt != SERROR_OK)
			return rt;
	}

	rwbuf_append(out_buf, ws_head, wfp.head_len);
	rwbuf_append(out_buf, data, data_len);

	return SERROR_OK;
#else
	if ((rt = rwbuf_mlc(out_buf, wfp.head_len + wfp.payload_len)) != SERROR_OK) {
		return rt;
	}

	rwbuf_append(out_buf, ws_head, wfp.head_len);
	rwbuf_append(out_buf, data, data_len);
#endif
	return SERROR_OK;
}