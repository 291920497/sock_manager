#include "ws.h"

#include "../../types.hpp"
#include "../../internal_fn.h"

#include "../../serror.h"
#include "../../tools/common/common_fn.h"

#define RFC6455 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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
		encode += 4;
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

	//将当前帧数据拷贝到上一帧的数据末尾
	memmove(in_prev_buf->data + in_prev_buf->payload_len, in_cur_buf->data, in_cur_buf->payload_len);
	in_prev_buf->payload_len += (in_cur_buf->payload_len);

	//如果协议头变长, 数据向后移动
	if (new_head_len > in_prev_buf->head_len) {
		memmove(in_prev_buf->data + new_head_len - in_prev_buf->head_len, in_prev_buf->data, in_prev_buf->payload_len);
	}

	if (is_fin) {
		in_prev_buf->fin |= 0x80;
		in_prev_buf->opcode = in_cur_buf->opcode;
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
	cf_sha1((uint8_t*)sec_ws_key, strlen(sec_ws_key), sha1);
	cf_base64_encode_r((uint8_t*)sha1, 20, (uint8_t*)b64, sizeof(b64));

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

		key_hash = cf_hash_func(key, -1);
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

static int32_t sf_ws_parse_frame(struct sock_session* ss, char* data, uint32_t data_len, rcv_decode_mod_t* mod, uint32_t* offset, uint32_t* back_offset, uint8_t isck_msk) {
	if ((data_len - mod->processed) < 2) {
		mod->lenght_tirgger = mod->processed + 2;
		return 0;
	}

	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));

	uint32_t total;
	uint8_t fin_opcode = *(data + mod->processed);
	uint8_t msk_paylen = *(data + mod->processed + 1);
	wfp.fin = fin_opcode & 0x80;
	wfp.mask = msk_paylen & 0x80;
	wfp.opcode = fin_opcode & 0x7F;
	wfp.payload_len = msk_paylen & 0x7F;
	wfp.head_len = 2 + (isck_msk ? 4 : 0);	//头2字节 + mask4

	if (wfp.opcode == 0x08)
		return SERROR_WS_FIN;

	if (isck_msk) {
		if (!(wfp.mask))
			return SERROR_WS_NO_MASK;
	}

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

	//判断当前缓冲器是否能容纳一个整包
	if ((mod->processed + wfp.payload_len + wfp.head_len) > rwbuf_capcity(&ss->rbuf))
		return SERROR_WS_OVERFLOW;

	//收到的数据长度不满足一个数据包, 修改触发器且继续等待
	if ((wfp.head_len + wfp.payload_len) > (data_len - mod->processed)) {
		mod->lenght_tirgger = mod->processed + wfp.head_len + wfp.payload_len;
		return 0;
	}

	//处理掩码, 如果是心跳包则跳过
	if (isck_msk && wfp.payload_len) {
		memcpy(wfp.mask_code, data + mod->processed + wfp.head_len - 4, 4);
		sf_ws_decode_data(wfp.mask_code, wfp.data, wfp.payload_len);
	}

	//如果是PING或者PONG包, 
	if (wfp.fin && (wfp.opcode == 0x0A || wfp.opcode == 0x09)) {
		//if ping
		if (wfp.opcode == 0x09) {
			//调用pong函数
		}

		//|data|ping/pong|data
		if (mod->processed) {
			mod->processed += wfp.head_len;
			return 0;
		}

		//|ping/pong|data
		*offset = wfp.head_len;
		*back_offset = 0;
		return wfp.head_len;
	}

	//收到完整的数据包, 判断当前是否为结束报文
	if (wfp.fin) {
		struct ws_frame_protocol twfp, * pwfp;
		pwfp = &twfp;

		//总长 = 已处理的长度(包含因合并数据包产生的不再使用的长度) + 当前数据包长度
		total = mod->processed + wfp.head_len + wfp.payload_len;

		//若存在等待被合并的数据包, 则合并且计算出
		if (mod->processed) {
			//上一帧数据必须在首地址. 解码上一帧的报文
			sf_ws_decode_protocol(data, pwfp);
			//合并数据, 注意: 合并动作, 将第二帧的数据拷贝到第一帧的数据末尾, 但是将空出第一帧的报文头长度
			sf_ws_merge_protocol(pwfp, &wfp, wfp.fin);

			//两帧使用总缓冲区长度 - 合并后完整一帧的长度, 后续的内存则需要移除
			*back_offset = total - (pwfp->head_len + pwfp->payload_len);
		}
		else
			pwfp = &wfp;
		

		switch (pwfp->opcode) {
		case 0x01:
		case 0x02:
		{
			//offset front len
			*offset = pwfp->head_len;

			mod->lenght_tirgger = 2 + (isck_msk ? 4 : 0);	//等待下一个包头+掩码
			mod->processed = 0;	

			//aband total
			return total;
		}
		case 0x0A:
		{
			//收到pong
			break;
		}
		case 0x09: {
			break;
		}
			
		}
	}
	else {
		//如果是第二帧, 那么合并
		if (mod->processed) {
			struct ws_frame_protocol prev_wfp;
			sf_ws_decode_protocol(data, &prev_wfp);

			//真实处理的长度为前后两帧占用缓冲区长度
			mod->processed = mod->processed + wfp.head_len + wfp.payload_len;

			//合并了两帧数据, 且后一帧数据拼接到前一帧的数据末尾, 且修正前一帧数据的协议头
			sf_ws_merge_protocol(&prev_wfp, &wfp, wfp.fin);
			
			mod->lenght_tirgger = mod->processed + 2 + (isck_msk ? 4 : 0);
		}
		else {
			//等待下一个包头+掩码的到达
			mod->lenght_tirgger = wfp.head_len + wfp.payload_len + 2 + (isck_msk ? 4 : 0);
			//更新已处理的字节数
			mod->processed = wfp.head_len + wfp.payload_len;
		}
	}
	

	return 0;
}

int32_t ws_decode_cb(sock_session_t* ss, char* data, uint32_t data_len, rcv_decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset) {
	uint32_t total = 0, capcity;
	uint32_t len = mod->processed;


	//如果已经完成握手
	if (ss->flag.ws_handshake) {
		return sf_ws_parse_frame(ss, data, data_len, mod, front_offset, back_offset, ss->flag.is_connect ? 0 : 1);
	}
	else {
		if (data_len > 4) {
			while ((total + len) < data_len - 3) {
				if (*((int*)(data + total + len)) == 0x0A0D0A0D) {
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

				ss->flag.ws_handshake = ~0;

				//下一帧数据满足2字节 + 根据本端是否是客户端, 判断是否追加掩码长度
				mod->lenght_tirgger = 2 + (ss->flag.is_connect ? 0 : 4);
				mod->processed = 0;

				//偏移当前头的长度, 外部消息为0则不需要发送
				*front_offset = total;
				//删除total长度的数据
				//printf("%s:%d ws handshake done\n", ss->ip, ss->port);
				return total;
			}
			else {
				mod->processed = len;
				capcity = rwbuf_capcity(&ss->rbuf);
				if (len >= rwbuf_capcity(&ss->rbuf))
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

int32_t ws_svr_encode_fn(const char* data, uint32_t data_len, rwbuf_t* out_buf) {
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

static int32_t sf_encode_pingpoing_frame(rwbuf_t* out_buf, uint8_t is_ping, uint8_t hs_mask) {
	int32_t rt;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = is_ping ? 0x09 : 0x0A;
	wfp.mask = hs_mask ? 1 : 0;
	if (wfp.mask) {
		for (int i = 0; i < 4; ++i) {
			wfp.mask_code[i] = rand() & 255;
		}
	}

	char ws_head[32];
	sf_ws_encode_protocol(ws_head, &wfp);

	rt = rwbuf_append_complete(out_buf, ws_head, wfp.head_len);
	if (rt < 0)
		return rt;

	return SERROR_OK;
}

int32_t ws_svr_ping_fn(rwbuf_t* out_buf) {
	return sf_encode_pingpoing_frame(out_buf, 1, 0);
	/*int32_t rt;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = 0x09;

	char ws_head[16];
	sf_ws_encode_protocol(ws_head, &wfp);

	rt = rwbuf_append_complete(out_buf, ws_head, wfp.head_len);
	if (rt < 0)
		return rt;

	return SERROR_OK;*/
}

int32_t ws_svr_pong_fn(rwbuf_t* out_buf) {
	return sf_encode_pingpoing_frame(out_buf, 0, 0);
	/*int32_t rt;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = 0x0A;

	char ws_head[16];
	sf_ws_encode_protocol(ws_head, &wfp);

	rt = rwbuf_append_complete(out_buf, ws_head, wfp.head_len);
	if (rt < 0)
		return rt;

	return SERROR_OK;*/
}

int32_t ws_clt_encode_fn(const char* data, uint32_t len, rwbuf_t* out_buf) {
	uint32_t head_len = 0, rt, total;
	if (len < 126)
		head_len += 2;
	else if (len < 0xFFFF)
		head_len += 4;
	else
		head_len += 6;

	char ws_head[16], * msk_data;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.mask = 1;
	wfp.payload_len = len;
	wfp.opcode = 0x01;
	for (int i = 0; i < 4; ++i) {
		wfp.mask_code[i] = rand() & 255;
	}

	sf_ws_encode_protocol(ws_head, &wfp);
	
	total = wfp.head_len + wfp.payload_len;
	if (!rwbuf_enough(out_buf, total)) {
		rt = rwbuf_relc(out_buf, rwbuf_capcity(out_buf) + total);
		if (rt != SERROR_OK)
			return rt;
	}

	msk_data = (char*)rwbuf_start_ptr(out_buf) + rwbuf_len(out_buf);
	rwbuf_append(out_buf, ws_head, wfp.head_len);

	//data address
	rwbuf_append(out_buf, data, wfp.payload_len);
	sf_ws_decode_data(wfp.mask_code, msk_data + wfp.head_len, wfp.payload_len);
	return SERROR_OK;
}

int32_t ws_clt_ping_fn(rwbuf_t* out_buf) {
	return sf_encode_pingpoing_frame(out_buf, 1, 0);
	/*int32_t rt;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = 0x09;
	wfp.mask = 1;
	for (int i = 0; i < 4; ++i) {
		wfp.mask_code[i] = rand() & 255;
	}

	char ws_head[16];
	sf_ws_encode_protocol(ws_head, &wfp);

	rt = rwbuf_append_complete(out_buf, ws_head, wfp.head_len);
	if (rt < 0)
		return rt;

	return SERROR_OK;*/
}

int32_t ws_clt_pong_fn(rwbuf_t* out_buf) {
	return sf_encode_pingpoing_frame(out_buf, 1, 0);
	/*int32_t rt;
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = 0x0A;
	wfp.mask = 1;
	for (int i = 0; i < 4; ++i) {
		wfp.mask_code[i] = rand() & 255;
	}

	char ws_head[16];
	sf_ws_encode_protocol(ws_head, &wfp);

	rt = rwbuf_append_complete(out_buf, ws_head, wfp.head_len);
	if (rt < 0)
		return rt;

	return SERROR_OK;*/
}
