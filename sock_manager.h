#ifndef _SESSION_MANAGER_H_
#define _SESSION_MANAGER_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif//_GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>


#define ENABLE_SSL 1

#define ENABLE_URCU 0

#if (ENABLE_SSL)
#define SSL_SESSION_ID "sock_manager"
#endif//ENABLE_SSL

#ifndef MAX_EPOLL_SIZE
#define MAX_EPOLL_SIZE 512
#endif//MAX_EPOLL_SIZE

#ifndef MAX_USERDATA_LEN
#define MAX_USERDATA_LEN 16
#endif//MAX_USERDATA_LEN


//类型申明
typedef struct sock_session sock_session_t;
typedef struct session_manager session_manager_t;
typedef struct messenger messenger_t;	//这个函数的声明在post_office/messenger/messenger.h中 在会调用加入消息,需要引入该头文件
typedef struct rwbuf rwbuf_t;
typedef struct sortingcenter_ctx sortingcenter_ctx_t;

//typedef void(*)

//typedef void (*session_complate_pkg_cb)(sock_session_t*, char*, uint32_t, void*, uint8_t);

//与heap_timer同步的回调函数类型, 不想引入头文件
typedef void(*sm_heap_timer_cb)(uint32_t, void*, uint8_t);



//这作为解包回调的输入输出参数
typedef struct rcv_decode_mod {
	uint32_t lenght_tirgger;				//输入: 当前回调的数据长度>=当前设定值 输出: 下次回调的时机>=设置的数据长度
	uint32_t processed;						//输入: 上次回调已处理的数据索引 输出: 本次处理+上次处理的字节数 
//	uint8_t fin;							//输出: 当前回调的数据是否是最后一个包
}rcv_decode_mod_t;

/*
*	session_decode_pkg_cb 说明
*	ss, sock session上下文
*	data, 接收到的数据起始地址
*	len, data的长度
*	mod, 解包模块, 说明参照rcv_decode_mod_t
*	return value
*		val < 0: 指示任意错误, 将由内部移除当前session
*		val = 0: 内部将什么也不做, 但是依然可以通过输出mod内的参数修改解包回调的行为
*		val > 0: 表示解包函数得到一个完整的数据包, 数据包的长度即为返回值 (这里需要注意的是, 这个返回值是包括包头的(因为大多数情况都有包头))
*	offset, 最后说明这个输出参数, 当返回值 > 0的时候使用, 用于除去包头的长度, 表示真正的数据起始位置需要函数返回值偏移offset
*/
typedef int32_t(*session_decode_pkg_cb)(sock_session_t* ss, char* data, uint32_t len, rcv_decode_mod_t* mod, uint32_t* offset);


/*
*	session_encode_fn 说明
*	data, 需要封包的完整数据
*	len, 需要封包的数据长度, 如果对长度有限制, 也可以在这个函数中设置
*	out_buf, 传出的参数, 这个函数将数据写入out_buf后, 有上层交给信使处理, 
*	若这个buf是有数据的, 那么将产生一个THEME_SEND事件在读写线程中被处理
*		val < 0: 指示自定义的错误, 或者使用serror.h内的错误码
*		val = 0: 成功
*/
typedef int32_t (*session_encode_fn)(const char* data, uint32_t len, rwbuf_t* out_buf);

typedef void (*session_event_cb)(sortingcenter_ctx_t* scc, uint32_t ev, int8_t* data, uint32_t len, uint32_t total_len, session_encode_fn encode_fn, void* udata, uint8_t udata_len, messenger_t* msger);

typedef struct session_behavior {
	session_event_cb		conn_cb;		//创建连接回调
	session_event_cb		disconn_cb;		//断开连接回调
	session_decode_pkg_cb	decode_cb;		//用户自定义解包协议
	session_encode_fn		encode_fn;		//用户自定义封包协议
	session_event_cb	complate_cb;		//解包成功回调
}session_behavior_t;


typedef struct tls_operate {
	const char* ca;							//ca证书路径
	const char* cert;						//证书路径
	const char* key;						//证书密钥路径
}tls_operate_t;

//分拣中心需要的参数
typedef struct sortingcenter_ctx {
	uint32_t hash;
	void* session_address;
	session_encode_fn encode_fn;
}sortingcenter_ctx_t;


#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

//函数声明

//创建一个session管理器
session_manager_t* sm_init_manager(uint32_t session_cache_size/*, uint32_t buf_cache_size, uint32_t buf_len*/);

//销毁session管理器
void sm_exit_manager(session_manager_t* sm);

void sm_set_run(session_manager_t* sm, uint8_t run);

sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint32_t max_send_len,
	uint8_t enable_tls, tls_operate_t tls, session_behavior_t behavior, void* udata, uint8_t udata_len);

sock_session_t* sm_add_client(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, uint32_t max_send_len,
	uint8_t enable_tls, void* server_ctx, uint8_t add_online, session_behavior_t behavior, void* udata, uint8_t udata_len);

sock_session_t* sm_add_server(session_manager_t* sm, const char* domain, uint16_t port, uint32_t max_send_len,
	session_behavior_t behavior, void* udata, uint8_t udata_len);

uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval_ms, uint32_t delay_ms, int32_t repeat, sm_heap_timer_cb timer_cb, void* udata, uint8_t udata_len);

void sm_del_timer(session_manager_t* sm, uint32_t timer_id, uint32_t is_incallback);

void sm_del_session(sock_session_t* ss);

//void sm_set_ready(sock_session_t* ss, uint8_t ready);

void* sm_sortingcenter(session_manager_t* sm);

void sm_soringcenter_ctx(sock_session_t* ss, sortingcenter_ctx_t* out_ctx);

int sm_add_signal(session_manager_t* sm, uint32_t sig, void (*cb)(int));

int32_t sm_run2(session_manager_t* sm, uint64_t us);

void sm_run(session_manager_t* sm);


#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SESSION_MANAGER_H_