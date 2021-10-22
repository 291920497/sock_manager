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
#define MAX_USERDATA_LEN 64
#endif//MAX_USERDATA_LEN




//类型申明
typedef struct sock_session sock_session_t;
typedef struct session_manager session_manager_t;

typedef void (*session_event_cb)(sock_session_t*);
typedef void (*session_complate_pkg_cb)(sock_session_t*, char*, uint32_t, void*, uint8_t);

typedef struct session_behavior {
	session_event_cb		conn_cb;		//创建连接回调
	session_event_cb		disconn_cb;		//断开连接回调
											//用户自定义解包协议
											//用户自定义封包协议
	session_complate_pkg_cb	complate_cb;	//解包成功回调
}session_behavior_t;

typedef struct session_tls {
	const char* ca;							//ca证书路径
	const char* cert;						//证书路径
	const char* key;						//证书密钥路径
}session_tls_t;


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
	uint8_t enable_tls, session_tls_t tls, session_behavior_t behavior, void* udata, uint8_t udata_len);

sock_session_t* sm_add_client(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, uint32_t max_send_len,
	uint8_t enable_tls, void* server_ctx, uint8_t add_online, session_behavior_t behavior, void* udata, uint8_t udata_len);

sock_session_t* sm_add_server(session_manager_t* sm, const char* domain, uint16_t port, uint32_t max_send_len,
	session_behavior_t behavior, void* udata, uint8_t udata_len);

uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval_ms, uint32_t delay_ms, int32_t repeat, void(*timer_cb)(uint32_t, void*), void* udata, uint8_t udata_len);

void sm_del_timer(session_manager_t* sm, uint32_t timer_id, uint32_t is_incallback);

void sm_del_session(sock_session_t* ss);

int sm_add_signal(session_manager_t* sm, uint32_t sig, void (*cb)(int));

int32_t sm_run2(session_manager_t* sm, uint64_t us);

void sm_run(session_manager_t* sm);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SESSION_MANAGER_H_