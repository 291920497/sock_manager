#ifndef _SESSION_MANAGER_H_
#define _SESSION_MANAGER_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef MAX_EPOLL_SIZE
#define MAX_EPOLL_SIZE (512)
#endif//MAX_EPOLL_SIZE




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


#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

//函数声明

//创建一个session管理器
session_manager_t* sm_init_manager(uint32_t cache_size);

//销毁session管理器
void sm_exit_manager(session_manager_t* sm);

void sm_set_run(session_manager_t* sm, uint8_t run);

int32_t sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint8_t enable_et, uint32_t max_send_len, session_behavior_t behavior, void* udata, uint8_t udata_len);

int32_t sm_run2(session_manager_t* sm, uint64_t us);

void sm_run(session_manager_t* sm);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SESSION_MANAGER_H_