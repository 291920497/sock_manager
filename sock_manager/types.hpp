#ifndef _TYPES_HPP_
#define _TYPES_HPP_

#include "types.h"

#ifndef _WIN32
#include "tools/stl/list.h"
#include <pthread.h>
#else
#include <Windows.h>
#include "tools/stl/wlist.h"
#endif//_WIN32

#include "tools/stl/rbtree.h"
#include "tools/common/spin_lock.h"

typedef struct sock_session {
	int32_t		fd;
	int32_t		epoll_state;

	session_flag_t	flag;		//状态机
	uint32_t	uuid_hash;

	uint16_t	port;
	char		ip[16];

	rwbuf_t		rbuf;			//接收缓冲区
	rwbuf_t		wbuf;			//发送缓冲区

	uint8_t		rtry_number;	//尝试读的次数
	uint8_t		wtry_number;	//尝试写的次数

//	uint8_t		udatalen;		//用户数据长度
//	uint8_t		udata[MAX_USERDATA_LEN];		//用户数据, 用户自定义
	void*		udata;

	uint64_t	last_active;	//最后一次活跃的时间
	tls_info_t	tls_info;		//tls协议上下文
//	void*		protocol_info;	//应用层协议

	rcv_decode_mod_t		decode_mod;		//解包模块
	session_rw				recv_cb;		//可读事件回调
	session_rw				send_cb;		//可写事件回调
	session_behavior_t		uevent;			//用户行为

	struct session_manager* sm;

	cds_list_head_t	elem_lively;
	cds_list_head_t	elem_offline;
	cds_list_head_t	elem_listens;
	cds_list_head_t elem_changed;			//有改变的session, 用于在读缓冲区发生改变时加入该列表
	cds_list_head_t	elem_pending_recv;
	cds_list_head_t	elem_pending_send;
	cds_list_head_t	elem_cache;
}sock_session_t;

//session manager
typedef struct session_manager {
#ifndef _WIN32
	int32_t			ep_fd;
#else
	fd_set			rfdst;
	fd_set			wfdst;
#endif//_WIN32
	uint32_t		overflow;			//该管理器下写缓冲区的溢出长度
	manager_flag_t	flag;		//状态机

	heap_timer_t* ht_timer;	//定时器

	cds_list_head_t list_lively;
	cds_list_head_t list_offline;
	cds_list_head_t list_reconnect;
	cds_list_head_t list_listens;
	cds_list_head_t list_changed;			//有改变的session, 用于在读缓冲区发生改变时加入该列表
	cds_list_head_t list_pending_recv;
	cds_list_head_t list_pending_send;
	cds_list_head_t list_session_cache;

#if (SM_MULTI_THREAD)
	int32_t			fdpipe[2];
	cds_list_head_t list_rcvbuf;			//接收到的事件, entry类型为external_buf_vehicle_t
	cds_list_head_t list_sndbuf;			//等待发送的数据列表, entry类型为external_buf_vehicle_t
	osspin_lk_t		lk_sndbuf;				//待发送数据列表的自旋锁
	session_dispatch_data_cb dispath_data_cb;	//派发数据包的回调函数
	rb_root_t		rb_tidy;				//用于整理数据包
	cds_list_head_t list_tidy;				//整理后的待发送数据包链表
#endif//SM_MULTI_THREAD
}session_manager_t;

#endif//_TYPES_HPP_