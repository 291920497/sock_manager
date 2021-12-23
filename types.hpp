#ifndef _TYPES_HPP_
#define _TYPES_HPP_

#include "types.h"

#ifndef _WIN32
#include "tools/stl/list.h"
#else
#include "tools/stl/wlist.h"
#endif//_WIN32
#include "tools/stl/rbtree.h"

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
#ifdef _WIN32
	//cds_list_head_t	elem_forgotten;			//win32下select模型中被遗忘的套接字
#endif
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
#ifdef _WIN32
	//cds_list_head_t	list_forgotten;			//win32下select模型中被遗忘的套接字
#endif//WIN32

	cds_list_head_t list_fifo;		//排队的信使
	cds_list_head_t list_outbox_fifo;	//等待放入发件箱的信使
	rb_root_t rbroot_house_number;	//门牌号列表

	sock_session_t* pipe0;
	//	sorting_center_t* sc;			//分拣中心
}session_manager_t;

#endif//_TYPES_HPP_