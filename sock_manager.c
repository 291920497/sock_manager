#include "sock_manager.h"
#include "serror.h"

//std
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <errno.h>

//heap_timer
#include "tools/heap_timer/heap_timer.h"

#include <urcu.h>
#include <urcu/rculist.h>

#include "tools/common/nofile_ctl.h"


//session manager的状态机
typedef struct manager_flag {
	char running	: 1;
}manager_flag_t;

typedef enum {
	EV_ET = EPOLLET,
	EV_RECV = EPOLLIN,
	EV_WRITE = EPOLLOUT
}sm_event_t;


//sock_session的数据结构
typedef struct sock_session {
	int32_t		fd;
	int32_t		epoll_state;

	uint32_t	uuid_hash;

	uint16_t	port;
	char		ip[16];	

	uint8_t		udatalen;		//用户数据长度
	uint8_t		udata[64];		//用户数据, 用户自定义
	
	uint64_t	last_active;	//最后一次活跃的时间

	session_event_cb		recv_cb;		//可读事件回调
	session_behavior_t		uevent;			//用户行为

	struct session_manager* sm;

	struct cds_list_head	elem_online;
	struct cds_list_head	elem_offline;
	struct cds_list_head	elem_servers;
	struct cds_list_head	elem_listens;
	struct cds_list_head	elem_pending_recv;
	struct cds_list_head	elem_pending_send;
}sock_session_t;

//session manager
typedef struct session_manager {
	int32_t			ep_fd;
	manager_flag_t	flag;		//状态机
	heap_timer_t*	ht_timer;	//定时器

	struct cds_list_head list_online;
	struct cds_list_head list_offline;
	struct cds_list_head list_servers;
	struct cds_list_head list_listens;
	struct cds_list_head list_pending_recv;
	struct cds_list_head list_pending_send;

	uint8_t		udatalen;		//用户数据长度
	uint8_t		udata[64];		//用户数据, 用户自定义
}session_manager_t;


/*
	static function
*/

//添加监听事件
static int32_t sm_add_event(session_manager_t* sm, sock_session_t* ss, sm_event_t ev) {
	//If the monitor status exists except for the ET flag
	if ((ss->epoll_state & (~(EV_ET))) & ev) {
		return 0;
	}

	struct epoll_event epev;
	epev.data.ptr = ss;
	int ctl = EPOLL_CTL_ADD;

	//If the original flag is not 0, the operation changes to modify
	if (ss->epoll_state & (~(EPOLLET))) {
		ctl = EPOLL_CTL_MOD;
	}

	ss->epoll_state |= ev;
	epev.events = ss->epoll_state;

	return epoll_ctl(sm->ep_fd, ctl, ss->fd, &epev);
}

//删除监听事件
static int32_t sm_del_event(session_manager_t* sm, sock_session_t* ss, sm_event_t ev) {
	if (!((ss->epoll_state & (~(EV_ET))) & ev)) { return 0; }

	struct epoll_event epev;
	epev.data.ptr = ss;
	int ctl = EPOLL_CTL_DEL;

	if (ss->epoll_state & (~(EPOLLET | ev))) {
		ctl = EPOLL_CTL_MOD;
	}

	ss->epoll_state &= (~ev);
	epev.events = ss->epoll_state;

	return epoll_ctl(sm->ep_fd, ctl, ss->fd, &epev);
}

static int try_socket(int _domain, int _type, int _protocol) {
	int fd, try_count = 1;
	do {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		//failed and no attempt
		if (fd == -1 && try_count) {
			--try_count;

			if (nofile_ckup() == 0)
				continue;
		}
	} while (0);
	return fd;
}



/*
	global function
*/

session_manager_t* sm_init_manager() {
	session_manager_t* sm = (session_manager_t*)malloc(sizeof(session_manager_t));
	if (!sm)return 0;

	memset(sm, 0, sizeof(session_manager_t));
	sm->flag.running = 1;

	//Init all list
	CDS_INIT_LIST_HEAD(&(sm->list_online));
	CDS_INIT_LIST_HEAD(&(sm->list_offline));
	CDS_INIT_LIST_HEAD(&(sm->list_servers));
	CDS_INIT_LIST_HEAD(&(sm->list_listens));
	CDS_INIT_LIST_HEAD(&(sm->list_pending_recv));
	CDS_INIT_LIST_HEAD(&(sm->list_pending_send));

	//inti timer manager
	sm->ht_timer = ht_create_heap_timer();
	if (sm->ht_timer == 0)
		goto sm_init_manager_failed;

	//init epoll, try twice
	sm->ep_fd = epoll_create(EPOLL_CLOEXEC);
	if (sm->ep_fd == -1) {
		sm->ep_fd = epoll_create(1 << 15);	//32768
		if (sm->ep_fd == -1) {
			goto sm_init_manager_failed;
		}
	}

	//add default timer
	//heart cb
	//ht_add_timer(sm->ht_timer, MAX_HEART_TIMEOUT * 1000, 0, -1, cb_on_heart_timeout, sm);
	//server reconnect cb
	//ht_add_timer(sm->ht_timer, MAX_RECONN_SERVER_TIMEOUT * 1000, 0, -1, cb_on_reconnection_timeout, sm);

	return sm;

sm_init_manager_failed:
	if (sm->ht_timer) {
		ht_destroy_heap_timer(sm->ht_timer);
	}
	if (sm) {
		free(sm);
	}
	return 0;

}

void sm_exit_manager(session_manager_t* sm){
	if (sm == 0)
		return;

	//clean resources and all session
	sock_session_t* pos, * n;
	cds_list_for_each_entry_safe(pos, n, &sm->list_online, elem_online) {
		//printf("[%s] [%s:%d] [%s] Clean Online session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		//sm_del_session(pos, 0);
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_servers, elem_servers) {
		//printf("[%s] [%s:%d] [%s] Clean server session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		//sm_del_session(pos, 0);
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_listens, elem_listens) {
		//printf("[%s] [%s:%d] [%s] Clean listener session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		//close(pos->fd);
		//list_del_init(&pos->elem_listens);
		//s_free_session(sm, pos);
	}

	//sm_clear_offline(sm);

	if (sm->ht_timer) {
		ht_destroy_heap_timer(sm->ht_timer);
	}
	if (sm) {
		free(sm);
	}
}

void sm_set_run(session_manager_t* sm, uint8_t run) {
	if (sm) {
		sm->flag.running = run;
	}
}

int32_t sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint8_t enable_et, uint32_t max_send_len, session_behavior_t behavior, void* udata, uint8_t udata_len) {
	if (!sm) return SERROR_SM_UNINIT;

	sock_session_t* ss;
	int rt, err, fd, try_count = 1, optval = 1;

	fd = try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)  return SERROR_SYSAPI_ERR;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	rt = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (rt == -1) 
		return SERROR_SYSAPI_ERR;

	rt = bind(fd, (const struct sockaddr*)&sin, sizeof(sin));
	if (rt == -1)
		return SERROR_SYSAPI_ERR;

	rt = listen(fd, max_listen);
	if (rt == -1)
		return SERROR_SYSAPI_ERR;



}

int32_t sm_run2(session_manager_t* sm, uint64_t us) {
	struct epoll_event events[MAX_EPOLL_SIZE];

	int ret = epoll_wait(sm->ep_fd, events, MAX_EPOLL_SIZE, us);

	if (ret == -1) {
		if (errno != EINTR) { return -1; }
		return 0;
	}

	for (int i = 0; i < ret; ++i) {
		sock_session_t* ss = (struct sock_session*)events[i].data.ptr;
		if (events[i].events & EPOLLIN) {
			//ss->on_recv_cb(ss);
			ss->recv_cb(ss);
			/*if (ss->i_buf.recv_len && ss->on_protocol_recv_cb) {
				ss->on_protocol_recv_cb(ss);
			}*/
		}
		if (events[i].events & EPOLLOUT) {
			//sm_send(ss);
		}
	}

	//sm_pending_send(sm);
	//sm_pending_recv(sm);
	//sm_clear_offline(sm);
	return 0;
}

void sm_run(session_manager_t* sm) {
	while (sm->flag.running) {
		uint64_t wait_time = ht_update_timer(sm->ht_timer);

		//signal
		if (sm_run2(sm, wait_time) == 0) {
			if (errno == SIGQUIT)
				sm->flag.running = 0;
		}
	}
}