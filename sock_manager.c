#include "sock_manager.h"
#include "serror.h"

//std
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>

//uuid
#include <uuid/uuid.h>

//urcu
#include <urcu.h>
#include <urcu/rculist.h>

//heap_timer
#include "tools/heap_timer/heap_timer.h"
#include "tools/common/nofile_ctl.h"
#include "tools/rwbuf/rwbuf.h"

#define sm_malloc malloc
#define sm_realloc realloc
#define sm_free	free

//sock_session 的状态机
typedef struct session_flag {
	int32_t		closed : 1;
	int32_t		etmod : 1;
	int32_t		ready : 1;		//是否准备就绪,这将影响广播时是否将消息下发到这个session, 例如ws wss握手
}session_flag_t;

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

	session_flag_t	flag;		//状态机
	uint32_t	uuid_hash;

	uint16_t	port;
	char		ip[16];	

	rwbuf_t		rbuf;			//接收缓冲区
	rwbuf_t		wbuf;			//发送缓冲区

	uint8_t		udatalen;		//用户数据长度
	uint8_t		udata[MAX_USERDATA_LEN];		//用户数据, 用户自定义
	
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
	struct cds_list_head	elem_cache;
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
	struct cds_list_head list_session_cache;

	uint8_t		udatalen;		//用户数据长度
	uint8_t		udata[MAX_USERDATA_LEN];		//用户数据, 用户自定义
}session_manager_t;

/*
	static variable
*/

static CDS_LIST_HEAD(_slist_session_cache);



/*
	static function
*/

//添加监听事件
static int32_t sf_add_event(session_manager_t* sm, sock_session_t* ss, sm_event_t ev) {
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
static int32_t sf_del_event(session_manager_t* sm, sock_session_t* ss, sm_event_t ev) {
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

//解析域名为IP, 这个函数的返回值具体含义在netdb.h:617
static int32_t sf_domain2ip(const char* domain, char* ip_buf, uint16_t buf_len) {
	struct addrinfo hints;
	struct addrinfo* res, * cur;
	int rt;
	struct sockaddr_in* addr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;     /* Allow IPv4 */
	hints.ai_flags = AI_PASSIVE;/* For wildcard IP address */
	hints.ai_protocol = 0;         /* Any protocol */
	hints.ai_socktype = SOCK_STREAM;

	rt = getaddrinfo(domain, NULL, &hints, &res);
	if (rt)
		return rt;

	if (!res)
		return EAI_AGAIN;

	addr = (struct sockaddr_in*)res->ai_addr;
	if (!inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_len)) {
		return EAI_OVERFLOW;
	}
	return SERROR_OK;
}

//创建一个uuid的hash值, inbuffer 为
static uint32_t sf_uuidhash() {
	//uuid
	char buf[64];
	uuid_t uu;
	uuid_generate(uu);
	uuid_generate_random(uu);
	uuid_unparse_upper(uu, buf);

	uint32_t hash = 0;
	int32_t klen = strnlen(buf, 64);
	const unsigned char* key = (const unsigned char*)buf;
	const unsigned char* p;
	int i;
	if (!key) return hash;

	if (klen == -1) {
		for (p = key; *p; p++) {
			hash = hash * 33 + tolower(*p);
		}
		klen = p - key;
	}
	else {
		for (p = key, i = klen; i; i--, p++) {
			hash = hash * 33 + tolower(*p);
		}
	}

	return hash;
}


//构建sock_session_t
static int32_t sf_construct_session(session_manager_t* sm, sock_session_t* ss, int32_t fd, const char* ip, uint16_t port,uint32_t send_len, session_event_cb recv_cb, session_behavior_t uevent, void* udata, uint16_t udata_len) {
	int rt;
	char uuid_buf[64];

	if (!ss || !sm || udata_len > MAX_USERDATA_LEN)
		return SERROR_INPARAM_ERR;

	//memset(ss, 0, sizeof(sock_session_t));
	ss->fd = fd;
	ss->epoll_state = 0;
	ss->sm = sm;
	ss->port = port;
	ss->recv_cb = recv_cb;
	ss->last_active = time(0);
	ss->uuid_hash = sf_uuidhash();
	memcpy(&ss->uevent, &uevent, sizeof(uevent));
	strcpy(ss->ip, ip);
	
	ss->flag.closed = 0;
	ss->flag.etmod = 0;
	ss->flag.ready = 0;

	if (udata && udata_len)
		memcpy(&ss->udata, &udata, udata_len);

	rt = rwbuf_relc(&ss->wbuf, send_len);
	if (rt != SERROR_OK)
		goto session_construct_failed;

	rt = rwbuf_relc(&ss->rbuf, send_len * 2);
	if (rt != SERROR_OK)
		goto session_construct_failed;

	CDS_INIT_LIST_HEAD(&(ss->elem_online));
	CDS_INIT_LIST_HEAD(&(ss->elem_offline));
	CDS_INIT_LIST_HEAD(&(ss->elem_servers));
	CDS_INIT_LIST_HEAD(&(ss->elem_listens));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_recv));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_send));

	//构建时不考虑cache cache由manager统一管理
	//CDS_INIT_LIST_HEAD(&(ss->elem_cache));

	return SERROR_OK;

session_construct_failed:
	if (ss->wbuf.size)
		rwbuf_free(&ss->wbuf);
	if (ss->rbuf.size)
		rwbuf_free(&ss->rbuf);
	return rt;
}

static void sf_destruct_session(sock_session_t* ss) {
	if (!ss)
		return;

	ss->fd = -1;
	ss->epoll_state = 0;
	ss->sm = 0;
	ss->port = 0;
	ss->recv_cb = 0;
	ss->last_active = 0;
	ss->uuid_hash = 0;
	ss->ip[0] = 0;

	ss->wbuf.len = 0;
	ss->wbuf.offset = 0;

	ss->rbuf.len = 0;
	ss->rbuf.offset = 0;

	ss->flag.closed = ~0;
	ss->flag.etmod = 0;
	ss->flag.ready = 0;
	memset(&ss->uevent, 0, sizeof(session_behavior_t));

	//这一段用于区分于初始化
	if(ss->elem_online.next)
		cds_list_del(&(ss->elem_online));
	if (ss->elem_offline.next)
		cds_list_del(&(ss->elem_offline));
	if (ss->elem_servers.next)
		cds_list_del(&(ss->elem_servers));
	if (ss->elem_listens.next)
		cds_list_del(&(ss->elem_listens));
	if (ss->elem_pending_recv.next)
		cds_list_del(&(ss->elem_pending_recv));
	if (ss->elem_pending_send.next)
		cds_list_del(&(ss->elem_pending_send));
	if (ss->elem_cache.next)
		cds_list_del(&(ss->elem_cache));

	CDS_INIT_LIST_HEAD(&(ss->elem_online));
	CDS_INIT_LIST_HEAD(&(ss->elem_offline));
	CDS_INIT_LIST_HEAD(&(ss->elem_servers));
	CDS_INIT_LIST_HEAD(&(ss->elem_listens));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_recv));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_send));
	CDS_INIT_LIST_HEAD(&(ss->elem_cache));
}

//从cache内获取一个sock_session_t
static sock_session_t* sf_cache_session(session_manager_t* sm) {
	sock_session_t* ss = 0;

	if (!sm)
		return ss;

	if (cds_list_empty(&(sm->list_session_cache))) {
		//new session
		ss = sm_malloc(sizeof(sock_session_t));
		if (ss) {
			sf_destruct_session(ss);
		}
		return ss;
	}

	ss = cds_list_entry(sm->list_session_cache.next, struct sock_session, elem_cache);
	cds_list_del(&(sm->list_session_cache.next));
	sf_destruct_session(ss);
	return ss;
}

//归还一个sock_session到cache
static void sf_free_session(session_manager_t* sm, sock_session_t* ss) {
	if (!sm) {
		rwbuf_free(&ss->wbuf);
		rwbuf_free(&ss->rbuf);
		sm_free(ss);
		return;
	}

	sf_destruct_session(ss);
	cds_list_add(&ss->elem_cache, &sm->list_session_cache);
}

static int sf_try_socket(int _domain, int _type, int _protocol) {
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

/**
*	s_try_accept - Try to accept a sock fileno
*/
static int sf_try_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t* __restrict __addr_len) {
	int fd = -1, try_count = 1;
	do {
		fd = accept(__fd, __addr, __addr_len);
		if (fd == -1) {
			int err = errno;

			//is nothing
			if (err == EAGAIN)
				return -2;
			//If the error is caused by fileno and the processing is complete
			else if (err == EMFILE && try_count) {
				--try_count;
				if (nofile_ckup() == 0)
					continue;
			}
			return -1;
		}
		//if (fd == -1 && try_count) {
		//	--try_count;
		//	
		//	if (tools_nofile_ckup() == 0)
		//		continue;
		//}
	} while (0);
	return fd;
}

static void sf_accpet_cb(sock_session_t* ss) {
	do {
		int rt;
		struct sockaddr_in c_sin;
		socklen_t s_len = sizeof(c_sin);
		memset(&c_sin, 0, sizeof(c_sin));

		int c_fd, try_count = 1;
		//c_fd = sf_try_accept(ss->fd, (struct sock_addr*)&c_sin, &s_len);
		c_fd = sf_try_accept(ss->fd, &c_sin, &s_len);
		if (c_fd == -2) {
			return;
		}
		else if (c_fd == -1) {
			//printf("[%s] [%s:%d] [%s] Accept function failed. errmsg: [ %s ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno));
			return;
		}

		const char* ip = inet_ntoa(c_sin.sin_addr);
		unsigned short port = ntohs(c_sin.sin_port);

	} while (ss->flag.etmod);
}


/*
	global function
*/

session_manager_t* sm_init_manager(uint32_t cache_size) {
	
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
	CDS_INIT_LIST_HEAD(&(sm->list_session_cache));

	//create cache_session
	for (int i = 0; i < cache_size; ++i) {
		sock_session_t* ss = sm_malloc(sizeof(sock_session_t));
		if (ss) {
			memset(ss, 0, sizeof(sock_session_t));
			sf_destruct_session(ss);
			cds_list_add(&ss->elem_cache, &sm->list_session_cache);
		}else
			goto sm_init_manager_failed;	
	}

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
	if (cds_list_empty(&sm->list_session_cache)) {
		//agen
	}
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

	sock_session_t* ss = 0;
	int rt, err, fd, ev, try_count = 1, optval = 1;

	fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
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

	ss = sf_cache_session(sm);
	if (ss == 0)
		return SERROR_MEMALC_ERR;

	rt = sf_construct_session(sm, ss, fd, "0.0.0.0", port, max_send_len, NULL/*accpet_function*/, behavior, udata, udata_len);
	if (rt != SERROR_OK) {
		sf_free_session(sm, ss);
		return rt;
	}

	//add epoll status
	ev = EV_RECV;
	if (enable_et)
		ev |= EV_ET;

	rt = sf_add_event(sm, ss, ev);
	if (rt) {
		sf_free_session(sm, ss);
		return rt;
	}
		
	//add to listener list
	cds_list_add_tail(&(ss->elem_listens), &(sm->list_listens));
	return SERROR_OK;
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