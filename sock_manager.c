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

#define _sm_malloc malloc
#define _sm_realloc realloc
#define _sm_free	free

#define MAX_RECONN_SERVER_TIMEOUT 5

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
	
	uint8_t		rtry_number;	//尝试读的次数
	//uint8_t		wtry_number;	//尝试写的次数
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

//日志相关

#ifndef _WIN32
#define __FILENAME__ (strrchr(__FILE__,'/') + 1)
#else
#define __FILENAME__ (strrchr(__FILE__,'\\') + 1)
#endif//_WIN32

static const char* sf_timefmt() {
	struct timeval tv;
	gettimeofday(&tv, 0);
	struct tm t;
	localtime_r(&tv.tv_sec, &t);

	static char time_fmt[64];
	sprintf(time_fmt, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
		//sprintf(time_fmt, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
		t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
	return time_fmt;
}

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
		freeaddrinfo(res);
		return EAI_OVERFLOW;
	}
	freeaddrinfo(res);
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
static int32_t sf_construct_session(session_manager_t* sm, sock_session_t* ss, int32_t fd, uint8_t enable_et, const char* ip, uint16_t port,uint32_t send_len, session_event_cb recv_cb, session_behavior_t uevent, void* udata, uint16_t udata_len) {
	int rt;

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
	ss->flag.ready = 0;

	if (enable_et) {
		ss->flag.etmod = ~0;
		nofile_set_nonblocking(fd);
	}

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

	ss->rtry_number = 0;
	//ss->wtry_number = 0;

	ss->flag.closed = ~0;
	ss->flag.etmod = 0;
	ss->flag.ready = 0;
	memset(&ss->uevent, 0, sizeof(session_behavior_t));
	rwbuf_clear(&ss->wbuf);
	rwbuf_clear(&ss->rbuf);
	
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
		ss = _sm_malloc(sizeof(sock_session_t));
		if (ss) {
			memset(ss, 0, sizeof(sock_session_t));
			sf_destruct_session(ss);
		}
		return ss;
	}

	ss = cds_list_entry(sm->list_session_cache.next, struct sock_session, elem_cache);
	cds_list_del_init(&ss->elem_cache);
	sf_destruct_session(ss);
	return ss;
}

//归还一个sock_session到cache
static void sf_free_session(session_manager_t* sm, sock_session_t* ss) {
	if (!sm) {
		rwbuf_free(&ss->wbuf);
		rwbuf_free(&ss->rbuf);
		_sm_free(ss);
		return;
	}

	sf_destruct_session(ss);
	cds_list_add_tail(&ss->elem_cache, &sm->list_session_cache);
}

static int sf_try_socket(int _domain, int _type, int _protocol) {
	int fd, try_count = 1;

	do {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			if (nofile_ckup() == 0)
				continue;
			return SERROR_SYSAPI_ERR;
		}

		break;

	} while (try_count--);
	
	return fd;
}

static int32_t sf_reconnect_server(sock_session_t* ss) {
	int fd, rt, ev;
	struct sockaddr_in sin;

	if (ss->fd != -1) {
		shutdown(ss->fd, SHUT_RDWR);
		ss->fd = -1;
	}

	fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return SERROR_SYSAPI_ERR;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(ss->port);
	sin.sin_addr.s_addr = inet_addr(ss->ip);

	ss->fd = fd;
	if (ss->flag.etmod)
		nofile_set_nonblocking(fd);

	rt = connect(ss->fd, (const struct sockaddr*)&sin, sizeof(sin));
	//if connect error
	if (rt == -1 && errno != EINPROGRESS) {
		////set need reconnect
		//ss->flag.closed = ~0;
		return SERROR_SYSAPI_ERR;
	}
	else {
		//add epoll status
		ev = (ss->flag.etmod ? EV_ET : 0) | EV_RECV;
		rt = sf_add_event(ss->sm, ss, ev);
		if (rt != SERROR_OK)
			return SERROR_SYSAPI_ERR;
	}
	ss->flag.closed = 0;

	return SERROR_OK;
}

static void sf_timer_reconn_cb(uint32_t timer_id, void* p) {
	session_manager_t* sm = *(session_manager_t**)p;

	int rt;
	const char* einprogress = "Connection in progress";
	const char* refused = "Connection refused";
	const char* success = "Connection succeeded";
	const char* msg;
	uint64_t ct = time(0);

	sock_session_t* ss, * n;
	cds_list_for_each_entry(ss, &sm->list_servers, elem_servers) {
		if (ss->flag.closed) {
			rt = sf_reconnect_server(ss);
			if (rt == SERROR_OK) {
				if (ss->flag.etmod)
					msg = einprogress;
				else
					msg = success;

#if TEST_CODE
				printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, msg);
#endif
			}
			else {
				printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));
			}
				
		}
	}
}

/**
*	s_try_accept - Try to accept a sock fileno
*/
static int sf_try_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t* __restrict __addr_len) {
	int fd = -1, try_count = 1, err;

	do {
		fd = accept(__fd, __addr, __addr_len);

		if (fd == -1) {
			err = errno;
			
			//is nothing
			if (err == EAGAIN)
				return -2;
			//If the error is caused by fileno and the processing is complete
			else if (err == EMFILE && try_count) {
				if (nofile_ckup() == 0)
					continue;
			}

			return -1;
		}

		break;

	} while (try_count--);

	return fd;
}

static void sf_del_session(sock_session_t* ss) {
	if (ss) {
		sf_del_event(ss->sm, ss, EV_RECV | EV_WRITE);

		//发送一个事件给消费线程, 通知断开事件以及尚未发送的数据
		//...


		//sf_destruct_session(ss);



		//从未决队列中移除
		if (cds_list_empty(&ss->elem_pending_recv) == 0)
			cds_list_del_init(&ss->elem_pending_recv);

		if (cds_list_empty(&ss->elem_pending_send) == 0)
			cds_list_del_init(&ss->elem_pending_send);

		if (cds_list_empty(&ss->elem_online) == 0)
			cds_list_del_init(&ss->elem_online);

		if (cds_list_empty(&ss->elem_listens) == 0)
			cds_list_del_init(&ss->elem_listens);

		/*if (cds_list_empty(&ss->elem_servers) == 0)
			cds_list_del_init(&ss->elem_servers);*/

		ss->flag.closed = ~0;
	}
}

static void sf_accpet_cb(sock_session_t* ss) {
	do {
		struct sockaddr_in c_sin;
		socklen_t s_len = sizeof(c_sin);
		memset(&c_sin, 0, sizeof(c_sin));

		int c_fd, try_count = 1;
		//c_fd = sf_try_accept(ss->fd, (struct sock_addr*)&c_sin, &s_len);
		c_fd = sf_try_accept(ss->fd, &c_sin, &s_len);
		if (c_fd == -2) {
			//半连接池没有可以接收的套接字
			if (cds_list_empty(&ss->elem_pending_recv) == 0)
				cds_list_del_init(&ss->elem_pending_recv);	
			return;
		}
		else if (c_fd == -1) {
			//printf("[%s] [%s:%d] [%s] Accept function failed. errmsg: [ %s ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno));
			//系统API调用错误 查看errno
			printf("[%s] [%s:%d] [%s], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, errno, strerror(errno));
			if(cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, & ss->sm->list_pending_recv);
			return;
		}

		const char* ip = inet_ntoa(c_sin.sin_addr);
		unsigned short port = ntohs(c_sin.sin_port);
		//printf("fd: %d\n", c_fd);
		sock_session_t* css = sm_add_client(ss->sm, c_fd, ip, port, ss->flag.etmod, ss->wbuf.size, 1, ss->uevent, ss->udata, ss->udatalen);
		if (!css) {
			//系统API调用错误 查看errno
			printf("[%s] [%s:%d] [%s], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, errno, strerror(errno));
			return;
		}

	} while (ss->flag.etmod);
}

static void sf_recv_cb(sock_session_t* ss) {
	if (ss->flag.closed)
		return;

	int rt;
	do {
		int buflen = RWBUF_UNUSE_LEN(&(ss->rbuf));

#if TEST_CODE
		//如果已经没有额外可用的buffer
		if (buflen == 0) {
			printf("rwbuf->len = 0\n");

			//加入未决队列中, 理论上, 这里是不会执行到的.(在当前线程读写正常的前提下)
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
			return;
		}
#endif

		int rd = recv(ss->fd, RWBUF_START_PTR(&(ss->rbuf)), buflen, 0);
		if (rd == -1) {
			//If there is no data readability
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				//if in the recv pending
				if (cds_list_empty(&ss->elem_pending_recv) == 0)
					cds_list_del_init(&ss->elem_pending_recv);
				return;
			}
			//If it is caused by interruption
			else if (errno == EINTR) {
				//if not recv pending
				if (cds_list_empty(&ss->elem_pending_recv))
					cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
					return;
			}
			rt = SERROR_SYSAPI_ERR;
			break;
		}
		else if (rd == 0) {
			rt = SERROR_PEER_DISCONN;
			break;
		}

		//et model add pending recv list
		/*if (ss->flag.etmod & EV_ET) {
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
		}*/

		if (rd < buflen) {
			//如何读到的长度不等于提供的的长度, 那么说明读完了, 从未决队列中移除
			if (cds_list_empty(&ss->elem_pending_recv) == 0)
				cds_list_del_init(&ss->elem_pending_recv);
		}
		else {
			//如果读到的长度等于了提供的长度, 那么可能存在没读完的情况,按照EINTR处理
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
		}

		//修改接收缓冲区的长度, 不额外提供接口
		ss->rbuf.len += rd;
		//重置读尝试的次数
		ss->rtry_number = 0;
		return;
	} while (0);
	
	//sm_del_session 并标注原因
	/*if (rt == SERROR_SYSAPI_ERR) {
		printf("ip: [%s], port: [%d], msg: [%s]\n", ss->ip, ss->port, strerror(errno));
	}
	else if (rt == SERROR_PEER_DISCONN) {
		printf("ip: [%s], port: [%d], msg: [%s]\n", ss->ip, ss->port, "client disconnect");
	}*/


	if (rt == SERROR_SYSAPI_ERR)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));

#ifdef TEST_CODE
	else if (rt == SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif

	//如果是服务器则暂不回收, 等待重连
	if (cds_list_empty(&ss->elem_servers))
		sm_del_session(ss);
	else
		sf_del_session(ss);
}

static void sf_send_cb(sock_session_t* ss) {
	//如果已经完全关闭, 可能存在半连接,那么剩余的数据也应该尝试发送, 所以这个状态一定要严谨
	if (ss->flag.closed)
		return;

	//uint32_t len = RWBUF_GET_LEN(&ss->wbuf);
	int rt;
	do {
		uint32_t snd_len = RWBUF_GET_LEN(&ss->wbuf);
		if (!snd_len)
			return;
	
		int32_t sd = send(ss->fd, RWBUF_START_PTR(&ss->wbuf), snd_len, 0);
		if (sd == -1) {
			//If the interrupt or the kernel buffer is temporarily full
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (cds_list_empty(&ss->elem_pending_send))
					cds_list_add_tail(&ss->elem_pending_send, &ss->sm->list_pending_send);
				return;
			}
			//If is error
			else {
				if (cds_list_empty(&ss->elem_pending_send) == 0)
					cds_list_del_init(&ss->elem_pending_send);
				rt = SERROR_SYSAPI_ERR;
				break;
			}
		}
		else if (sd == 0) {
			rt = SERROR_PEER_DISCONN;
		}

		//丢弃掉已经写入内核缓冲区的数据
		rwbuf_aband_front(&ss->wbuf, sd);

		//if not complated, 如果请求发送的长度 > 成功发送的长度, 那么任务尚未完成
		if (snd_len - sd) {
			//这个函数会在原本的状态上判断, 如果有那么什么也不做并不会,并不会陷入内核
			rt = sf_add_event(ss->sm, ss, EV_WRITE);

			//几乎不会发生
			if (rt != SERROR_OK)
				break;

			//如果写未决, 那么重新规划wbuf的offset, 使其有充足的缓冲区以供使用
			rwbuf_replan(&ss->wbuf);

			//add send pending
			if (cds_list_empty(&ss->elem_pending_send)) 
				cds_list_add_tail(&ss->elem_pending_send, &ss->sm->list_pending_send);
				
		}
		else {
			sf_del_event(ss->sm, ss, EV_WRITE);
			//remove send pending
			if (cds_list_empty(&ss->elem_pending_send) == 0)
				cds_list_del_init(&ss->elem_pending_send);
		}

		//ok
		return;
	} while (0);
	
	//failed;
	//sm_del_session
	//sm_del_session 并标注原因
	/*if (rt == SERROR_SYSAPI_ERR) {
		printf("ip: [%s], port: [%d], msg: [%s]\n", ss->ip, ss->port, strerror(errno));
	}
	else if (rt == SERROR_PEER_DISCONN) {
		printf("ip: [%s], port: [%d], msg: [%s]\n", ss->ip, ss->port, "client disconnect");
	}
	sm_del_session(ss);*/
	
	if (rt == SERROR_SYSAPI_ERR)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));

#ifdef TEST_CODE
	else if(rt == SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif//TEST_CODE

	//sm_del_session(ss);
	//如果是服务器则暂不回收, 等待重连
	if (cds_list_empty(&ss->elem_servers))
		sm_del_session(ss);
	else
		sf_del_session(ss);
}



//处理写未决
static void sf_pending_send(session_manager_t* sm) {
	if (sm) {
		sock_session_t* ss, * n;
		if (cds_list_empty(&sm->list_pending_send) == 0) {
			cds_list_for_each_entry_safe(ss, n, &sm->list_pending_send, elem_pending_send) {
				//减少不必要的函数调用
				if (ss->flag.closed == 0 && RWBUF_GET_LEN(&ss->wbuf))
					sf_send_cb(ss);
				/*else if(RWBUF_GET_LEN(&ss->wbuf) == 0){
					if (++ss->wtry_number > 8) {
						if (cds_list_empty(&ss->elem_servers))
							sm_del_session(ss);
						else
							sf_del_session(ss);

						printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
					}
				}*/
					
			}
		}
	}
}

//处理读未决
static void sf_pending_recv(session_manager_t* sm) {
	if (sm) {
		sock_session_t* ss, * n;
		if (cds_list_empty(&sm->list_pending_recv) == 0) {
			cds_list_for_each_entry_safe(ss, n, &sm->list_pending_recv, elem_pending_recv) {
				//尚未关闭且有剩余缓冲区
				if (ss->flag.closed == 0) {
					//可能是监听套接字
					if (RWBUF_UNUSE_LEN(&ss->rbuf))
						//sf_recv_cb(ss);
						ss->recv_cb(ss);
					else {
						//尝试读取8次,缓冲区都没有空间, 那么一定输出BUF出现了问题, 在正常的前提下,这应该永远不会发生
						if (++ss->rtry_number > 8) {
							if (cds_list_empty(&ss->elem_servers))
								sm_del_session(ss);
							else
								sf_del_session(ss);
							printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Receive buffer full");
						}
					}
				}
				/*if (pos->flag.closed == 0 && RWBUF_UNUSE_LEN(&pos->rbuf))
					sf_recv_cb(pos);*/
			}
		}
	}
}

//清理所有断开连接的session
static void sf_clean_offline(session_manager_t* sm) {
	int rt;
	sock_session_t* pos, *n;
	cds_list_for_each_entry_safe(pos, n, &sm->list_offline, elem_offline) {
		cds_list_del_init(&pos->elem_offline);

		//rt = shutdown(pos->fd, SHUT_RDWR);
		rt = close(pos->fd);
		if (rt == -1)
			printf("close: %s\n", strerror(errno));

		sf_destruct_session(pos);
		cds_list_add_tail(&pos->elem_cache, &sm->list_session_cache);
	}
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
		sock_session_t* ss = _sm_malloc(sizeof(sock_session_t));
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
	ht_add_timer(sm->ht_timer, MAX_RECONN_SERVER_TIMEOUT * 1000, 0, -1, sf_timer_reconn_cb, &sm, sizeof(void*));

	return sm;

sm_init_manager_failed:
	if (cds_list_empty(&sm->list_session_cache) == 0) {
		sock_session_t* pos, *p;
		cds_list_for_each_entry_safe(pos, p, &sm->list_session_cache, elem_cache) {
			cds_list_del_init(&pos->elem_cache);
			_sm_free(pos);
		}
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
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_servers, elem_servers) {
		//printf("[%s] [%s:%d] [%s] Clean server session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		//sm_del_session(pos, 0);
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_listens, elem_listens) {
		//printf("[%s] [%s:%d] [%s] Clean listener session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		//close(pos->fd);
		//list_del_init(&pos->elem_listens);
		//s_free_session(sm, pos);

		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	//sm_clear_offline(sm);
	sf_clean_offline(sm);

	if (cds_list_empty(&sm->list_session_cache) == 0) {
		cds_list_for_each_entry_safe(pos, n, &sm->list_session_cache, elem_cache) {
			cds_list_del_init(&pos->elem_cache);
			rwbuf_free(&pos->rbuf);
			rwbuf_free(&pos->wbuf);
			_sm_free(pos);
		}
	}

	/*while (cds_list_empty(&sm->list_session_cache) == 0) {
		pos = cds_list_entry(sm->list_session_cache.next, struct sock_session, elem_cache);
		cds_list_del_init(&pos->elem_cache);
		rwbuf_free(&pos->rbuf);
		rwbuf_free(&pos->wbuf);
		printf("free: %p\n", pos);
		_sm_free(pos);
	}*/

	if (sm->ht_timer) 
		ht_destroy_heap_timer(sm->ht_timer);

	if (sm) 
		free(sm);
	
}

void sm_set_run(session_manager_t* sm, uint8_t run) {
	if (sm) {
		sm->flag.running = run;
	}
}

sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint8_t enable_et, uint32_t max_send_len, 
	session_behavior_t behavior, void* udata, uint8_t udata_len) {
	sock_session_t* ss = 0;
	int rt, fd, ev, optval = 1;

	if (!sm) return ss;

	fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)  return 0;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	rt = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (rt == -1) 
		return 0;

	rt = bind(fd, (const struct sockaddr*)&sin, sizeof(sin));
	if (rt == -1)
		return 0;

	rt = listen(fd, max_listen);
	if (rt == -1)
		return 0;

	ss = sf_cache_session(sm);
	if (ss == 0)
		return 0;

	rt = sf_construct_session(sm, ss, fd, enable_et, "0.0.0.0", port, max_send_len, sf_accpet_cb/*accpet_function*/, behavior, udata, udata_len);
	if (rt != SERROR_OK) {
		sf_free_session(sm, ss);
		return 0;
	}

	//add epoll status
	ev = (enable_et ? EV_ET : 0) | EV_RECV;

	rt = sf_add_event(sm, ss, ev);
	if (rt) {
		sf_free_session(sm, ss);
		return 0;
	}

	//add to listener list
	cds_list_add_tail(&(ss->elem_listens), &(sm->list_listens));
	return ss;
}

sock_session_t* sm_add_client(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, uint8_t enable_et, 
	uint32_t max_send_len, uint8_t add_online, session_behavior_t behavior, void* udata, uint8_t udata_len) {

	if (!sm || fd < 0)
		return 0;

	sock_session_t* ss = sf_cache_session(sm);
	if (!ss)
		return 0;

	int32_t rt = sf_construct_session(sm, ss, fd, enable_et, ip, port, max_send_len, sf_recv_cb/*recv_cb*/, behavior, udata, udata_len);

	//add epoll status
	int ev = (enable_et ? EV_ET : 0) | EV_RECV;

	rt = sf_add_event(sm, ss, ev);
	if (rt) {
		sf_free_session(sm, ss);
		return 0;
	}

	//add to online list
	if(add_online)
		cds_list_add_tail(&(ss->elem_online), &(sm->list_online));
	return ss;
}

sock_session_t* sm_add_server(session_manager_t* sm, const char* domain, uint16_t port, uint8_t enable_et, uint32_t max_send_len,
	session_behavior_t behavior, void* udata, uint8_t udata_len) {

	if (!sm)
		return 0;

	int fd, rt, ev = 0;
	sock_session_t* ss = 0;
	struct sockaddr_in sin;
	char ip[32] = { 0 };

	do {
		rt = sf_domain2ip(domain, ip, sizeof(ip));
		if (rt != SERROR_OK)
			break;

		fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
			break;

		ss = sf_cache_session(sm);
		if (!ss) 
			break;

		rt = sf_construct_session(sm, ss, fd, enable_et, ip, port, max_send_len, sf_recv_cb, behavior, udata, udata_len);
		if (rt != SERROR_OK)
			break;

		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		sin.sin_addr.s_addr = inet_addr(ip);

		rt = connect(fd, &sin, sizeof(sin));
		//if connect error
		if (rt == -1 && errno != EINPROGRESS) {
			////set need reconnect
			//ss->flag.closed = ~0;
			break;
		}
		else {
			//add epoll status
			ev = (enable_et ? EV_ET : 0) | EV_RECV;
			rt = sf_add_event(sm, ss, ev);
			if (rt != SERROR_OK)
				break;
		}

		//If it is in ET mode and the connection fails, waiting reconnect
		if (enable_et == 0 && rt == -1)
			break;

		cds_list_add_tail(&ss->elem_servers, &sm->list_servers);
		return ss;

	} while (0);


	if (ss)
		sf_free_session(sm, ss);

	if (fd != -1)
		close(fd);
	return 0;
}

uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval_ms, uint32_t delay_ms, int32_t repeat, void(*timer_cb)(uint32_t, void*), void* udata, uint8_t udata_len) {
	if (sm == 0 || sm->ht_timer == 0)
		return -1;

	return ht_add_timer(sm->ht_timer, interval_ms, delay_ms, repeat, timer_cb, udata, udata_len);
}

void sm_del_timer(session_manager_t* sm, uint32_t timer_id, uint32_t is_incallback) {
	if (sm == 0 || timer_id < 0)
		return;

	if (is_incallback)
		ht_del_timer_incallback(sm->ht_timer, timer_id);
	else
		ht_del_timer(sm->ht_timer, timer_id);
}

void sm_del_session(sock_session_t* ss) {

	//统一操作, 但不包括服务器列表
	sf_del_session(ss);

	if (cds_list_empty(&ss->elem_servers) == 0)
		cds_list_del_init(&ss->elem_servers);

	//加入到离线队列
	cds_list_add_tail(&ss->elem_offline, &ss->sm->list_offline);

	//因为fd尚未回收, 统一在一个函数内操作,减少用户态->内核态的切换
}

int sm_add_signal(session_manager_t* sm, uint32_t sig, void (*cb)(int)) {
	struct sigaction new_act;
	memset(&new_act, 0, sizeof(new_act));
	new_act.sa_handler = cb;
	sigfillset(&new_act.sa_mask);

	return sigaction(sig, &new_act, 0);
}

int32_t sm_run2(session_manager_t* sm, uint64_t us) {
	struct epoll_event events[MAX_EPOLL_SIZE];

	int ret = epoll_wait(sm->ep_fd, events, MAX_EPOLL_SIZE, us);

	if (ret == -1) {
		if (errno != EINTR) { return -1; }
		//printf("epoll_wait: %d, %s\n", errno, strerror(errno));
		return 0;
	}

	for (int i = 0; i < ret; ++i) {
		sock_session_t* ss = (struct sock_session*)events[i].data.ptr;
		if (events[i].events & EPOLLIN) {
			ss->recv_cb(ss);
		}
		if (events[i].events & EPOLLOUT) {
			sf_send_cb(ss);
		}
	}

	sf_pending_send(sm);
	sf_pending_recv(sm);
	sf_clean_offline(sm);

	return ~0;
}

void sm_run(session_manager_t* sm) {
	while (sm->flag.running) {
		uint64_t waitms = ht_update_timer(sm->ht_timer);

		if (cds_list_empty(&sm->list_pending_send) == 0 || cds_list_empty(&sm->list_pending_recv) == 0)
			waitms = 0;

		//signal
		if (sm_run2(sm, waitms) == 0) {
			if (errno == SIGQUIT)
				sm->flag.running = 0;
		}
	}
}