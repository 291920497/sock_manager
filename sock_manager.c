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



//heap_timer
#include "tools/heap_timer/heap_timer.h"
#include "tools/common/nofile_ctl.h"
#include "tools/rwbuf/rwbuf.h"

#include "smlist.h"

#if (ENABLE_SSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif//ENABLE_SSL

#define _sm_malloc malloc
#define _sm_realloc realloc
#define _sm_free	free

#define MAX_RECONN_SERVER_TIMEOUT 5

//sock_session 的状态机
typedef struct session_flag {
	int32_t		closed : 1;
//	int32_t		etmod : 1;
	int32_t		comming : 1;				//是否有数据到来
	int32_t		ready : 1;					//是否准备就绪,这将影响广播时是否将消息下发到这个session, 例如ws wss握手
	int32_t		tls_handshake : 1;			//是否是ws websocket
	int32_t		tls : 1;					//是否是wss websocket
	int32_t		tls_rwantw : 1;				//是否想在可读事件发生的时候调用SSL_write
	int32_t		tls_wwantr : 1;				//是否期望在可写事件发生的时候调用SSL_read
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

typedef void (*session_rw)(sock_session_t*);

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

	void*		tls_ctx;		//wss使用到的上下文

	rcv_decode_mod_t		decode_mod;		//解包模块
	session_rw				recv_cb;		//可读事件回调
	session_rw				send_cb;		//可写事件回调
	session_behavior_t		uevent;			//用户行为

	struct session_manager* sm;

	_sm_list_head	elem_online;
	_sm_list_head	elem_offline;
	_sm_list_head	elem_servers;
	_sm_list_head	elem_listens;
	_sm_list_head	elem_pending_recv;
	_sm_list_head	elem_pending_send;
	_sm_list_head	elem_cache;
}sock_session_t;

//session manager
typedef struct session_manager {
	int32_t			ep_fd;
	manager_flag_t	flag;		//状态机
	heap_timer_t*	ht_timer;	//定时器

	_sm_list_head list_online;
	_sm_list_head list_offline;
	_sm_list_head list_servers;
	_sm_list_head list_listens;
	_sm_list_head list_pending_recv;
	_sm_list_head list_pending_send;
	_sm_list_head list_session_cache;

//	_sm_list_head list_msg_cache;	//用于单次调用缓存的所有消息

//	uint8_t		udatalen;		//用户数据长度
//	uint8_t		udata[MAX_USERDATA_LEN];		//用户数据, 用户自定义
}session_manager_t;

/*
	static variable
*/

//static CDS_LIST_HEAD(_slist_session_cache);



/*
	static function
*/

//tls错误
#if (ENABLE_SSL)
static int32_t sf_tls_err(SSL* ssl, int32_t rc) {
	int32_t err = SSL_get_error(ssl, rc);
	//清除当前线程的错误
	ERR_clear_error();

	//暂时不太搞得清楚其他错误的具体原因
	//if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
	//	return SSL_ERROR_NONE;

	return err;
}
#endif//ENABLE_SSL

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
static int32_t sf_construct_session(session_manager_t* sm, sock_session_t* ss, int32_t fd, const char* ip, uint16_t port,uint32_t send_len, session_event_cb recv_cb, session_event_cb send_cb, session_behavior_t uevent, void* udata, uint16_t udata_len) {
	int rt;

	if (!ss || !sm || udata_len > MAX_USERDATA_LEN)
		return SERROR_INPARAM_ERR;

	//memset(ss, 0, sizeof(sock_session_t));
	ss->fd = fd;
	ss->epoll_state = 0;
	ss->sm = sm;
	ss->port = port;
	ss->recv_cb = recv_cb;
	ss->send_cb = send_cb;
	ss->last_active = time(0);
	ss->uuid_hash = sf_uuidhash();
	memset(&ss->decode_mod, 0, sizeof(ss->decode_mod));
	memcpy(&ss->uevent, &uevent, sizeof(uevent));
	strcpy(ss->ip, ip);
	
	ss->flag.closed = 0;
	ss->flag.comming = 0;
	ss->flag.ready = 0;
	ss->flag.tls_handshake = 0;
	ss->flag.tls = 0;
	ss->flag.tls_rwantw = 0;
	ss->flag.tls_wwantr = 0;
	ss->tls_ctx = 0;

	nofile_set_nonblocking(fd);

	if (udata && udata_len)
		memcpy(&ss->udata, &udata, udata_len);

	rt = rwbuf_relc(&ss->wbuf, send_len);
	if (rt != SERROR_OK)
		goto session_construct_failed;

	rt = rwbuf_relc(&ss->rbuf, send_len * 2);
	if (rt != SERROR_OK)
		goto session_construct_failed;

	_SM_LIST_INIT_HEAD(&(ss->elem_online));
	_SM_LIST_INIT_HEAD(&(ss->elem_offline));
	_SM_LIST_INIT_HEAD(&(ss->elem_servers));
	_SM_LIST_INIT_HEAD(&(ss->elem_listens));
	_SM_LIST_INIT_HEAD(&(ss->elem_pending_recv));
	_SM_LIST_INIT_HEAD(&(ss->elem_pending_send));

	//构建时不考虑cache cache由manager统一管理
	//_SM_LIST_INIT_HEAD(&(ss->elem_cache));

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
//	ss->flag.etmod = 0;
	ss->flag.comming = 0;
	ss->flag.ready = 0;
	ss->flag.tls_handshake = 0;
	ss->flag.tls = 0;
	ss->flag.tls_rwantw = 0;
	ss->flag.tls_wwantr = 0;
	ss->tls_ctx = 0;

	memset(&ss->decode_mod, 0, sizeof(ss->decode_mod));
	memset(&ss->uevent, 0, sizeof(session_behavior_t));
	rwbuf_clear(&ss->wbuf);
	rwbuf_clear(&ss->rbuf);
	
	//这一段用于区分于初始化
	if(ss->elem_online.next)
		_SM_LIST_DEL(&(ss->elem_online));
	if (ss->elem_offline.next)
		_SM_LIST_DEL(&(ss->elem_offline));
	if (ss->elem_servers.next)
		_SM_LIST_DEL(&(ss->elem_servers));
	if (ss->elem_listens.next)
		_SM_LIST_DEL(&(ss->elem_listens));
	if (ss->elem_pending_recv.next)
		_SM_LIST_DEL(&(ss->elem_pending_recv));
	if (ss->elem_pending_send.next)
		_SM_LIST_DEL(&(ss->elem_pending_send));
	if (ss->elem_cache.next)
		_SM_LIST_DEL(&(ss->elem_cache));

	_SM_LIST_INIT_HEAD(&(ss->elem_online));
	_SM_LIST_INIT_HEAD(&(ss->elem_offline));
	_SM_LIST_INIT_HEAD(&(ss->elem_servers));
	_SM_LIST_INIT_HEAD(&(ss->elem_listens));
	_SM_LIST_INIT_HEAD(&(ss->elem_pending_recv));
	_SM_LIST_INIT_HEAD(&(ss->elem_pending_send));
	_SM_LIST_INIT_HEAD(&(ss->elem_cache));
}

//从cache内获取一个sock_session_t
static sock_session_t* sf_cache_session(session_manager_t* sm) {
	sock_session_t* ss = 0;

	if (!sm)
		return ss;

	if (_SM_LIST_EMPTY(&(sm->list_session_cache))) {
		//new session
		ss = _sm_malloc(sizeof(sock_session_t));
		if (ss) {
			memset(ss, 0, sizeof(sock_session_t));
			sf_destruct_session(ss);
		}
		return ss;
	}

	ss = _SM_LIST_ENTRY(sm->list_session_cache.next, struct sock_session, elem_cache);
	_SM_LIST_DEL_INIT(&ss->elem_cache);
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
	_SM_LIST_ADD_TAIL(&ss->elem_cache, &sm->list_session_cache);
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
//	if (ss->flag.etmod)
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
		//ev = (ss->flag.etmod ? EV_ET : 0) | EV_RECV;
		ev = EV_ET | EV_RECV;
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
	_SM_LIST_FOR_EACH_ENTRY(ss, &sm->list_servers, elem_servers) {
		if (ss->flag.closed) {
			rt = sf_reconnect_server(ss);
			if (rt == SERROR_OK) {
				msg = einprogress;
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

static void sf_del_session(sock_session_t* ss, uint8_t remove_online) {
	if (ss) {
		sf_del_event(ss->sm, ss, EV_RECV | EV_WRITE);

#if(ENABLE_SSL)
		if (ss->tls_ctx) {
			if (_SM_LIST_EMPTY(&ss->elem_listens))
				SSL_free(ss->tls_ctx);
			else
				SSL_CTX_free(ss->tls_ctx);
			ss->tls_ctx = 0;
		}
#endif//ENABLE_SSL

		//发送一个事件给消费线程, 通知断开事件以及尚未发送的数据
		//...


		//sf_destruct_session(ss);



		//从未决队列中移除
		if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_pending_recv);

		if (_SM_LIST_EMPTY(&ss->elem_pending_send) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_pending_send);

		//这里是为了迁就带有数据的FIN报文, 让session延迟回收
		if (remove_online) {
			if (_SM_LIST_EMPTY(&ss->elem_online) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_online);
		}

		if (_SM_LIST_EMPTY(&ss->elem_listens) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_listens);

		/*if (_SM_LIST_EMPTY(&ss->elem_servers) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_servers);*/

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
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_recv);	
			return;
		}
		else if (c_fd == -1) {
			//printf("[%s] [%s:%d] [%s] Accept function failed. errmsg: [ %s ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno));
			//系统API调用错误 查看errno
			printf("[%s] [%s:%d] [%s], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, errno, strerror(errno));
			if(_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, & ss->sm->list_pending_recv);
			return;
		}

		const char* ip = inet_ntoa(c_sin.sin_addr);
		unsigned short port = ntohs(c_sin.sin_port);
		//printf("fd: %d\n", c_fd);
		sock_session_t* css = sm_add_client(ss->sm, c_fd, ip, port, ss->wbuf.size, ss->flag.tls, ss->tls_ctx, 1, ss->uevent, ss->udata, ss->udatalen);
		if (!css) {
			//系统API调用错误 查看errno
			printf("[%s] [%s:%d] [%s], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, errno, strerror(errno));
			close(c_fd);
			return;
		}
		else {
			printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, css->ip, css->port, "accept");
		}

	} while (1);
}

static void sf_recv_cb(sock_session_t* ss) {
	if (ss->flag.closed)
		return;

	int32_t rt, eno;
	do {
		int32_t buflen = RWBUF_UNUSE_LEN(&(ss->rbuf));

#if TEST_CODE
		//如果已经没有额外可用的buffer
		if (buflen == 0) {
			printf("rwbuf->len = 0\n");

			//加入未决队列中, 理论上, 这里是不会执行到的.(在当前线程读写正常的前提下)
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
			return;
		}
#endif

		int rd = recv(ss->fd, RWBUF_START_PTR(&(ss->rbuf)) + RWBUF_GET_LEN(&(ss->rbuf)), buflen, 0);
		if (rd == -1) {
			eno = errno;
			//If there is no data readability
			if (eno == EAGAIN) {
				//if in the recv pending
				if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
					_SM_LIST_DEL_INIT(&ss->elem_pending_recv);
				return;
			}
			//If it is caused by interruption
			else if (eno == EINTR) {
				//if not recv pending
				if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
					_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
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
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
		}*/

		if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
			_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);

		/*
		if (rd < buflen) {
			//如何读到的长度不等于提供的的长度, 那么说明读完了, 从未决队列中移除
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_recv);
		}
		else {
			//如果读到的长度等于了提供的长度, 那么可能存在没读完的情况,按照EINTR处理
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
		}
		*/

		//修改接收缓冲区的长度, 不额外提供接口
		ss->rbuf.len += rd;
		//重置读尝试的次数
		ss->rtry_number = 0;
		//设置为有数据到来
		ss->flag.comming = ~0;
		return;
	} while (0);
	
	if (rt == SERROR_SYSAPI_ERR)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));

#ifdef TEST_CODE
	else if (rt == SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif

	//如果是服务器则暂不回收, 等待重连
	if (_SM_LIST_EMPTY(&ss->elem_servers))
		sm_del_session(ss);
	else {
		if (ss->flag.comming)
			sf_del_session(ss, 0);
		else
			sf_del_session(ss, 1);
	}
}

/*
	这个函数作为代码复用, 所以将涉及到session的操作, 这会影响tls的标识
	成功: SERROR_OK
	失败: 返回serror.h 中的错误码, 可能将结合ssl库的错误定位真实错误原因
*/
static int32_t sf_tls_read_err(sock_session_t* ss, int32_t rd, int32_t* out_tls_err) {
	int rt, err, eno, serr = 0;
#if (ENABLE_SSL)
	SSL* ssl = ss->tls_ctx;
	rt = sf_tls_err(ssl, rd);
	*out_tls_err = rt;
	err = ERR_get_error();

	switch (rt) {
		//tls 协议已经出现关闭警告
	case SSL_ERROR_ZERO_RETURN:
		serr = SERROR_TLS_WARCLS_ERR;
		break;
		//协议错误
	case SSL_ERROR_SSL:
		serr = SERROR_TLS_SSL_ERR;
		break;
	}

	//判断是否出现致命性错误
	if (serr)
		return serr;

	//判断是否为底层传输协议出错
	if (rt == SSL_ERROR_SYSCALL) {
		//表示没有出现错误, 那么是底层传输协议错误
		if (err == 0) {
			serr = SERROR_PEER_DISCONN;
			return serr;
		}

		eno = errno;
		//If there is no data readability
		if (eno == EAGAIN) {
			//if in the recv pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_recv);
			return SERROR_OK;
		}
		//If it is caused by interruption
		else if (eno == EINTR) {
			//if not recv pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
			return SERROR_OK;
		}

		//其他错误, 应该关闭
		serr = SERROR_SYSAPI_ERR;
		return serr;
	}

	//如果出现了重新协商, 希望在可写事件发生时再次调用SSL_read
	if (rt == SSL_ERROR_WANT_WRITE) {
		ss->flag.tls_wwantr = ~0;

		//添加可写事件
		if(sf_add_event(ss->sm, ss, EV_WRITE) == 0)
			return SERROR_OK;

		return SERROR_SYSAPI_ERR;
	}

	//如何希望下次可读事件发生时再调用, 清除未决队列
	if (rt == SSL_ERROR_WANT_READ) {
		if (_SM_LIST_EMPTY(&ss->elem_pending_recv) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_pending_recv);
		return SERROR_OK;
	}

	//如果都不是以上情况, 那么应该关闭并从SSL库中获取错误信息
	//打印错误
	serr = SERROR_TLS_LIB_ERR;
#endif
	return serr;
}

static int32_t sf_tls_send_err(sock_session_t* ss, int32_t sd, int32_t* out_tls_err) {
	int rt, err, serr, eno;
#if (ENABLE_SSL)
	SSL* ssl = ss->tls_ctx;
	rt = sf_tls_err(ssl, sd);
	*out_tls_err = rt;
	err = ERR_get_error();

	switch (rt) {
		//tls 协议已经出现关闭警告
	case SSL_ERROR_ZERO_RETURN:
		serr = SERROR_TLS_WARCLS_ERR;
		break;
		//协议错误
	case SSL_ERROR_SSL:
		serr = SERROR_TLS_SSL_ERR;
		break;
	}

	//判断是否出现致命性错误
	if (serr)
		return serr;

	//判断是否为底层传输协议出错
	if (rt == SSL_ERROR_SYSCALL) {
		//表示没有出现错误, 那么是底层传输协议错误
		if (err == 0) {
			serr = SERROR_PEER_DISCONN;
			return serr;
		}

		eno = errno;
		//If there is no data readability
		if (eno == EAGAIN) {
			//if in the recv pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_send) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_send);
			return SERROR_OK;
		}
		//If it is caused by interruption
		else if (eno == EINTR) {
			//if not recv pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_send))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_send, &ss->sm->list_pending_send);
			return SERROR_OK;
		}

		//其他错误, 应该关闭
		serr = SERROR_SYSAPI_ERR;
		return serr;
	}

	//如果出现了重新协商, 希望在可写事件发生时再次调用SSL_read
	if (rt == SSL_ERROR_WANT_WRITE) {
		//添加可写事件
		if (sf_add_event(ss->sm, ss, EV_WRITE) == 0)
			return SERROR_OK;

		return SERROR_SYSAPI_ERR;
	}

	//如果在可读事件中调用
	if (rt == SSL_ERROR_WANT_READ) {
		//recv事件一直在, 静等回调即可
		ss->flag.tls_rwantw = ~0;
		return SERROR_OK;
	}

	//如果都不是以上情况, 那么应该关闭并从SSL库中获取错误信息
	//打印错误
	serr = SERROR_TLS_LIB_ERR;
#endif
	return serr;
}


//这个函数需要用到
static void sf_tls_send_cb(sock_session_t* ss);
static void sf_tls_recv_cb(sock_session_t* ss) {
	if (ss->flag.closed)
		return;

#if (ENABLE_SSL)
	int32_t rt = 0, err, eno, rd, serr = 0;
	SSL* ssl = ss->tls_ctx;

	//是否正在重新协商
	if (ss->flag.tls_rwantw) {
		//立即还原可写事件调用读
		ss->flag.tls_wwantr = 0;
		sf_tls_send_cb(ss);
		return;
	}

	do {
		if (ss->flag.tls_handshake) {
			int buflen = RWBUF_UNUSE_LEN(&(ss->rbuf));
			rd = SSL_read(ssl, RWBUF_START_PTR(&(ss->rbuf)) + RWBUF_GET_LEN(&(ss->rbuf)), buflen);
			if (rd <= 0) {
				serr = sf_tls_read_err(ss, rd, &rt);
				//预期内的错误
				if (serr == SERROR_OK)
					return;

				break;
			}

			/*
				再尝试读取一次, 预防以下情况
				1. 多个包一起到达, 但在ET模式下作为一次事件通知
				2. FIN报文携带数据
			*/
			if (_SM_LIST_EMPTY(&ss->elem_pending_recv))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_recv, &ss->sm->list_pending_recv);

			//修改接收缓冲区的长度, 不额外提供接口
			ss->rbuf.len += rd;
			//重置读尝试的次数
			ss->rtry_number = 0;
			//设置为有数据到来
			ss->flag.comming = ~0;
			return;
		}
		else {
			//如果握手完成
			if ((rd = SSL_accept(ss->tls_ctx)) == 1) {
				ss->flag.tls_handshake = ~0;
				return;
			}
			
			serr = sf_tls_read_err(ss, rd, &rt);
			//预期内的错误
			if (serr == SERROR_OK)
				return;

			break;
		}
	} while (0);


	switch (serr) {
	case SERROR_SYSAPI_ERR:
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));
		break;
	case SERROR_PEER_DISCONN:
#ifdef TEST_CODE
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif//TEST_CODE
		break;
		//以下都是SSL的错误了
	default:
		SSL_shutdown(ssl);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], serr: [%d], errno: [%d], tls_err: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errno, rt, "Active shutdown");
	}

	if (_SM_LIST_EMPTY(&ss->elem_servers))
		sm_del_session(ss);
	else {
		if (ss->flag.comming)
			sf_del_session(ss, 0);
		else
			sf_del_session(ss, 1);
	}

#endif//ENABLE_SSL
}

static void sf_send_cb(sock_session_t* ss) {
	//如果已经完全关闭, 可能存在半连接,那么剩余的数据也应该尝试发送, 所以这个状态一定要严谨
	if (ss->flag.closed)
		return;

	//uint32_t len = RWBUF_GET_LEN(&ss->wbuf);
	int32_t rt;
	do {
		uint32_t snd_len = RWBUF_GET_LEN(&ss->wbuf);
		if (!snd_len)
			return;

		int32_t sd = send(ss->fd, RWBUF_START_PTR(&ss->wbuf), snd_len, 0);
		if (sd == -1) {
			//If the interrupt or the kernel buffer is temporarily full
			if (errno == EAGAIN || errno == EINTR) {
				if (_SM_LIST_EMPTY(&ss->elem_pending_send))
					_SM_LIST_ADD_TAIL(&ss->elem_pending_send, &ss->sm->list_pending_send);
				return;
			}
			//If is error
			else {
				if (_SM_LIST_EMPTY(&ss->elem_pending_send) == 0)
					_SM_LIST_DEL_INIT(&ss->elem_pending_send);
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
			if (_SM_LIST_EMPTY(&ss->elem_pending_send))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_send, &ss->sm->list_pending_send);

		}
		else {
			sf_del_event(ss->sm, ss, EV_WRITE);
			//remove send pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_send) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_send);
		}

		//ok
		return;
	} while (0);


	if (rt == SERROR_SYSAPI_ERR)
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));
	else if (rt == SERROR_PEER_DISCONN)
#ifdef TEST_CODE
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif//TEST_CODE

	//sm_del_session(ss);
	//如果是服务器则暂不回收, 等待重连
	if (_SM_LIST_EMPTY(&ss->elem_servers))
		sm_del_session(ss);
	else
		sf_del_session(ss, 1);
}

static void sf_tls_send_cb(sock_session_t* ss) {
	if (ss->flag.closed)
		return;

#if (ENABLE_SSL)
	int32_t rt, snd_len, err, eno, sd, serr = 0;
	SSL* ssl = ss->tls_ctx;

	//是否正在重新协商
	if (ss->flag.tls_wwantr) {
		//立即还原可写事件调用读
		ss->flag.tls_wwantr = 0;
		sf_tls_recv_cb(ss);
		return;
	}

	do {
		snd_len = RWBUF_GET_LEN(&ss->wbuf);
		//没有数据可以发送, 这里不在外面判断, 为了应对TLS的重新协商
		if (!snd_len) return;

		sd = SSL_write(ssl, RWBUF_START_PTR(&ss->wbuf), snd_len);
		if (sd <= 0) {
			//写判断错误
			serr = sf_tls_send_err(ss, sd, &rt);
			//预期内的错误
			if (serr == SERROR_OK)
				return;

			break;
		}

		rwbuf_aband_front(&ss->wbuf, sd);
		//if not complated, 如果请求发送的长度 > 成功发送的长度, 那么任务尚未完成
		if (snd_len - sd) {
			if (sf_add_event(ss->sm, ss, EV_WRITE) != 0) {
				serr = SERROR_SYSAPI_ERR;
				break;
			}

			rwbuf_replan(&ss->wbuf);

			//add send pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_send))
				_SM_LIST_ADD_TAIL(&ss->elem_pending_send, &ss->sm->list_pending_send);
		}
		else {
			sf_del_event(ss->sm, ss, EV_WRITE);
			//remove send pending
			if (_SM_LIST_EMPTY(&ss->elem_pending_send) == 0)
				_SM_LIST_DEL_INIT(&ss->elem_pending_send);
		}

		return;
	} while (0);
	
	switch (serr) {
	case SERROR_SYSAPI_ERR:
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));
		break;
	case SERROR_PEER_DISCONN:
#ifdef TEST_CODE
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
#endif//TEST_CODE
		break;
		//以下都是SSL的错误了
	default:
		SSL_shutdown(ssl);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], serr: [%d], errno: [%d], tls_err: [%d], ssl_err: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errno, rt, err, "Active shutdown");
	}

	if (_SM_LIST_EMPTY(&ss->elem_servers))
		sm_del_session(ss);
	else
		sf_del_session(ss, 1);

#endif//ENABLE_SSL
}



//处理写未决
static void sf_pending_send(session_manager_t* sm) {
	if (sm) {
		sock_session_t* ss, * n;
		if (_SM_LIST_EMPTY(&sm->list_pending_send) == 0) {
			_SM_LIST_FOR_EACH_ENTRY_SAFE(ss, n, &sm->list_pending_send, elem_pending_send) {
				//减少不必要的函数调用
				//if (ss->flag.closed == 0 && RWBUF_GET_LEN(&ss->wbuf))
				
				//迎合tls, 不对写入长度做判断, 应该真正写入的数据可能在Bio中
				if (ss->flag.closed == 0) {
					/*if (ss->flag.tls)
						sf_tls_send_cb(ss);
					else
						sf_send_cb(ss);*/
					if (ss->send_cb)
						ss->send_cb(ss);
				}			
			}
		}
	}
}

//处理读未决
static void sf_pending_recv(session_manager_t* sm) {
	if (sm) {
		sock_session_t* ss, * n;
		if (_SM_LIST_EMPTY(&sm->list_pending_recv) == 0) {
			_SM_LIST_FOR_EACH_ENTRY_SAFE(ss, n, &sm->list_pending_recv, elem_pending_recv) {
				//尚未关闭且有剩余缓冲区
				if (ss->flag.closed == 0) {
					//可能是监听套接字
					if (RWBUF_UNUSE_LEN(&ss->rbuf))
						//sf_recv_cb(ss);
						ss->recv_cb(ss);
					else {
						//尝试读取8次,缓冲区都没有空间, 那么一定输出BUF出现了问题, 在正常的前提下,这应该永远不会发生
						if (++ss->rtry_number > 8) {
							if (_SM_LIST_EMPTY(&ss->elem_servers))
								sm_del_session(ss);
							else
								sf_del_session(ss, 1);
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
	sock_session_t* ss, *n;

	//这一步原本是在sf_del_sesion内的操作, 但是为了迎合带数据的FIN报文, 所以在这里新增了这一块代码
	_SM_LIST_FOR_EACH_ENTRY_SAFE(ss, n, &sm->list_online, elem_online) {		
		if (ss->flag.closed) {
			//if (_SM_LIST_EMPTY(&ss->elem_online) == 0)
			_SM_LIST_DEL_INIT(&ss->elem_online);

			//加入到离线队列
			if (_SM_LIST_EMPTY(&ss->elem_offline) == 0)
				_SM_LIST_ADD_TAIL(&ss->elem_offline, &ss->sm->list_offline);
		}
	}

	_SM_LIST_FOR_EACH_ENTRY_SAFE(ss, n, &sm->list_offline, elem_offline) {
		_SM_LIST_DEL_INIT(&ss->elem_offline);

		//rt = shutdown(pos->fd, SHUT_RDWR);
		rt = close(ss->fd);
		if (rt == -1)
			printf("close: %s\n", strerror(errno));

		sf_destruct_session(ss);
		_SM_LIST_ADD_TAIL(&ss->elem_cache, &sm->list_session_cache);
	}
}

//回调解包函数
static void sf_call_decode_fn(session_manager_t* sm) {
	int32_t rt, len;
	uint32_t offset;
	int8_t* data;
	sock_session_t* ss, * n;
	rwbuf_t* rbuf;
	_SM_LIST_FOR_EACH_ENTRY_SAFE(ss, n, &sm->list_online, elem_online) {
		if (ss->flag.comming == 0)
			continue;

		rbuf = &ss->rbuf;

		do {
			offset = 0;
			len = RWBUF_GET_LEN(rbuf);
			data = RWBUF_START_PTR(rbuf);

			if (len && len >= ss->decode_mod.lenght_tirgger) {
				if (ss->uevent.decode_cb) {
					rt = ss->uevent.decode_cb(ss, data, len, &ss->decode_mod, &offset);

					if (rt == 0)
						break;
					else if (rt < 0) {
						if (_SM_LIST_EMPTY(&ss->elem_servers))
							sm_del_session(ss);
						else
							sf_del_session(ss, 1);
						break;
					}

					if (rwbuf_aband_front(rbuf, rt) != SERROR_OK) {
						if (_SM_LIST_EMPTY(&ss->elem_servers))
							sm_del_session(ss);
						else
							sf_del_session(ss, 1);
						break;
					}

					//发布一个接收消息
					if (ss->flag.closed) {
						data + offset;
						rt - offset;
					}
				}
			}
		} while ((len - rt) >= ss->decode_mod.lenght_tirgger && ss->decode_mod.lenght_tirgger != 0/*这是怕解包函数啥也不做导致死循环*/);

		ss->flag.comming = 0;
		rwbuf_replan(rbuf);
	}
}

/*
	global function
*/

session_manager_t* sm_init_manager(uint32_t session_cache_size) {
	session_manager_t* sm = (session_manager_t*)malloc(sizeof(session_manager_t));
	if (!sm)return 0;

	memset(sm, 0, sizeof(session_manager_t));
	sm->flag.running = 1;

	//Init all list
	_SM_LIST_INIT_HEAD(&(sm->list_online));
	_SM_LIST_INIT_HEAD(&(sm->list_offline));
	_SM_LIST_INIT_HEAD(&(sm->list_servers));
	_SM_LIST_INIT_HEAD(&(sm->list_listens));
	_SM_LIST_INIT_HEAD(&(sm->list_pending_recv));
	_SM_LIST_INIT_HEAD(&(sm->list_pending_send));
	_SM_LIST_INIT_HEAD(&(sm->list_session_cache));

	//create cache_session
	for (int i = 0; i < session_cache_size; ++i) {
		sock_session_t* ss = _sm_malloc(sizeof(sock_session_t));
		if (ss) {
			memset(ss, 0, sizeof(sock_session_t));
			sf_destruct_session(ss);
			_SM_LIST_ADD_TAIL(&ss->elem_cache, &sm->list_session_cache);
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

#if(ENABLE_SSL)
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
#endif//ENABLE_SSL

	//add default timer
	//heart cb
	//ht_add_timer(sm->ht_timer, MAX_HEART_TIMEOUT * 1000, 0, -1, cb_on_heart_timeout, sm);
	//server reconnect cb
	ht_add_timer(sm->ht_timer, MAX_RECONN_SERVER_TIMEOUT * 1000, 0, -1, sf_timer_reconn_cb, &sm, sizeof(void*));

	return sm;

sm_init_manager_failed:
	if (_SM_LIST_EMPTY(&sm->list_session_cache) == 0) {
		sock_session_t* pos, *p;
		_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, p, &sm->list_session_cache, elem_cache) {
			_SM_LIST_DEL_INIT(&pos->elem_cache);
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
	_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &sm->list_online, elem_online) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &sm->list_servers, elem_servers) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &sm->list_listens, elem_listens) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	//sm_clear_offline(sm);
	sf_clean_offline(sm);

	if (_SM_LIST_EMPTY(&sm->list_session_cache) == 0) {
		_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &sm->list_session_cache, elem_cache) {
			_SM_LIST_DEL_INIT(&pos->elem_cache);
			rwbuf_free(&pos->rbuf);
			rwbuf_free(&pos->wbuf);
			_sm_free(pos);
		}
	}

#if (ENABLE_SSL)
	SSL_COMP_free_compression_methods();
	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif

	/*while (_SM_LIST_EMPTY(&sm->list_session_cache) == 0) {
		pos = _SM_LIST_ENTRY(sm->list_session_cache.next, struct sock_session, elem_cache);
		_SM_LIST_DEL_INIT(&pos->elem_cache);
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


sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint32_t max_send_len,
	uint8_t enable_tls, session_tls_t tls, session_behavior_t behavior, void* udata, uint8_t udata_len) {

	sock_session_t* ss = 0;
	int rt, err, fd, ev, optval = 1;
#if(ENABLE_SSL)
	SSL_CTX* ctx = 0;
#endif//ENABLE_SSL

	if (!sm) return 0;

	fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)  return 0;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	rt = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (rt == -1)
		goto add_listen_failed;

	rt = bind(fd, (const struct sockaddr*)&sin, sizeof(sin));
	if (rt == -1)
		goto add_listen_failed;

	rt = listen(fd, max_listen);
	if (rt == -1)
		goto add_listen_failed;

	ss = sf_cache_session(sm);
	if (ss == 0)
		goto add_listen_failed;

	rt = sf_construct_session(sm, ss, fd, "0.0.0.0", port, max_send_len, sf_accpet_cb, NULL/*accpet_function*/, behavior, udata, udata_len);
	if (rt != SERROR_OK) 
		goto add_listen_failed;

#if(ENABLE_SSL)
	err = 0;
	if (enable_tls) {
		if (tls.cert == 0 || tls.key == 0)
			err = 1;

		ctx = SSL_CTX_new(SSLv23_server_method());
		if (!ctx)
			err = SERROR_TLS_MLC_ERR;

		//加载CA证书
		if (err== 0 && tls.ca) {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
			if (rt = SSL_CTX_load_verify_locations(ctx, tls.ca, NULL) != 1)
				err = SERROR_TLS_CA_ERR;
		}

		//加载自己的证书
		if (err == 0 && (rt = SSL_CTX_use_certificate_file(ctx, tls.cert, SSL_FILETYPE_PEM)) != 1)
			err = SERROR_TLS_CERT_ERR;

		//加载私钥
		if (err == 0 && (rt = SSL_CTX_use_PrivateKey_file(ctx, tls.key, SSL_FILETYPE_PEM)) != 1)
			err = SERROR_TLS_KEY_ERR;

		//判断私钥是否正确
		if (err == 0 && (rt = SSL_CTX_check_private_key(ctx)) != 1)
			err = SERROR_TLS_CHECK_ERR;

		if (err) {
			//打印错误, 并且清理当前线程的错误
			printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], serr: [%d]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, err);
			if (ctx)
				SSL_CTX_free(ctx);
			ERR_clear_error();
			goto add_listen_failed;
		}
		//设置即使由这个ctx创建的ssl即使写入部分也将返回
		//SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

		ss->flag.tls = ~0;
		ss->tls_ctx = ctx;
	}
#else
	if (enable_tls) 
		goto add_listen_failed;
#endif//ENABLE_SSL	

	//add epoll status
	rt = sf_add_event(sm, ss, EV_ET | EV_RECV);
	if (rt)
		goto add_listen_failed;

	//add to listener list
	_SM_LIST_ADD_TAIL(&(ss->elem_listens), &(sm->list_listens));
	return ss;

add_listen_failed:
	if(fd != -1)
		close(fd);
	if(ss)
		sf_free_session(sm, ss);
	return 0;
}

sock_session_t* sm_add_client(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, uint32_t max_send_len,
	uint8_t enable_tls, void* server_ctx, uint8_t add_online, session_behavior_t behavior, void* udata, uint8_t udata_len) {

	if (!sm || fd < 0)
		return 0;

	int32_t rt, err = 0;
	sock_session_t* ss = sf_cache_session(sm);
	if (!ss)
		return 0;

	rt = sf_construct_session(sm, ss, fd, ip, port, max_send_len, sf_recv_cb/*recv_cb*/, sf_send_cb, behavior, udata, udata_len);
	if (rt != SERROR_OK)
		goto add_client_failed;

#if (ENABLE_SSL)
	SSL* ssl = 0;
	if (enable_tls) {
		ssl = SSL_new(server_ctx);
		if (err == 0 && !ssl)
			err = 1;

		if (err == 0 && (rt = SSL_set_session_id_context(ssl, SSL_SESSION_ID, strlen(SSL_SESSION_ID))) != 1)
			err = 2;

		if (err == 0 && (rt = SSL_set_fd(ssl, fd)) != 1)
			err = 3;

		if(err == 0 && ssl)
			SSL_set_accept_state(ssl);

		/*
		*	此处设计为非阻塞的SSL_accept
		*	原因: SSL_accept接收一个client hello, 但是对端如果只是连接, 
			但没有按照tls协议上传加密算法列表, 将阻塞在此处. 这是一个严重的问题
		*/
		if (err == 0) {
			if ((rt = SSL_accept(ssl)) != 1) {
				if (SSL_get_error(ssl, rt) != SSL_ERROR_WANT_READ)
					err = 4;
			}
			else
				ss->flag.tls_handshake = ~0;	//设置为已完成握手, 但是一般不在这里完成
		}

		if (err) {
			printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], tls_err: [%d], ssl_err: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, rt, ERR_get_error(), "Active shutdown");
			ERR_clear_error();
			goto add_client_failed;
		}
		SSL_set_options(ssl, SSL_OP_NO_SSLv2);
		SSL_set_options(ssl, SSL_OP_NO_SSLv3);
		SSL_set_options(ssl, SSL_OP_NO_TLSv1_1);
		SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);
		//SSL_set_options(ssl, SSL_OP_NO_TLSv1);

		//回调函数改为tls
		ss->recv_cb = sf_tls_recv_cb;
		ss->send_cb = sf_tls_send_cb;
	}
#endif//ENABLE_SSL

	//add epoll status
	rt = sf_add_event(sm, ss, EV_ET | EV_RECV);
	if (rt) 
		goto add_client_failed;

#if (ENABLE_SSL)
	ss->tls_ctx = ssl;
	ss->flag.tls = ~0;
#endif//ENABLE_SSL

	//add to online list
	if (add_online)
		_SM_LIST_ADD_TAIL(&(ss->elem_online), &(sm->list_online));
	return ss;

add_client_failed:
#if (ENABLE_SSL)
	if (enable_tls && ssl)
		SSL_free(ssl);
#endif//ENABLE_SSL

	if(ss)
		sf_free_session(sm, ss);

	return 0;
}

sock_session_t* sm_add_server(session_manager_t* sm, const char* domain, uint16_t port, uint32_t max_send_len,
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

		rt = sf_construct_session(sm, ss, fd, ip, port, max_send_len, sf_recv_cb, sf_send_cb, behavior, udata, udata_len);
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
			rt = sf_add_event(sm, ss, EV_ET | EV_RECV);
			if (rt != SERROR_OK)
				break;
		}

		//If it is in ET mode and the connection fails, waiting reconnect
		if (rt == -1)
			break;

		_SM_LIST_ADD_TAIL(&ss->elem_servers, &sm->list_servers);
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
	sf_del_session(ss, 1);

	if (_SM_LIST_EMPTY(&ss->elem_servers) == 0)
		_SM_LIST_DEL_INIT(&ss->elem_servers);

	//加入到离线队列
	_SM_LIST_ADD_TAIL(&ss->elem_offline, &ss->sm->list_offline);

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
			/*if (ss->flag.tls)
				sf_tls_send_cb(ss);
			else
				sf_send_cb(ss);*/
			ss->send_cb(ss);
		}
	}

	sf_pending_send(sm);
	sf_pending_recv(sm);
	sf_call_decode_fn(sm);
	sf_clean_offline(sm);

	return ~0;
}

void sm_run(session_manager_t* sm) {
	while (sm->flag.running) {
		uint64_t waitms = ht_update_timer(sm->ht_timer);

		if (_SM_LIST_EMPTY(&sm->list_pending_send) == 0 || _SM_LIST_EMPTY(&sm->list_pending_recv) == 0)
			waitms = 0;

		//signal
		if (sm_run2(sm, waitms) == 0) {
			if (errno == SIGQUIT)
				sm->flag.running = 0;
		}
	}
}