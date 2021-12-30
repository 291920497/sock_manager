#ifndef _INTERNAL_FN_H_
#define _INTERNAL_FN_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include "sock_manager.h"
#include "tools/common/nofile_ctl.h"
#include "tools/common/common_fn.h"

//types
#include "types.hpp"

#ifndef _WIN32
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/socket.h>
#else
#include <objbase.h>
#endif//_WIN32

#if (ENABLE_SSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif//ENABLE_SSL

#ifndef _WIN32
#define __FILENAME__ (strrchr(__FILE__,'/') + 1)
#else
#define __FILENAME__ (strrchr(__FILE__,'\\') + 1)
#endif//_WIN32

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

;

#ifndef _WIN32
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

#else

static const char* sf_timefmt() {
	static char time_fmt[64];
	time_t t = time(NULL);
	struct tm tmt;
	gmtime_s(&tmt, &t);
	struct tm* tm = &tmt;

	snprintf(time_fmt,sizeof(time_fmt), "%04d-%02d-%02d %02d:%02d:%02d.%06d",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec, 0);
	return time_fmt;
}
#endif//_WIN32

static int32_t sf_errstr(char* errbuf, uint32_t errbuf_len) {
	int32_t eno;
#ifndef _WIN32
	eno = errno;
	if (errbuf)
		strncpy(errbuf, strerror(eno), errbuf_len);
#else
	eno = GetLastError();
	if (errbuf)
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errbuf, errbuf_len, NULL);
#endif//_WIN32
	return eno;
}

//添加监听事件
static int32_t sf_add_event(session_manager_t* sm, sock_session_t* ss, int32_t ev) {
	if ((ss->epoll_state & (~(EV_ET))) & ev)
		return SERROR_OK;

#ifndef _WIN32

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
#else

	if (ev & EV_RECV) {
		if (!FD_ISSET(ss->fd, &sm->rfdst)) {
			//FD_SET(ss->fd, &sm->rfdst);
			ss->epoll_state |= EV_RECV;
		}
	}

	if (ev & EV_WRITE) {
		if (!FD_ISSET(ss->fd, &sm->wfdst)) {
			//FD_SET(ss->fd, &sm->wfdst);
			ss->epoll_state |= EV_WRITE;
		}
	}

	return SERROR_OK;
#endif//_WIN32
}

//删除监听事件
static int32_t sf_del_event(session_manager_t* sm, sock_session_t* ss, int32_t ev) {
	if (!((ss->epoll_state & (~(EV_ET))) & ev))
		return SERROR_OK;

#ifndef _WIN32

	struct epoll_event epev;
	epev.data.ptr = ss;
	int ctl = EPOLL_CTL_DEL;

	if (ss->epoll_state & (~(EPOLLET | ev))) {
		ctl = EPOLL_CTL_MOD;
	}

	ss->epoll_state &= (~ev);
	epev.events = ss->epoll_state;

	return epoll_ctl(sm->ep_fd, ctl, ss->fd, &epev);

#else
	if (ev & EV_RECV) {
		if (FD_ISSET(ss->fd, &sm->rfdst)) {
			FD_CLR(ss->fd, &sm->rfdst);
			ss->epoll_state &= (~EV_RECV);
		}
	}

	if (ev & EV_WRITE) {
		if (FD_ISSET(ss->fd, &sm->wfdst)) {
			FD_CLR(ss->fd, &sm->wfdst);
			ss->epoll_state &= (~EV_WRITE);
		}	
	}
	return SERROR_OK;
#endif//_WIN32
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
#ifndef _WIN32
		return EAI_OVERFLOW;
#else
		return SERROR_SYSAPI_ERR;
#endif//_WIN32
	}
	freeaddrinfo(res);
	return SERROR_OK;
}

//创建一个uuid的hash值, inbuffer 为
static uint32_t sf_uuidhash() {
	//uuid
	char buf[64];
	memset(buf, 0, sizeof(buf));

#ifndef _WIN32
	uuid_t uu = {0};
	uuid_generate(uu);
	uuid_generate_random(uu);
	uuid_unparse_upper(uu, buf);
#else
	GUID guid;
	::CoCreateGuid(&guid);
	snprintf(buf, sizeof(buf), "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]);
#endif//_WIN32

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

/**
*	s_try_accept - Try to accept a sock fileno
*/
static int sf_try_accept(int __fd, sockaddr* __addr, socklen_t* __restrict __addr_len) {
	int fd = -1, try_count = 1, err;

	do {
		fd = accept(__fd, __addr, __addr_len);

		if (fd == -1) {
#ifndef _WIN32
			err = errno;
			//is nothing
			if (err == EAGAIN)
				return -2;
#else
			err = GetLastError();
			if(err == WSAEWOULDBLOCK)
				return -2;
#endif//_WIN32
			
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

static uint32_t sf_uncoded_send_fn(sock_session_t* ss, const char* data, uint32_t len) {
	uint32_t rt;

	if (!data || !len)
		return 0;

	if (rwbuf_unused_len(&ss->wbuf)) {
		rt = rwbuf_append(&ss->wbuf, data, len);
		if (rt)
			sf_add_event(ss->sm, ss, EV_WRITE);
		return rt;
	}

	return 0;
}

static void sf_recv_cb(sock_session_t* ss) {
	static char buf[256];
	if (ss->flag.fin_peer)
		return;

	buf[0] = 0;
	int32_t rt, eno, buflen;
	

	do {
		buflen = rwbuf_unused_len(&(ss->rbuf));

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

		int rd = recv(ss->fd, (char*)rwbuf_start_ptr(&(ss->rbuf)) + rwbuf_len(&(ss->rbuf)), buflen, 0);
		if (rd == -1) {
			eno = sf_errstr(buf, sizeof(buf));
#ifndef _WIN32
			//eno = errno;
			//If there is no data readability
			if (eno == EAGAIN) {
#else
			//eno = GetLastError();
			if (eno == WSAEWOULDBLOCK) {
#endif//_WIN32
				//if in the recv pending
				if (cds_list_empty(&ss->elem_pending_recv) == 0)
					cds_list_del_init(&ss->elem_pending_recv);
				return;
			}
#ifndef _WIN32
			//If it is caused by interruption
			else if (eno == EINTR) {
				//if not recv pending
				if (cds_list_empty(&ss->elem_pending_recv))
					cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
				return;
			}
#endif//WIN32
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

		if (cds_list_empty(&ss->elem_pending_recv))
			cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);

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

		//数据长度发生了改变, 可以尝试解包
		if (cds_list_empty(&ss->elem_changed))
			cds_list_add_tail(&ss->elem_changed, &ss->sm->list_changed);

		//修改接收缓冲区的长度, 不额外提供接口
		ss->rbuf.len += rd;
		//重置读尝试的次数
		ss->rtry_number = 0;
		//设置为有数据到来
		ss->flag.comming = ~0;
		return;
	} while (0);

	if (rt != SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, rt, eno, buf);

//	if (rt == SERROR_SYSAPI_ERR) {
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, SERROR_SYSAPI_ERR, eno, buf);
//	}
//#ifdef TEST_CODE
//	else if (rt == SERROR_PEER_DISCONN)
//		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
//#endif

	//如果是服务器则暂不回收, 等待重连
	sm_del_session(ss);
}

static void sf_send_cb(sock_session_t* ss) {
	//如果已经完全关闭, 可能存在半连接,那么剩余的数据也应该尝试发送, 所以这个状态一定要严谨
	static char buf[256];
	if (ss->flag.fin_peer)
		return;

	buf[0] = 0;
	int32_t rt, eno, snd_len;

	do {
		snd_len = rwbuf_len(&ss->wbuf);
		if (!snd_len)
			return;

		int32_t sd = send(ss->fd, (char*)rwbuf_start_ptr(&ss->wbuf), snd_len, 0);
		if (sd == -1) {
			eno = sf_errstr(buf, sizeof(buf));
#ifndef _WIN32
			//If the interrupt or the kernel buffer is temporarily full
//			eno = errno;
			if (eno == EAGAIN || eno == EINTR) {
#else
			//			eno = GetLastError();
			if (eno == WSAEWOULDBLOCK) {
#endif//_WIN32
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

	if (rt != SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, rt, eno, buf);

//	if (rt == SERROR_SYSAPI_ERR) {
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, SERROR_SYSAPI_ERR, eno, buf);
//	}
//		//printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, eno, buf);
//	else if (rt == SERROR_PEER_DISCONN) {
//#ifdef TEST_CODE
//		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
//#endif//TEST_CODE
//	}

	//sm_del_session(ss);
	//如果是服务器则暂不回收, 等待重连

	sm_del_session(ss);
}

//tls



//#if (ENABLE_SSL)
//static int32_t sf_tls_err(SSL* ssl, int32_t rc) {
//	int32_t err = SSL_get_error(ssl, rc);
//	//清除当前线程的错误
//	ERR_clear_error();
//
//	//暂时不太搞得清楚其他错误的具体原因
//	//if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
//	//	return SSL_ERROR_NONE;
//
//	return err;
//}
//#endif//ENABLE_SSL

static int32_t sf_tls_read_err(sock_session_t* ss, int32_t rd, _OUT int32_t* errcode, _OUT char* errstr) {
	int rt, err, eno, serr = 0;
#if (ENABLE_SSL)
	SSL* ssl = (SSL*)(ss->tls_info.ssl);
	/*rt = sf_tls_err(ssl, rd);
	*out_tls_err = rt;
	err = ERR_get_error();*/

	rt = SSL_get_error(ssl, rd);
	err = ERR_get_error();
	ERR_clear_error();

	if (errcode)
		*errcode = 0;

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
	if (serr) {
		if (errcode)
			*errcode = err;

		if (errstr)
			ERR_error_string(err, errstr);
		return serr;
	}	

	//判断是否为底层传输协议出错
	if (rt == SSL_ERROR_SYSCALL) {
		//表示没有出现错误, 那么是底层传输协议错误
		if (err == 0) {
			serr = SERROR_PEER_DISCONN;
			return serr;
		}

		eno = sf_errstr(errstr, 256);
#ifndef _WIN32
//		eno = errno;
		//If there is no data readability
		if (eno == EAGAIN) {
#else
//		eno = GetLastError();
		if (eno == WSAEWOULDBLOCK) {
#endif//_WIN32
			//if in the recv pending
			if (cds_list_empty(&ss->elem_pending_recv) == 0)
				cds_list_del_init(&ss->elem_pending_recv);
			return SERROR_OK;
		}
#ifndef _WIN32
		//If it is caused by interruption
		else if (eno == EINTR) {
			//if not recv pending
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
			return SERROR_OK;
		}
#endif//_WIN32

		if (errcode)
			*errcode = eno;

		return SERROR_SYSAPI_ERR;
	}

	//如果出现了重新协商, 希望在可写事件发生时再次调用SSL_read
	//if (rt == SSL_ERROR_WANT_WRITE) {
	//	//ss->flag.tls_wwantr = ~0;

	//	////添加可写事件
	//	//if (sf_add_event(ss->sm, ss, EV_WRITE) == 0)
	//	//	return SERROR_OK;

	//	//return SERROR_SYSAPI_ERR;

	//	//取消重新协商的功能
	//	return SERROR_TLS_SSL_ERR;
	//}

	//如何希望下次可读事件发生时再调用, 清除未决队列
	if (rt == SSL_ERROR_WANT_READ) {
		if (cds_list_empty(&ss->elem_pending_recv) == 0)
			cds_list_del_init(&ss->elem_pending_recv);
		return SERROR_OK;
	}

	//如果都不是以上情况, 那么应该关闭并从SSL库中获取错误信息
	//打印错误
	serr = SERROR_TLS_LIB_ERR;
	/*if (openssl_err)
		*openssl_err = err;*/

	if (errcode)
		*errcode = err;

	if (errstr)
		ERR_error_string(err, errstr);
#endif
	return serr;
}

static void sf_tls_recv_cb(sock_session_t* ss) {
	static char errstr[256];
	if (ss->flag.fin_peer)
		return;

#if (ENABLE_SSL)
	errstr[0] = 0;
	int32_t err, rd, errcode = 0, serr = 0;
	SSL* ssl = (SSL*)(ss->tls_info.ssl);
	

	//是否正在重新协商
	//if (ss->flag.tls_rwantw) {
	//	//立即还原可写事件调用读
	//	ss->flag.tls_wwantr = 0;
	//	sf_tls_send_cb(ss);
	//	return;
	//}

	do {
		if (ss->flag.tls_handshake) {
		//if (SSL_do_handshake(ssl)) {
			int buflen = rwbuf_unused_len(&(ss->rbuf));
			rd = SSL_read(ssl, rwbuf_start_ptr(&(ss->rbuf)) + rwbuf_len(&(ss->rbuf)), buflen);
			if (rd <= 0) {
				serr = sf_tls_read_err(ss, rd, &errcode, errstr);
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
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);

			//数据长度发生了改变, 可以尝试解包
			if (cds_list_empty(&ss->elem_changed))
				cds_list_add_tail(&ss->elem_changed, &ss->sm->list_changed);

			//修改接收缓冲区的长度, 不额外提供接口
			ss->rbuf.len += rd;
			//重置读尝试的次数
			ss->rtry_number = 0;
			//设置为有数据到来
			ss->flag.comming = ~0;
			return;
		}
		else {
			if (ss->flag.is_connect)
				rd = SSL_connect(ssl);
			else
				rd = SSL_accept(ssl);

			if (rd == 1) {
				if ((errcode = SSL_get_verify_result(ssl)) == X509_V_OK) {
					ss->flag.tls_handshake = ~0;

					//若握手完成, 且有数据等待发送
					if (rwbuf_len(&ss->wbuf)) {
						sf_add_event(ss->sm, ss, EV_WRITE);
					}
					return;
				}
				else {
					serr = SERROR_TLS_X509_ERR;
					strcpy(errstr, X509_verify_cert_error_string(serr));
					break;
				}
			}

			serr = sf_tls_read_err(ss, rd, &errcode, errstr);
			//预期内的错误
			if (serr == SERROR_OK)
				return;

			break;
		}
	} while (0);


	if (serr != SERROR_PEER_DISCONN)
		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errcode, errstr);
	SSL_shutdown(ssl);

//	switch (serr) {
//	case SERROR_SYSAPI_ERR:
//		//printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errcode, "System api error");
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errcode, errstr);
//		break;
//	case SERROR_PEER_DISCONN:
//#ifdef TEST_CODE
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
//#endif//TEST_CODE
//		break;
//		//以下都是SSL的错误了
//	default:
//		SSL_shutdown(ssl);
//		//printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], serr: [%d], errno: [%d], tls_err: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errno, rt, "Active shutdown");
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errcode, errstr);
//	}

	sm_del_session(ss);

#endif//ENABLE_SSL
}

//static void sf_tls_recv_cb2(sock_session_t* ss) {
//	if (ss->flag.fin_peer)
//		return;
//
//#if(ENABLE_SSL)
//
//	int32_t rt = 0, err, eno, rd, serr = 0;
//	SSL* ssl = (SSL*)(ss->tls_info.ssl);
//
//	//判断
//
//#endif//ENABLE_SSL
//}

static int32_t sf_tls_send_err(sock_session_t* ss, int32_t sd, _OUT int32_t* errcode, _OUT char* errstr) {
	int rt, err, eno, serr = 0;
#if (ENABLE_SSL)
	SSL* ssl = (SSL*)(ss->tls_info.ssl);
	//rt = sf_tls_err(ssl, sd);
	rt = SSL_get_error(ssl, sd);
	err = ERR_get_error();
	ERR_clear_error();

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
	if (serr) {
		if (errcode)
			*errcode = err;

		if (errstr)
			ERR_error_string(err, errstr);
		return serr;
	}

	//判断是否为底层传输协议出错
	if (rt == SSL_ERROR_SYSCALL) {
		//表示没有出现错误, 那么是底层传输协议错误
		if (err == 0) {
			serr = SERROR_PEER_DISCONN;
			return serr;
		}
		
		eno = sf_errstr(errstr, 256);
#ifndef _WIN32
//		eno = errno;
		//If there is no data readability
		if (eno == EAGAIN) {
#else
//		eno = GetLastError();
		if (eno == WSAEWOULDBLOCK) {
#endif//_WIN32
			//if in the recv pending
			if (cds_list_empty(&ss->elem_pending_send) == 0)
				cds_list_del_init(&ss->elem_pending_send);
			return SERROR_OK;
		}
#ifndef _WIN32
		//If it is caused by interruption
		else if (eno == EINTR) {
			//if not recv pending
			if (cds_list_empty(&ss->elem_pending_send))
				cds_list_add_tail(&ss->elem_pending_send, &ss->sm->list_pending_send);
			return SERROR_OK;
		}
#endif//_WIN32

		if (errcode)
			*errcode = eno;

		return SERROR_SYSAPI_ERR;
	}

	//如果出现了重新协商, 希望在可写事件发生时再次调用SSL_read
	if (rt == SSL_ERROR_WANT_WRITE) {
		//添加可写事件
		if (sf_add_event(ss->sm, ss, EV_WRITE) == 0)
			return SERROR_OK;

		return SERROR_SYSAPI_ERR;
	}

	////如果在可读事件中调用, 需要判断是否作为客户端发起握手
	//if (rt == SSL_ERROR_WANT_READ) {
	//	//recv事件一直在, 静等回调即可
	//	ss->flag.tls_rwantw = ~0;
	//	return SERROR_OK;
	//	//取消重新协商的功能
	//	//return SERROR_TLS_SSL_ERR;
	//}

	//检查是否是client hello
	if (rt = SSL_ERROR_WANT_READ && ss->flag.tls_handshake == 0 && ss->flag.is_connect) {
		sf_del_event(ss->sm, ss, EV_WRITE);
		return SERROR_OK;
	}

	//如果都不是以上情况, 那么应该关闭并从SSL库中获取错误信息
	//打印错误
	serr = SERROR_TLS_LIB_ERR;

	if (errcode)
		*errcode = err;

	if (errstr)
		ERR_error_string(err, errstr);
#endif
	return serr;
}

//static void sf_tls_send_cb(sock_session_t* ss) {
//	if (ss->flag.fin_peer)
//		return;
//
//#if (ENABLE_SSL)
//	int32_t rt, snd_len, err = 0, eno, sd, serr = 0;
//	SSL* ssl = (SSL*)ss->tls_info.ssl;
//
//	////是否正在重新协商
//	//if (ss->flag.tls_wwantr) {
//	//	//立即还原可写事件调用读
//	//	ss->flag.tls_wwantr = 0;
//	//	sf_tls_recv_cb(ss);
//	//	return;
//	//}
//
//	do {
//		snd_len = RWBUF_GET_LEN(&ss->wbuf);
//		//没有数据可以发送, 这里不在外面判断, 为了应对TLS的重新协商
//		if (!snd_len) return;
//
//		sd = SSL_write(ssl, RWBUF_START_PTR(&ss->wbuf), snd_len);
//		if (sd <= 0) {
//			//写判断错误
//			serr = sf_tls_send_err(ss, sd, &rt);
//			//预期内的错误
//			if (serr == SERROR_OK)
//				return;
//
//			break;
//		}
//
//		rwbuf_aband_front(&ss->wbuf, sd);
//		//if not complated, 如果请求发送的长度 > 成功发送的长度, 那么任务尚未完成
//		if (snd_len - sd) {
//			if (sf_add_event(ss->sm, ss, EV_WRITE) != 0) {
//				serr = SERROR_SYSAPI_ERR;
//				break;
//			}
//
//			rwbuf_replan(&ss->wbuf);
//
//			//add send pending
//			if (cds_list_empty(&ss->elem_pending_send))
//				cds_list_add_tail(&ss->elem_pending_send, &ss->sm->list_pending_send);
//		}
//		else {
//			sf_del_event(ss->sm, ss, EV_WRITE);
//			//remove send pending
//			if (cds_list_empty(&ss->elem_pending_send) == 0)
//				cds_list_del_init(&ss->elem_pending_send);
//		}
//
//		return;
//	} while (0);
//
//	switch (serr) {
//	case SERROR_SYSAPI_ERR:
//		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errno, strerror(errno));
//		break;
//	case SERROR_PEER_DISCONN:
//#ifdef TEST_CODE
//		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
//#endif//TEST_CODE
//		break;
//		//以下都是SSL的错误了
//	default:
//		SSL_shutdown(ssl);
//		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], serr: [%d], errno: [%d], tls_err: [%d], ssl_err: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errno, rt, err, "Active shutdown");
//	}
//
//	if (cds_list_empty(&ss->elem_servers))
//		sm_del_session(ss);
//	else
//		sf_del_session(ss, 1);
//
//#endif//ENABLE_SSL
//}

static void sf_tls_send_cb(sock_session_t* ss) {
	if (ss->flag.fin_peer)
		return;

#if (ENABLE_SSL)
	int32_t snd_len, sd, errcode = 0, serr = 0, err = 0;
	SSL* ssl = (SSL*)ss->tls_info.ssl;
	static char errstr[256];
	errstr[0] = 0;
	
	do {
		if (ss->flag.tls_handshake) {
			snd_len = rwbuf_len(&ss->wbuf);

			if (!snd_len) {
				//这里应该永远都无法到达
				sf_del_event(ss->sm, ss, EV_WRITE);
				return;
			}
			//没有数据可以发送, 这里不在外面判断, 为了应对TLS的重新协商
			//if (!snd_len) return;

			sd = SSL_write(ssl, rwbuf_start_ptr(&ss->wbuf), snd_len);
			if (sd <= 0) {
				//写判断错误
				serr = sf_tls_send_err(ss, sd, &errcode, errstr);
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
				if (cds_list_empty(&ss->elem_pending_send))
					cds_list_add_tail(&ss->elem_pending_send, &ss->sm->list_pending_send);
			}
			else {
				sf_del_event(ss->sm, ss, EV_WRITE);
				//remove send pending
				if (cds_list_empty(&ss->elem_pending_send) == 0)
					cds_list_del_init(&ss->elem_pending_send);
			}

			return;
		}
		else {
			if (ss->flag.is_connect)
				sd = SSL_connect(ssl);
			else
				sd = SSL_accept(ssl);

			//此处应永远无法到达
			if (sd == 1) {
				if ((errcode = SSL_get_verify_result(ssl)) == X509_V_OK) {
					ss->flag.tls_handshake = ~0;
					//若握手完成, 且有数据等待发送
					if (rwbuf_len(&ss->wbuf)) {
						sf_add_event(ss->sm, ss, EV_WRITE);
					}
					return;
				}
				else {
					serr = SERROR_TLS_X509_ERR;
					strcpy(errstr, X509_verify_cert_error_string(serr));
					break;
				}
			}

			serr = sf_tls_send_err(ss, sd, &errcode, errstr);
			//预期内的错误
			if (serr == SERROR_OK)
				return;

			break;
		}
			
	} while (0);

	printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errcode, errstr);
	SSL_shutdown(ssl);

//	switch (serr) {
//	case SERROR_SYSAPI_ERR:
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, errcode, "System api error");
//		break;
//	case SERROR_PEER_DISCONN:
//#ifdef TEST_CODE
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "reset by peer");
//#endif//TEST_CODE
//		break;
//		//以下都是SSL的错误了
//	default:
//		SSL_shutdown(ssl);
//		printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, serr, errcode, errstr);
//	}

	sm_del_session(ss);

#endif//ENABLE_SSL
}

static int32_t sf_tls_enable_from_ctx(sock_session_t* ss, void* tls_ctx, _OUT int32_t* errcode, _OUT char* errstr) {
#if (ENABLE_SSL)
	int32_t fd = ss->fd;
	int32_t err = 0, rt, ncode = 0;
	SSL_CTX* ctx = (SSL_CTX*)tls_ctx;
	SSL* ssl = 0;

	if (!ctx)
		return SERROR_INPARAM_ERR;

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);

	ssl = SSL_new(ctx);

	if (err == 0 && !ssl)
		err = 1;

	if (err == 0 && (rt = SSL_set_session_id_context(ssl, (const unsigned char*)SSL_SESSION_ID, strlen(SSL_SESSION_ID))) != 1)
		err = 2;

	if (err == 0 && (rt = SSL_set_fd(ssl, fd)) != 1)
		err = 3;

	if (err == 0 && ssl)
		SSL_set_accept_state(ssl);

	/*
	*	此处设计为非阻塞的SSL_accept
	*	原因: SSL_accept接收一个client hello, 但是对端如果只是连接,
	*	但没有按照tls协议上传加密算法列表, 将阻塞在此处. 这是一个严重的问题
	*/

	if (err == 0) {
		if ((rt = SSL_accept(ssl)) != 1) {
			if ((rt = SSL_get_error(ssl, rt)) != SSL_ERROR_WANT_READ)
				err = 4;
		}
		else
			ss->flag.tls_handshake = ~0;	//设置为已完成握手, 但是一般不在这里完成
	}

	if (err) {
		ncode = ERR_get_error();

		if (errcode)
			*errcode = ncode;

		if (errstr)
			ERR_error_string(ncode, errstr);

		if (ssl)
			SSL_free(ssl);

		ERR_clear_error();
		return SERROR_TLS_SSL_ERR;
	}

	ss->flag.tls = ~0;
	ss->tls_info.ssl = ssl;

	//回调函数改为tls
	ss->recv_cb = sf_tls_recv_cb;
	ss->send_cb = sf_tls_send_cb;

	return SERROR_OK;
#else
	return SERROR_TLS_NOENABLE;
#endif//ENABLE_SSL
}

static int32_t sf_reconnect(sock_session_t* ss) {
	struct sockaddr_in sin;
	int32_t rt, ret, ev = 0;

	if (ss->fd != -1) {
		rt = cf_closesocket(ss->fd);
//#ifndef _WIN32
//		rt = close(ss->fd);
//#else
//		//closecok
//		rt = closesocket(ss->fd);
//#endif//_WIN32

		if (rt != 0)
			return SERROR_SYSAPI_ERR;

		ss->fd = -1;
	}
	
	ss->fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
	if (ss->fd == -1)
		return SERROR_SYSAPI_ERR;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(ss->port);
	sin.sin_addr.s_addr = inet_addr(ss->ip);

	nofile_set_nonblocking(ss->fd);

	rt = connect(ss->fd, (const struct sockaddr*)&sin, sizeof(sin));
#ifndef _WIN32
	if (rt == -1 && errno != EINPROGRESS) {
#else
	if (rt == -1 && GetLastError() != WSAEWOULDBLOCK) {
#endif//_WIN32
		return SERROR_SYSAPI_ERR;
	}

#if(ENABLE_SSL)
	//tls
	if (ss->flag.tls) {
		SSL* ssl = SSL_new((SSL_CTX*)ss->tls_info.ctx);
		if (!ssl)
			return SERROR_SYSAPI_ERR;

		SSL_set_fd(ssl, ss->fd);
		SSL_set_connect_state(ssl);
		ss->tls_info.ssl = ssl;

		//client hello
		ev |= EV_WRITE;
	}
#endif//ENABLE_SSL
	
	//add epoll status
	ev |= (EV_ET | EV_RECV);
	rt = sf_add_event(ss->sm, ss, ev);
	if (rt != SERROR_OK) {
#if(ENABLE_SSL)
		if (ss->flag.tls && ss->tls_info.ssl) {
			SSL_free((SSL*)ss->tls_info.ssl);
			ss->tls_info.ssl = 0;
		}
#endif//ENABLE_SSL
		return SERROR_SYSAPI_ERR;
	}
	

	//clear flag
	ss->flag.fin_peer = 0;
	ss->flag.comming = 0;
	ss->flag.ws_handshake = 0;
	ss->flag.tls_handshake = 0;

	rwbuf_clear(&ss->rbuf);
	rwbuf_clear(&ss->wbuf);
	ss->last_active = time(0);

	return SERROR_OK;
}

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_INTERNAL_FN_H_