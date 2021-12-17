//#include "../inc/types.h"
#include "sock_manager.h"
#include "internal/internal_fn.h"

//std
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <signal.h>

#ifndef _WIN32
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#else

#endif//_WIN32
#include <errno.h>

#include "types.hpp"
#include "tools/common/base64_encoder.h"

#if (ENABLE_SSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif//ENABLE_SSL


#define _sm_malloc malloc
#define _sm_realloc realloc
#define _sm_free	free

#define MAX_RECONN_SERVER_TIMEOUT 5

static void sf_timer_reconn_cb(uint32_t timer_id, void* udata, uint8_t udata_len) {

}

static int32_t sf_construct_session(session_manager_t* sm, sock_session_t* ss, int32_t fd, const char* ip, uint16_t port, uint32_t send_len, session_rw recv_cb, session_rw send_cb, session_behavior_t* uevent, void* udata, uint16_t udata_len) {
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
	memcpy(&ss->uevent, uevent, sizeof(session_behavior_t));
	strcpy(ss->ip, ip);

	nofile_set_nonblocking(fd);

	if (udata && udata_len)
		memcpy(&ss->udata, &udata, udata_len);

	if (send_len) {
		rt = rwbuf_relc(&ss->wbuf, send_len);
		if (rt != SERROR_OK)
			goto clean;

		rt = rwbuf_relc(&ss->rbuf, send_len);
		if (rt != SERROR_OK)
			goto clean;
	}

	CDS_INIT_LIST_HEAD(&(ss->elem_lively));
	CDS_INIT_LIST_HEAD(&(ss->elem_offline));
#ifdef _WIN32
	//CDS_INIT_LIST_HEAD(&(ss->elem_forgotten));
#endif//_WIN32
	CDS_INIT_LIST_HEAD(&(ss->elem_listens));
	CDS_INIT_LIST_HEAD(&(ss->elem_changed));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_recv));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_send));

	return SERROR_OK;

clean:
	if (ss->wbuf.size)
		rwbuf_free(&ss->wbuf);
	if (ss->rbuf.size)
		rwbuf_free(&ss->rbuf);
	return rt;
}

static void sf_destruct_session(sock_session_t* ss) {
	if (!ss)
		return;

	rwbuf rbuf, wbuf;
	rwbuf_init(&rbuf);
	rwbuf_init(&wbuf);

	rwbuf_swap(&ss->rbuf, &rbuf);
	rwbuf_swap(&ss->wbuf, &wbuf);

	if (ss->elem_lively.next)
		cds_list_del(&(ss->elem_lively));
	if (ss->elem_offline.next)
		cds_list_del(&(ss->elem_offline));
	/*if (ss->elem_servers.next)
		cds_list_del(&(ss->elem_servers));*/
#ifdef _WIN32
	//CDS_INIT_LIST_HEAD(&(sm->list_forgotten));
	//if(ss->elem_forgotten.next)
		//cds_list_del(&(ss->elem_forgotten));
#endif//_WIN32
	if (ss->elem_listens.next)
		cds_list_del(&(ss->elem_listens));
	if (ss->elem_changed.next)
		cds_list_del(&(ss->elem_changed));
	if (ss->elem_pending_recv.next)
		cds_list_del(&(ss->elem_pending_recv));
	if (ss->elem_pending_send.next)
		cds_list_del(&(ss->elem_pending_send));
	if (ss->elem_cache.next)
		cds_list_del(&(ss->elem_cache));

	memset(ss, 0, sizeof(sock_session_t));
	ss->fd = -1;

	CDS_INIT_LIST_HEAD(&(ss->elem_lively));
	CDS_INIT_LIST_HEAD(&(ss->elem_offline));
#ifdef _WIN32
	//CDS_INIT_LIST_HEAD(&(ss->elem_forgotten));
#endif//_WIN32
	CDS_INIT_LIST_HEAD(&(ss->elem_listens));
	CDS_INIT_LIST_HEAD(&(ss->elem_changed));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_recv));
	CDS_INIT_LIST_HEAD(&(ss->elem_pending_send));
	CDS_INIT_LIST_HEAD(&(ss->elem_cache));

	rwbuf_swap(&ss->rbuf, &rbuf);
	rwbuf_swap(&ss->wbuf, &wbuf);
	rwbuf_clear(&ss->wbuf);
	rwbuf_clear(&ss->rbuf);
}

static sock_session_t* sf_cache_session(session_manager_t* sm) {
	sock_session_t* ss = 0;

	if (!sm)
		return ss;

	if (cds_list_empty(&(sm->list_session_cache))) {
		//new session
		ss = (sock_session_t*)_sm_malloc(sizeof(sock_session_t));
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



static void sf_accpet_cb(sock_session_t* ss) {
	do {
		struct sockaddr_in c_sin;
		socklen_t s_len = sizeof(c_sin);
		memset(&c_sin, 0, sizeof(c_sin));

		static char errstr[512];
		int32_t c_fd, try_count = 1, serr = 0, errcode = 0;
		//c_fd = sf_try_accept(ss->fd, (struct sock_addr*)&c_sin, &s_len);
		c_fd = sf_try_accept(ss->fd, (sockaddr*)&c_sin, &s_len);
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
			if (cds_list_empty(&ss->elem_pending_recv))
				cds_list_add_tail(&ss->elem_pending_recv, &ss->sm->list_pending_recv);
			return;
		}

		const char* ip = inet_ntoa(c_sin.sin_addr);
		unsigned short port = ntohs(c_sin.sin_port);
		//printf("fd: %d\n", c_fd);
		sock_session_t* css = sm_add_accepted(ss->sm, c_fd, ip, port, ss->wbuf.size, &ss->uevent, ss->udata, ss->udatalen);
		if (!css) {
			//系统API调用错误 查看errno
			printf("[%s] [%s:%d] [%s], errno: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, errno, strerror(errno));
#ifndef _WIN32
			close(c_fd);
#else
			closesocket(c_fd);
#endif//_WIN32
			return;
		}
		else {
			//printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, css->ip, css->port, "accept");
			static uint32_t count = 0;
			printf("accept: %d\n", ++count);
		}

		if (ss->flag.tls) {
			serr = sf_tls_enable_from_ctx(css, ss->tls_info.ctx, &errcode, errstr);
			
			if (serr != SERROR_OK) {
				printf("[%s] [%s:%d] [%s], Ready to disconnect, ip: [%s] port: [%d], serr: [%d], errcode: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, css->ip, css->port, serr, errcode, errstr);
				sm_del_session(css);
			}
		}


	} while (1);
}

//处理写未决
static void sf_pending_send(session_manager_t* sm) {
	if (sm) {
		sock_session_t* ss, * n;
		if (cds_list_empty(&sm->list_pending_send) == 0) {
			cds_list_for_each_entry_safe(ss, n, &sm->list_pending_send, elem_pending_send) {
				//减少不必要的函数调用
				//if (ss->flag.closed == 0 && RWBUF_GET_LEN(&ss->wbuf))

				//迎合tls, 不对写入长度做判断, 应该真正写入的数据可能在Bio中
				if (ss->flag.fin_peer == 0) {
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
		if (cds_list_empty(&sm->list_pending_recv) == 0) {
			cds_list_for_each_entry_safe(ss, n, &sm->list_pending_recv, elem_pending_recv) {
				//尚未关闭且有剩余缓冲区
				if (ss->flag.fin_peer == 0) {
					//可能是监听套接字
					if (rwbuf_unused_len(&ss->rbuf))
						//sf_recv_cb(ss);
						ss->recv_cb(ss);
					else {
						//尝试读取8次,缓冲区都没有空间, 那么一定输出BUF出现了问题, 在正常的前提下,这应该永远不会发生
						if (++ss->rtry_number > 8) {
							sm_del_session(ss);
							printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Receive buffer full");
						}
					}
				}
			}
		}
	}
}

//回调解包函数
static void sf_call_decode_fn(session_manager_t* sm) {
	int32_t len, ev, opt, frame, rt = 0;
	uint32_t front_offset, back_offset;
	int8_t* data;
	sock_session_t* ss, * n;
	rwbuf_t* rbuf;

	cds_list_for_each_entry_safe(ss, n, &sm->list_changed, elem_changed) {
		rbuf = &ss->rbuf;

		do {
			opt = 0;
			front_offset = 0;
			back_offset = 0;
			len = rwbuf_len(rbuf);
			data = rwbuf_start_ptr(rbuf);

			if (len && len >= ss->decode_mod.lenght_tirgger) {
				if (ss->uevent.decode_cb) {
					rt = ss->uevent.decode_cb(ss, (char*)data, len, &ss->decode_mod, &front_offset, &back_offset);

					if (rt == 0)
						break;
					else if (rt < 0) {
						sm_del_session(ss);
						//这里可以打印错误
						break;
					}

					if (rwbuf_aband_front(rbuf, rt) != SERROR_OK) {
						sm_del_session(ss);
						//这里可以打印错误
						break;
					}

					//若需要处理的数据大于1
					if (frame = (rt - front_offset - back_offset)) {
						//回调一次

#if (BETA_CODE)
						rwbuf_t beta_buf;
						rwbuf_init(&beta_buf);
						beta_buf.size = frame;
						beta_buf.len = frame;
						beta_buf.buf = data + front_offset;

						if (ss->uevent.complate_cb) {
							ss->uevent.complate_cb(ss, 0, &beta_buf, ss->udata, ss->udatalen);
						}

						//rwbuf_t beta_buf;
						//rwbuf_init(&beta_buf);
						//rwbuf_mlc(&beta_buf, frame);
						//rwbuf_append(&beta_buf, data + front_offset, frame);
						//
						////回调
						//if (ss->uevent.complate_cb) {
						//	ss->uevent.complate_cb(ss, 0, &beta_buf, ss->udata, ss->udatalen);
						//}
				
						//rwbuf_free(&beta_buf);
#endif//BETA_CODE
					}
				}
			}
		} while ((len - rt) >= ss->decode_mod.lenght_tirgger && ss->decode_mod.lenght_tirgger != 0/*这是怕解包函数啥也不做导致死循环*/);

		ss->flag.comming = 0;
		rwbuf_replan(rbuf);
		cds_list_del_init(&ss->elem_changed);
	}
}

//清理所有断开连接的session
static void sf_clean_offline(session_manager_t* sm) {
	int rt;
	sock_session_t* ss, * n;

	//这一步原本是在sf_del_sesion内的操作, 但是为了迎合带数据的FIN报文, 所以在这里新增了这一块代码
	//cds_list_for_each_entry_safe(ss, n, &sm->list_lively, elem_lively) {
	//	if (ss->flag.fin_peer) {
	//		//if (_SM_LIST_EMPTY(&ss->elem_online) == 0)
	//		cds_list_del_init(&ss->elem_lively);

	//		//加入到离线队列
	//		if (cds_list_empty(&ss->elem_offline) == 0)
	//			cds_list_add_tail(&ss->elem_offline, &ss->sm->list_offline);
	//	}
	//}

	cds_list_for_each_entry_safe(ss, n, &sm->list_offline, elem_offline) {
		cds_list_del_init(&ss->elem_offline);

		//rt = shutdown(pos->fd, SHUT_RDWR);
#ifndef _WIN32
		rt = close(ss->fd);
#else
		rt = closesocket(ss->fd);
		//rt = shutdown(ss->fd, SD_SEND);
#endif//_WIN32
		/*if (rt == -1)
			printf("close: %s\n", strerror(errno));*/

		//printf("shutdown offline: %s:%d\n", ss->ip, ss->port);

		sf_destruct_session(ss);
		cds_list_add_tail(&ss->elem_cache, &sm->list_session_cache);
	}
}

session_manager_t* sm_init_manager(uint32_t session_cache_size) {
	session_manager_t* sm = (session_manager_t*)malloc(sizeof(session_manager_t));
	if (!sm)return 0;

	memset(sm, 0, sizeof(session_manager_t));
	sm->flag.running = 1;
//	sm->ep_fd = -1;

	//Init all list
	CDS_INIT_LIST_HEAD(&(sm->list_lively));
	CDS_INIT_LIST_HEAD(&(sm->list_offline));
	CDS_INIT_LIST_HEAD(&(sm->list_reconnect));
	CDS_INIT_LIST_HEAD(&(sm->list_listens));
	CDS_INIT_LIST_HEAD(&(sm->list_changed));
	CDS_INIT_LIST_HEAD(&(sm->list_pending_recv));
	CDS_INIT_LIST_HEAD(&(sm->list_pending_send));
	CDS_INIT_LIST_HEAD(&(sm->list_session_cache));
#ifdef _WIN32
	//CDS_INIT_LIST_HEAD(&(sm->list_forgotten));
#endif//_WIN32

	//init rb root 
	CDS_INIT_LIST_HEAD(&(sm->list_fifo));
	CDS_INIT_LIST_HEAD(&(sm->list_outbox_fifo));
	//sm->rbroot_house_number = RB_ROOT;
	sm->rbroot_house_number.rb_node = NULL;

	//create cache_session
	for (int i = 0; i < session_cache_size; ++i) {
		sock_session_t* ss = (sock_session_t*)_sm_malloc(sizeof(sock_session_t));
		if (ss) {
			memset(ss, 0, sizeof(sock_session_t));
			sf_destruct_session(ss);
			cds_list_add_tail(&ss->elem_cache, &sm->list_session_cache);
		}
		else
			goto clean;
	}

	//inti timer manager
	sm->ht_timer = ht_create_heap_timer();
	if (sm->ht_timer == 0)
		goto clean;


#ifndef _WIN32
	//init epoll, try twice
	sm->ep_fd = epoll_create(EPOLL_CLOEXEC);
	if (sm->ep_fd == -1) {
		sm->ep_fd = epoll_create(1 << 15);	//32768
		if (sm->ep_fd == -1) {
			goto clean;
		}
	}

#else
	FD_ZERO(&sm->rfdst);
	FD_ZERO(&sm->wfdst);
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);
#endif//_WIN32

#if(ENABLE_SSL)
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
#endif//ENABLE_SSL
	
	ht_add_timer(sm->ht_timer, MAX_RECONN_SERVER_TIMEOUT * 1000, 0, -1, sf_timer_reconn_cb, &sm, sizeof(void*));
	return sm;


clean:
	if (cds_list_empty(&sm->list_session_cache) == 0) {
		sock_session_t* pos, * p;
		cds_list_for_each_entry_safe(pos, p, &sm->list_session_cache, elem_cache) {
			cds_list_del_init(&pos->elem_cache);
			_sm_free(pos);
		}
	}

#ifndef _WIN32
	if (sm->ep_fd != -1)
		close(sm->ep_fd);
#else
	WSACleanup();
#endif//_WIN32
		

	/*if (sm->tg)
		tg_exit_tirgger(sm->tg);*/

//	if (sm->sc)
//		sc_outof_business(sm->sc);

	if (sm->ht_timer)
		ht_destroy_heap_timer(sm->ht_timer);

	if (sm)
		free(sm);

	return 0;
}

void sm_exit_manager(session_manager_t* sm) {
	if (sm == 0)
		return;

	//clean resources and all session
	sock_session_t* pos, * n;
	//messenger_t* l, * r;
	cds_list_for_each_entry_safe(pos, n, &sm->list_lively, elem_lively) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_reconnect, elem_lively) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	cds_list_for_each_entry_safe(pos, n, &sm->list_listens, elem_listens) {
		sm_del_session(pos);
		printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port, "Active shutdown");
	}

	sf_clean_offline(sm);

	if (cds_list_empty(&sm->list_session_cache) == 0) {
		cds_list_for_each_entry_safe(pos, n, &sm->list_session_cache, elem_cache) {
			CDS_INIT_LIST_HEAD(&pos->elem_cache);
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

#ifndef _WIN32
	if (sm->ep_fd != -1)
		close(sm->ep_fd);
#else
	WSACleanup();
#endif//_WIN32

//	if (sm->sc)
//		sc_outof_business(sm->sc);

	if (sm->ht_timer)
		ht_destroy_heap_timer(sm->ht_timer);

	if (sm)
		free(sm);
}

void sm_set_running(session_manager_t* sm, uint8_t run) {
	if (sm) {
		sm->flag.running = run;
	}
}

sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, uint32_t max_send_len,
	session_behavior_t* accepted_behav, void* udata, uint8_t udata_len) {

	sock_session_t* ss = 0;
	struct sockaddr_in sin;
	int rt, err, fd, ev, optval = 1;

	if (!sm) return 0;

	fd = sf_try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		goto clean;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	rt = bind(fd, (const struct sockaddr*)&sin, sizeof(sin));
	if (rt == -1)
		goto clean;

	rt = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
	if (rt == -1)
		goto clean;

	rt = listen(fd, max_listen);
	if (rt == -1)
		goto clean;

	ss = sf_cache_session(sm);
	if (ss == 0)
		goto clean;

	rt = sf_construct_session(sm, ss, fd, "0.0.0.0", port, max_send_len, sf_accpet_cb, NULL/*accpet_function*/, accepted_behav, udata, udata_len);
	if (rt != SERROR_OK)
		goto clean;

	//add epoll status
	rt = sf_add_event(sm, ss, EV_ET | EV_RECV);
	if (rt)
		goto clean;

	//add to listener list
	cds_list_add_tail(&(ss->elem_listens), &(sm->list_listens));

	printf("[%s] [%s:%d] [%s], ip: [%s] port: [%d], msg: [%s]\n", sf_timefmt(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Add a listener");
	return ss;

clean:
	if (fd != -1)
#ifndef _WIN32
		close(fd);
#else
		closesocket(fd);
#endif//_WIN32

	if (ss)
		sf_free_session(sm, ss);
	return 0;
}

sock_session_t* sm_add_accepted(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, uint32_t max_send_len,
	session_behavior_t* behavior, void* udata, uint8_t udata_len) {

	if (!sm || fd < 0)
		return 0;

	int32_t rt, err = 0;
	sock_session_t* ss = sf_cache_session(sm);
	if (!ss)
		return 0;

	rt = sf_construct_session(sm, ss, fd, ip, port, max_send_len, sf_recv_cb/*sf_recv_cb*/, sf_send_cb, behavior, udata, udata_len);
	if (rt != SERROR_OK)
		goto clean;

	//add epoll status
	rt = sf_add_event(sm, ss, EV_ET | EV_RECV);
	if (rt)
		goto clean;

	//add to online list
	cds_list_add_tail(&(ss->elem_lively), &(sm->list_lively));
//	if (add_online)
//		cds_list_add_tail(&(ss->elem_lively), &(sm->list_lively));
//#ifdef _WIN32
//	else
//		cds_list_add_tail(&(ss->elem_lively), &(sm->list_forgotten));
//#endif//_WIN32

	//ss->flag.is_connect = ~0;
	return ss;

clean:
	if (ss)
		sf_free_session(sm, ss);
	return 0;
}

sock_session_t* sm_add_connect(session_manager_t* sm, const char* domain, uint16_t port, uint32_t max_send_len,
	uint8_t is_reconnect, session_behavior_t* behavior, void* udata, uint8_t udata_len) {

	if (!sm)
		return 0;

	int fd, rt, err, ev = 0;
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

		rt = connect(fd, (const sockaddr*)&sin, sizeof(sin));
		//if connect error
#ifndef _WIN32
		if (rt == -1 && errno != EINPROGRESS) {
#else
		if (rt == -1 && GetLastError() != WSAEWOULDBLOCK) {
#endif//_WIN32
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

		ss->flag.is_connect = ~0;

		if (is_reconnect) {
			ss->flag.reconnect = ~0;
		}

		cds_list_add_tail(&ss->elem_lively, &sm->list_lively);
//		if (add_online)
//			cds_list_add_tail(&ss->elem_lively, &sm->list_lively);
//#ifdef _WIN32
//		else
//			cds_list_add_tail(&ss->elem_lively, &sm->list_forgotten);
//#endif//_WIN32

		//cds_list_add_tail(&ss->elem_online, &sm->list_reconnect);
		return ss;

	} while (0);


	if (ss)
		sf_free_session(sm, ss);

	if (fd != -1){
#ifndef _WIN32
		close(fd);
#else
		closesocket(fd);
#endif//
	}

	return 0;
}

void sm_del_session(sock_session_t* ss) {
	//统一操作, 但不包括服务器列表
	//sf_del_session(ss, 1);

	sf_del_event(ss->sm, ss, EV_RECV | EV_WRITE);

#if(ENABLE_SSL)
	if (ss->flag.tls) {
		if (ss->tls_info.ctx)
			SSL_CTX_free((SSL_CTX*)(ss->tls_info.ctx));

		if (ss->tls_info.ssl)
			SSL_free((SSL*)(ss->tls_info.ssl));
	}
#endif//ENABLE_SSL

	//从未决队列中移除
	if (cds_list_empty(&ss->elem_pending_recv) == 0)
		cds_list_del_init(&ss->elem_pending_recv);

	if (cds_list_empty(&ss->elem_pending_send) == 0)
		cds_list_del_init(&ss->elem_pending_send);

	if (cds_list_empty(&ss->elem_listens) == 0)
		cds_list_del_init(&ss->elem_listens);

	//这里是为了迁就带有数据的FIN报文, 让session延迟回收

	//若没有数据到来,那么移除产生改变的列表, 这里应该永远都不应该被执行
	if (ss->flag.comming == 0) {
		if (cds_list_empty(&ss->elem_changed) == 0)
			cds_list_del_init(&ss->elem_changed);
	}
	

	
	/*if (ss->flag.comming == 0) {
		if (cds_list_empty(&ss->elem_online) == 0) {
			cds_list_del_init(&ss->elem_online);
		}
	}*/

	if (cds_list_empty(&ss->elem_lively) == 0) {
		cds_list_del_init(&ss->elem_lively);
	}

	//if(ss->flag.comming)

	/*if (ss->flag.reconnect == 0) {
		if (cds_list_empty(&ss->elem_servers) == 0)
			cds_list_del_init(&ss->elem_servers);
	}*/

	ss->flag.fin_peer = ~0;

	//加入到离线队列
	cds_list_add_tail(&ss->elem_offline, &ss->sm->list_offline);
}

int sm_add_signal(session_manager_t* sm, uint32_t sig, void (*cb)(int)) {
#ifndef _WIN32
	struct sigaction new_act;
	memset(&new_act, 0, sizeof(new_act));
	new_act.sa_handler = cb;
	sigfillset(&new_act.sa_mask);

	return sigaction(sig, &new_act, 0);
#else
	signal(sig, cb);
	return SERROR_OK;
#endif//_WIN32
}

uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval, uint32_t delay_ms, int32_t repeat, heap_timer_cb on_timeout, void* udata, uint8_t udata_len) {
	return ht_add_timer(sm->ht_timer, interval, delay_ms, repeat, on_timeout, udata, udata_len);
}

int32_t sm_send_fn(sock_session_t* ss, const char* data, uint32_t len) {
	int32_t rt;
	if (data && len > 0) {
		if (ss->flag.fin_peer == 0) {
			if (ss->uevent.encode_fn) {
				rt = ss->uevent.encode_fn(data, len, &ss->wbuf);

			}
			else {
				rt = rwbuf_append_complete(&ss->wbuf, data, len);
			}

			if (rt < 0)
				return rt;

			sf_add_event(ss->sm, ss, EV_WRITE);
		}

		return SERROR_OK;
	}
	return SERROR_INPARAM_ERR;
}

int32_t sm_tls_enable(sock_session_t* ss, tls_opt_t* tls_opt, _OUT char* errstr) {
	int32_t err = 0, tlserr, rt, flag;
#if(ENABLE_SSL)
	SSL_CTX* ctx = 0;
	SSL* ssl = 0;

	/*if (tls_opt->cert == 0 || tls_opt->key == 0)
		err = 1;*/

	if (ss->flag.is_connect)
		ctx = SSL_CTX_new(SSLv23_client_method());
	else 
		ctx = SSL_CTX_new(SSLv23_server_method());

	if (!ctx)
		err = SERROR_TLS_MLC_ERR;
	else {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
		//openssl 1.0.2 enable
		SSL_CTX_set_default_verify_paths(ctx);

		flag = SSL_VERIFY_NONE;
		if (tls_opt->verify_peer) {
			flag = ss->flag.is_connect ? SSL_VERIFY_PEER : (SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER);
		}
		SSL_CTX_set_verify(ctx, flag, NULL);
	}


	if (err == 0 && (tls_opt->ca || tls_opt->capath)) {
		if (rt = SSL_CTX_load_verify_locations(ctx, tls_opt->ca, tls_opt->capath) != 1)
			err = SERROR_TLS_CA_ERR;
	}

	if (tls_opt->cert && tls_opt->cert[0] != '\0' && tls_opt->key && tls_opt->cert[0] != '\0') {
		//加载自己的证书
		if (err == 0 && (rt = SSL_CTX_use_certificate_file(ctx, tls_opt->cert, SSL_FILETYPE_PEM)) == 1) {
			if (tls_opt->password && strlen(tls_opt->password))
				SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)tls_opt->password);
		}
		else
			err = SERROR_TLS_CERT_ERR;


		//加载私钥
		if (err == 0 && (rt = SSL_CTX_use_PrivateKey_file(ctx, tls_opt->key, SSL_FILETYPE_PEM)) != 1)
			err = SERROR_TLS_KEY_ERR;

		//判断私钥是否正确
		if (err == 0 && (rt = SSL_CTX_check_private_key(ctx)) != 1)
			err = SERROR_TLS_CHECK_ERR;

		if (err) {
			if (errstr)
				ERR_error_string(ERR_get_error(), errstr);

			if (ctx)
				SSL_CTX_free(ctx);

			ERR_clear_error();
			goto clean;
		}
	}

	//如果是客户端,为客户端创建独立的ssl
	if (ss->flag.is_connect) {
		ssl = SSL_new(ctx);
		if (!ssl)
			goto clean;
		else{
			SSL_set_fd(ssl, ss->fd);
			SSL_set_connect_state(ssl);

			//需要发起client hello
			sf_add_event(ss->sm, ss, EV_WRITE);

			ss->recv_cb = sf_tls_recv_cb;
			ss->send_cb = sf_tls_send_cb;
		}
	}

	ss->flag.tls = ~0;
	ss->tls_info.ctx = ctx;
	ss->tls_info.ssl = ssl;

	
	return SERROR_OK;
clean:
	if (ssl)
		SSL_free(ssl);

	if (ctx)
		SSL_CTX_free(ctx);

	return SERROR_TLS_LIB_ERR;

#else
	return SERROR_TLS_NOENABLE;
#endif//ENABLE_SSL
}

int32_t sm_ws_client_upgrade(sock_session_t* ss, const char* domain) {
	char fmt[256];
	char url[128] = { 0 };
	char host[64] = { 0 };
	unsigned char key[32];
	unsigned char b64[64];
	uint32_t fmt_len = 0;

	for (int i = 0; i < 30; ++i) {
		key[i] = rand() & 0xff;
	}

	base64_encode_r(key, 30, b64, sizeof(b64));

	char* cut = (char*)strchr(domain, ':');
	if (cut) {
		strncpy(host, domain, cut - domain);

		cut = strchr(cut, '/');
		if (cut) {
			strcpy(url, cut);
		}
		else {
			url[0] = '/';
		}
		
	}
	else {
		cut = (char*)strchr(domain, '/');
		if (cut) {
			strncpy(host, domain, cut - domain);
			strcpy(url, cut);
		}
		else {
			url[0] = '/';
		}
		
	}

	ss->flag.ws = ~0;
	ss->flag.ws_handshake = 0;

	sprintf(fmt,
		"GET %s HTTP/1.1\r\n"
		"Upgrade: websocket\r\n"
		"Host: %s\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"\r\n", url, host, b64);

	fmt_len = strlen(fmt);
	if (!rwbuf_enough(&ss->wbuf, fmt_len)) {
		return SERROR_WS_OVERFLOW;
	}

	rwbuf_append(&ss->wbuf, fmt, fmt_len);

	return sf_add_event(ss->sm, ss, EV_WRITE);
}

int32_t sm_run2(session_manager_t* sm, uint64_t us) {
#ifndef _WIN32
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

#else

	struct timeval tv;
	tv.tv_sec = us / 1000;
	tv.tv_usec = (us - tv.tv_sec * 1000) * 1000;

	FD_ZERO(&sm->rfdst);
	FD_ZERO(&sm->wfdst);

	sock_session_t* ss, * n;
	cds_list_for_each_entry_safe(ss, n, &sm->list_listens, elem_listens) {
		if(ss->epoll_state & EV_RECV)
			FD_SET(ss->fd, &sm->rfdst);
	}

	cds_list_for_each_entry_safe(ss, n, &sm->list_lively, elem_lively) {
		if (ss->epoll_state & EV_RECV)
			FD_SET(ss->fd, &sm->rfdst);

		if (ss->epoll_state & EV_WRITE)
			FD_SET(ss->fd, &sm->wfdst);
	}
	
	int rt = select(0, &sm->rfdst, &sm->wfdst, 0, &tv);
	if (rt == SOCKET_ERROR) {
		//if (errno != EINTR) { return -1; }
		int eno = GetLastError();
		return 0;
	}

	if (rt != 0) {
		cds_list_for_each_entry_safe(ss, n, &sm->list_listens, elem_listens) {
			if (FD_ISSET(ss->fd, &sm->rfdst)) {
				ss->recv_cb(ss);
			}
		}

		cds_list_for_each_entry_safe(ss, n, &sm->list_lively, elem_lively) {
			if (FD_ISSET(ss->fd, &sm->rfdst)) {
				ss->recv_cb(ss);
			}

			if (FD_ISSET(ss->fd, &sm->wfdst)) {
				ss->send_cb(ss);
			}
		}
	}

#endif//_WIN32

	sf_pending_send(sm);
	sf_pending_recv(sm);
	sf_call_decode_fn(sm);
	sf_clean_offline(sm);

	return ~0;
}

void sm_run(session_manager_t* sm) {
	static uint8_t first = 1;
	while (sm->flag.running) {
		uint64_t waitms = ht_update_timer(sm->ht_timer);

		if (first) {
			waitms = 0;
			first = 0;
		}

		if (cds_list_empty(&sm->list_pending_send) == 0 || cds_list_empty(&sm->list_pending_recv) == 0 || !cds_list_empty(&sm->list_outbox_fifo))
			waitms = 0;

		//signal
		if (sm_run2(sm, waitms) == 0) {
#ifdef _WIN32
			sm->flag.running = 0;
#endif//_WIN32
		}
	}
}