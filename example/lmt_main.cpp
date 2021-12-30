#include <stdio.h>

#include <signal.h>
#include "sock_manager/sock_manager.h"
#include "sock_manager/protocol/websocket/ws.h"
#include "sock_manager/protocol/tcp_binary/tcp_binary.h"
#include "sock_manager/external_fn.h"

#include <iostream>
#include <thread>
using namespace std;

session_manager_t* g_sm;

void sig_cb(int sig) {
	if (sig == SIGINT) {
		sm_set_running(g_sm, 0);
		printf("SIGINT\n");
		sm_add_signal(g_sm, SIGINT, sig_cb);
	}
}

#if (SM_MULTI_THREAD)

void dsp_cb(session_manager_t* sm, cds_list_head_t* list_vehicle) {
	char _buf[1024];
	uint32_t len;
	char* ptr;
	external_buf_vehicle_t* pos, * p;
	external_buf_t* pos1, * p1;
	cds_list_head_t _list;
	CDS_INIT_LIST_HEAD(&_list);

	cds_list_for_each_entry_safe(pos, p, list_vehicle, elem_sndbuf) {
		external_buf_vehicle_t ebv;
		memset(&ebv, 0, sizeof(ebv));
		CDS_INIT_LIST_HEAD(&ebv.list_datas);
		CDS_INIT_LIST_HEAD(&ebv.elem_sndbuf);


		cds_list_for_each_entry_safe(pos1, p1, &pos->list_datas, elem_datas) {
			ptr = (char*)rwbuf_start_ptr(&pos1->data);
			len = rwbuf_len(&pos1->data);

			if (pos->behav.complete_cb)
				pos->behav.complete_cb(pos->address, pos->hash, pos1->type, pos->total, ptr, len, pos->userdata, &pos->behav, &ebv);

			ef_remove_msgfvehicle(pos, pos1);
		}

		//若有数据需要发送, 添加到临时链表
		if (!cds_list_empty(&ebv.list_datas)) {
			external_buf_vehicle_t* pebv = ef_create_vehicle(pos->address, pos->hash, &pos->behav, pos->userdata);
			pebv->total = ebv.total;
			cds_list_splice_tail(&ebv.list_datas, &pebv->list_datas);
			cds_list_add_tail(&pebv->elem_sndbuf, &_list);
		}

		//断开连接, 销毁载具
		cds_list_del(&pos->elem_sndbuf);
		ef_destory_vehicle(pos);

	/*	if (cds_list_empty(&pos->list_datas)) {
			cds_list_del(&pos->elem_sndbuf);
			ef_destory_vehicle(pos);
		}*/
	}

	//将需要发送的数据包提交到sock_manager, 并唤起sm_run调用线程,
	ef_deliver_pkgs(sm, &_list);
	_sm_free(list_vehicle);


	/*if (cds_list_empty(list_vehicle)) {
		_sm_free(list_vehicle);
	}*/

	//ef_deliver_pkgs(sm, list_vehicle);
}

void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv){
	if (pkg_type == SM_PACKET_TYPE_DATA) {
		char _buf[1024];
		memcpy(_buf, data, len);
		_buf[len] = 0;
		printf("total: %d, len: %d, %s\n", total, len, _buf);

		rwbuf_t wbuf;
		rwbuf_init(&wbuf);

		behav->encode_fn(data, len, &wbuf);
		ef_insert_msg2vehicle(ebv, &wbuf, SM_PACKET_TYPE_DATA);
	}
	else if (pkg_type == SM_PACKET_TYPE_CREATE) {
		printf("%s:%d create\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_DESTORY) {
		printf("%s:%d destory\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_PONG) {
		printf("%s:%d pong\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_PING) {
		printf("%s:%d ping\n", ss->ip, ss->port);
	}
}

#else

void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, const char* data, uint32_t len, void* udata) {
	if (pkg_type == SM_PACKET_TYPE_DATA) {
		char _buf[1024];
		memcpy(_buf, data, len);
		_buf[len] = 0;
		printf("%s\n", _buf);

		sm_send_fn(ss, data, len);
	}
	else if (pkg_type == SM_PACKET_TYPE_CREATE) {
		printf("%s:%d create\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_DESTORY) {
		printf("%s:%d destory\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_PONG) {
		printf("%s:%d pong\n", ss->ip, ss->port);
	}
	else if (pkg_type == SM_PACKET_TYPE_PING) {
		printf("%s:%d ping\n", ss->ip, ss->port);
	}

	
}

#endif//SM_MULTI_THREAD

void tcp_listener(uint32_t port) {
	session_behavior_t behav;
	behav.decode_cb = tcp_binary_decode_cb;
	behav.encode_fn = tcp_binary_encode_fn;
	behav.complete_cb = complate_cb;
#if (SM_MULTI_THREAD)
	session_manager_t* sm = sm_init_manager(100, dsp_cb);
#else
	session_manager_t* sm = sm_init_manager(100);
#endif
	g_sm = sm;
	sm_add_signal(sm, SIGINT, sig_cb);
	sock_session* ss = sm_add_listen(sm, port, 1024, 20, &behav, 0);

	sm_run(sm);
	sm_exit_manager(sm);
}

void ws_listener(uint32_t port) {
	session_behavior_t behav;
	behav.decode_cb = ws_decode_cb;
	behav.encode_fn = ws_svr_encode_fn;
	behav.complete_cb = complate_cb;
#if (SM_MULTI_THREAD)
	session_manager_t* sm = sm_init_manager(100, dsp_cb);
#else
	session_manager_t* sm = sm_init_manager(100);
#endif
	g_sm = sm;
	sm_add_signal(sm, SIGINT, sig_cb);
	sock_session* ss = sm_add_listen(sm, port, 10, 8192, &behav, 0);

	sm_run(sm);
	sm_exit_manager(sm);
}

int main() {
#if _WIN32
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);
#endif//_WIN32

	//thread t1(ws_listener, 7777);
	//t1.detach();

	tcp_listener(6666);

	

#if _WIN32
	WSACleanup();
#endif//_WIN32

	return 0;
}