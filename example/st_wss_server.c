#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sock_manager/sock_manager.h"
#include "sock_manager/protocol/websocket/ws.h"
#include <signal.h>

#define CA_FILE "/root/tls/root/root.crt"
#define CERT_FILE "/root/tls/server/server.crt"
#define KEY_FILE "/root/tls/server/server.key"
#define PWD "123456"

session_manager_t* g_sm;

void sig_cb(int sig);
void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv);

int main(int argc, char** argv) {
	if (argc < 3) {
		printf("exec CacheCount(20480) ListenPort(6666)\n");
		return -1;
	}

	int32_t rt;
	uint32_t nCacheCount = atoi(argv[1]);
	uint16_t nPort = atoi(argv[2]);

	session_opt_t opt;
	opt.rcvlen = 8192;
	opt.sndlen = 8192;
	opt.overflow = 65536;
	opt.udata = 0;

	//作为websocket服务器, 采用websocket协议解包
	opt.behav.decode_cb = ws_decode_cb;
	opt.behav.encode_fn = ws_svr_encode_fn;
	opt.behav.complete_cb = complate_cb;

	session_manager_t* sm = sm_init_manager(nCacheCount);
	g_sm = sm;

	sm_add_signal(sm, SIGINT, sig_cb);
	sock_session_t* ss = sm_add_listen(sm, nPort, 1024, &opt);

	//upgrade tls
	char errstr[256];
	uint8_t is_need_client_cert = 0;

	tls_opt_t tlsopt;
	memset(&tlsopt, 0, sizeof(tlsopt));

	//是否要求客户端提供证书
	if (is_need_client_cert) {
		tlsopt.ca = CA_FILE;
		tlsopt.verify_peer = 1;
	}

	tlsopt.cert = CERT_FILE;
	tlsopt.key = KEY_FILE;
	tlsopt.password = PWD;

	//提升为tls协议
	rt = sm_upgrade_tls(ss, &tlsopt, errstr);
	if (rt != SERROR_OK) {
		printf("%s\n", errstr);
		exit(-1);
	}

	sm_run(sm);

	sm_exit_manager(sm);

	return 0;
}



void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv) {
	if (pkg_type == SM_PACKET_TYPE_DATA) {
		sm_0copy_send_fn(ss, data, len, 1, 0);
	}
	else if (pkg_type == SM_PACKET_TYPE_CREATE) {
	}
	else if (pkg_type == SM_PACKET_TYPE_DESTORY) {
	}
	else if (pkg_type == SM_PACKET_TYPE_PONG) {
	}
	else if (pkg_type == SM_PACKET_TYPE_PING) {
	}
}

void sig_cb(int sig) {
	if (sig == SIGINT) {
		sm_set_running(g_sm, 0);
		printf("SIGINT\n");
	}
#ifndef _WIN32
	else if (sig == SIGPIPE) {
		printf("SIGPIPE\n");
	}
#endif//_WIN32

#ifdef _WIN32
	sm_add_signal(g_sm, sig, sig_cb);
#endif//_WIN32
}