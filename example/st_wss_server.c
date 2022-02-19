#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sock_manager/sock_manager.h"
#include "sock_manager/protocol/websocket/ws.h"
#include <signal.h>

//#define CA_FILE "/root/tls/root/root.crt"
//#define CERT_FILE "/root/tls/server/server.crt"
//#define KEY_FILE "/root/tls/server/server.key"
//#define PWD "123456"

session_manager_t* g_sm;

void sig_cb(int sig);
void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv);

int main(int argc, char** argv) {
	if (argc < 5) {
        //如果需要客户端提供证书,才需要CA_FILE
        printf("%s <CacheCount> <ListenPort> <CERT_FILE> <KET_FILE> [CA_FILE]\n"\
            "example: %s 20480 6666 /root/tls/server/server.crt /root/tls/server/server.key /root/tls/root/ca.crt\n", argv[0], argv[0]);
		return -1;
	}

	int32_t rt;
	uint32_t nCacheCount = atoi(argv[1]);
	uint16_t nPort = atoi(argv[2]);
    const char* szCertFile = argv[3];
    const char* szKeyFile = argv[4];
    const char* szCAFile = 0;
    if (argc > 5) {
        szCAFile = argv[5];
    }

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
#ifndef _WIN32
	//由于openssl ,在调用SSL_shutdown时, BIO_write可能还有一些工作, 会导致SIGPIPE错误, 忽略即可
	sm_add_signal(sm, SIGPIPE, sig_cb);
#endif//_WIN32
	sock_session_t* ss = sm_add_listen(sm, nPort, 1024, &opt);

	//upgrade tls
	char errstr[256];
	uint8_t is_need_client_cert = 0;

	tls_opt_t tlsopt;
	memset(&tlsopt, 0, sizeof(tlsopt));

	//是否要求客户端提供证书
	if (is_need_client_cert) {
		tlsopt.ca = szCAFile;
		tlsopt.verify_peer = 1;
	}

	tlsopt.cert = szCertFile;
	tlsopt.key = szKeyFile;
	tlsopt.password = 0;

	//提升为tls协议
	rt = sm_upgrade_tls(ss, &tlsopt, errstr);
	if (rt != SERROR_OK) {
        printf("err: %d, %s\n", rt, errstr);
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