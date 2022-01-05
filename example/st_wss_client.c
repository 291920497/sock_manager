#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sock_manager/sock_manager.h"
#include "sock_manager/protocol/websocket/ws.h"
#include <signal.h>

#define CA_FILE "/root/tls/root/root.crt"
#define CERT_FILE "/root/tls/client/client.crt"
#define KEY_FILE "/root/tls/client/client.key"
#define PWD "123456"

session_manager_t* g_sm;

void sig_cb(int sig);
void complate_cb(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv);

int main(int argc, char** argv) {
	if (argc < 6) {
		printf("exec CacheCount(20480) ConnectHost(127.0.0.1) ConnectPort(6666) ClientCount(20480) SendDataLen(<4096)\n");
		return -1;
	}

	int32_t rt;
	uint32_t nCacheCount = atoi(argv[1]);
	const char* ip = argv[2];
	uint16_t nPort = atoi(argv[3]);
	uint32_t nClientCount = atoi(argv[4]);
	uint32_t nSendDataLen = atoi(argv[5]);

	if (nSendDataLen > 8192)
		nSendDataLen = 8188;

	char data[8192];

	session_opt_t opt;
	opt.rcvlen = 8192;
	opt.sndlen = 8192;
	opt.overflow = 65536;
	opt.udata = 0;

	//作为websocket服务器, 采用websocket协议解包
	opt.behav.decode_cb = ws_decode_cb;
	opt.behav.encode_fn = ws_clt_encode_fn;
	opt.behav.complete_cb = complate_cb;

	//upgrade tls
	char errstr[256];

	tls_opt_t tlsopt;
	memset(&tlsopt, 0, sizeof(tlsopt));

	tlsopt.ca = CA_FILE;	//客户端需要检验服务器的证书, 是否信任, 如果是自签证书, 需要设置ca
	tlsopt.cert = CERT_FILE;
	tlsopt.key = KEY_FILE;
	tlsopt.password = PWD;
	//tlsopt.verify_peer = 0;	//默认校验

	session_manager_t* sm = sm_init_manager(nCacheCount);
	g_sm = sm;

	sm_add_signal(sm, SIGINT, sig_cb);
#ifndef _WIN32
	//由于openssl ,在调用SSL_shutdown时, BIO_write可能还有一些工作, 会导致SIGPIPE错误, 忽略即可
	sm_add_signal(sm, SIGPIPE, sig_cb);
#endif//_WIN32

	for (int i = 0; i < nClientCount; ++i) {
		sock_session_t* ss = sm_add_connect(sm, ip, nPort, 0, &opt);

		//提升为tls协议
		rt = sm_upgrade_tls(ss, &tlsopt, errstr);
		if (rt != SERROR_OK) {
			printf("%s\n", errstr);
			exit(-1);
		}

		//提升为websocket协议
		sprintf(errstr, "%s:%d/", ip, nPort);
		rt = sm_ws_client_upgrade(ss, errstr);

		sm_0copy_send_fn(ss, data, nSendDataLen, 1, 0);
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