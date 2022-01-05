#ifndef _SOCK_MANAGER_H_
#define _SOCK_MANAGER_H_

#include <stdint.h>

#include "serror.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

//#if (SM_DISPATCH_MODEL)
//session_manager_t* sm_init_manager(uint32_t session_cache_size, session_dispatch_data_cb dispatch_cb);
//#else
//session_manager_t* sm_init_manager(uint32_t session_cache_size);
//#endif//SM_DISPATCH_MODEL

session_manager_t* sm_init_manager(uint32_t session_cache_size);

void sm_exit_manager(session_manager_t* sm);

void sm_set_running(session_manager_t* sm, uint8_t run);

sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, session_opt_t* opt);

sock_session_t* sm_add_accepted(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, session_opt_t* opt);

sock_session_t* sm_add_connect(session_manager_t* sm, const char* domain, uint16_t port, uint8_t is_reconnect, session_opt_t* opt);

void sm_del_session(sock_session_t* ss);

int32_t sm_add_signal(session_manager_t* sm, uint32_t sig, void (*cb)(int));

uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval, int32_t delay_ms, int32_t repeat, heap_timer_cb on_timeout, void* udata, uint8_t udata_len);

int32_t sm_0copy_send_fn(sock_session_t* ss, const char* data, uint32_t len, uint8_t call_encode, uint8_t close_after_sending);

int32_t sm_upgrade_dispatch_model(session_manager_t* sm, session_dispatch_data_cb dispatch_cb);

int32_t sm_upgrade_tls(sock_session_t* ss, tls_opt_t* tls_opt, _OUT char* errstr);

int32_t sm_ws_client_upgrade(sock_session_t* ss, const char* host);

int32_t sm_run2(session_manager_t* sm, uint64_t us);

void sm_run(session_manager_t* sm);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SOCK_MANAGER_H_