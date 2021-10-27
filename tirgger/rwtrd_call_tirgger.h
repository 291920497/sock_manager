#ifndef _RWTRD_CALL_TIRGGER_H_
#define _RWTRD_CALL_TIRGGER_H_

#include <stdint.h>

//sock manager
#include "../sock_manager.h"


typedef struct tirgger tirgger_t;
typedef struct behav_tirgger behav_tirgger_t;


//读写线程添加一个触发器到临时列表
int32_t tg_rwtrd_add_rcvmsg2tmp(tirgger_t* tg, uint8_t ev, uint32_t hash, void* session_addr, const char* data, uint32_t data_len, session_event_cb ev_cb, void* udata, uint8_t udata_len);

void tg_rwtrd_merge_rcvmsg(tirgger_t* tg);

int32_t tg_rwtrd_tirgger_pipe0(tirgger_t* tg);

#endif//_RWTRD_CALL_TIRGGER_H_