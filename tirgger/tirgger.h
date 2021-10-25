#ifndef _TIRGGER_H_
#define _TIRGGER_H_

#include "../smlist.h"

typedef struct tirgger tirgger_t;

#ifdef __cplusplus
extern "C" {;
#endif//__cplusplus

//将newp这个消息列表添加到tg的消息列表后面
void tg_add_rcvmsg_tail(tirgger_t* tg, _sm_list_head* newp);

void tg_add_sndmsg_tail(tirgger_t* tg, _sm_list_head* newp);

//将tg的消息列表添加到newp的后面
void tg_rcvmsg_add_tail(tirgger_t* tg, _sm_list_head* newp);

void tg_sndmsg_add_tail(tirgger_t* tg, _sm_list_head* newp);

#ifdef __cplusplus
}
#endif//__cplusplus


#endif//_TIRGGER_H_