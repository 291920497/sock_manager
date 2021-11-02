#ifndef _FRONT_DESK_H_
#define _FRONT_DESK_H_

//前台, 处理用户请求

//#include "messenger/messenger.h"

typedef struct messenger messenger_t;
typedef struct sorting_center sorting_center_t;

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

//void frontd_sent_letters()

//以下3个接口, 线程安全, 主要为了解决, 连接了服务器后, 可能在任意时间在任意线程向服务器发起消息

//招募一个信使
messenger_t* frontd_hire_messenger(uint32_t hash, void* session_address);

void frontd_fire_messenger(messenger_t* msger);

//让信使带着信去收件箱, 如果没有任何内容, 那么信使将被销毁
void front_detach_messenger(sorting_center_t* sc, messenger_t* msger);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_FRONT_DESK_H_