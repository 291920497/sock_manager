#ifndef _FRONT_DESK_H_
#define _FRONT_DESK_H_

//前台, 处理用户请求

//#include "messenger/messenger.h"
//#include "../sock_manager.h"
#include "../tools/rwbuf/rwbuf.h"

typedef enum etheme {
	//分拣中心(回调中会收到的时间)
	THEME_CREATE = 1 << 0,	//连接被创建
	THEME_DESTORY = 1 << 2,	//连接被销毁
	THEME_RECV = 1 << 3,	//可读
	THEME_RECV_AND_DESTROY = THEME_RECV | THEME_DESTORY,	//可读事件, 但是这个会话已经被关闭, 不再接收信息

	THEME_SEND = 1 << 16,	//可写
//	THEME_READY = 1 << 17,	//设置准备就绪
	THEME_REVISE_UDATA = 1 << 18,	//修改
}theme_t;

typedef struct messenger messenger_t;
typedef struct session_manager session_manager_t;
typedef struct sortingcenter_ctx sortingcenter_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

//void frontd_sent_letters()

//以下3个接口, 线程安全, 主要为了解决, 连接了服务器后, 可能在任意时间在任意线程向服务器发起消息

/*
*	frontd_hire_messenge , 招募一个信使来完成消息的传输, 可在解包完成回调内外使用
*	线程安全, 可重入
*	ss_ctx: 在sm_run之前调用sm_soringcenter_ctx, 提前保存的sortingcenter_ctx_t(在回调外传输消息旧的上下文可能已经失效)
*	return val:
*		0: 失败
*		other: 一个未携带任何信件的信使
*/
messenger_t* frontd_hire_messenger(sortingcenter_ctx_t* ss_ctx);

/*
*	frontd_fire_messenger, 开掉一个信使, 携带的信件将被销毁, 可在解包完成回调内外使用
*	线程安全, 可重入
*	msger: 由frontd_hire_messenger产生的返回值(不能在回调中使用该方法释放回调函数预招募的信使)
*/

void frontd_fire_messenger(messenger_t* msger);

/*
*	front_submit_sorting_center, 将信使提交到sm的分拣中心, 可在解包完成回调内外使用
*	线程不安全(调用前后保证sm尚未消亡), 可重入
*	sm:	由sm_init_manager创建
*	msger: 仅由frontd_hire_messenger创建的信使才可调用该函数
*/

void front_submit_sorting_center(session_manager_t* sm, messenger_t* msger);

/*
*	frontd_add_aparagraph_with_rwbuf, 将一段话交给msger(信使)托管, 通过rwbuf的方式
*	线程安全, 可重入
*	sentence: 需要信使传达的一句话
*	msger: 希望代理sentence的信使
*	theme: theme_t事件, 除主线程外, 能使用的包含 THEME_DESTORY THEME_READY THEME_SEND
*/

int32_t frontd_add_aparagraph_with_rwbuf(messenger_t* msger, rwbuf_t* sentence, theme_t theme);

/*
*	frontd_add_aparagraph_after_encoding_with_ram, 将数据调用msger信使携带的编码函数的对data编码后交给msger
*	线程安全, 可重入
*	msger: 代理数据的信使
*	data: 待封包的数据
*	len: 待封包的长度
*	theme: 具体提交的事件
*/
int32_t frontd_add_aparagraph_after_encoding_with_ram(messenger_t* msger, const char* data, uint32_t len, theme_t theme);


#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_FRONT_DESK_H_