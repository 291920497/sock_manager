#ifndef _TIRGGER_H_
#define _TIRGGER_H_

#include "../smlist.h"
#include "../sock_manager.h"
#include "../tools/rwbuf/rwbuf.h"

enum {
	//连接被创建, 逻辑线程处理
	TEV_CREATE,
	//有可读数据, 逻辑线程处理
	TEV_READ,
	//有可写数据, 读写线程处理
	TEV_WRITE,
	//连接断开, 可与读写结合
	TEV_DESTROY,
	//发送数据失败提示, 逻辑线程处理
	TEV_WRITE_FAILURE,
	//设置为准备就绪, 只有设置了该标识才能广播数据
	TEV_SET_READY,
	//主动断开一个session, 逻辑线程向管理线程发起
	TEV_DEL_SESSION,
};

typedef struct tirgger {
	_sm_list_head list_recv_msg;	//接收缓冲区的列表
	pthread_spinlock_t lock_recv_msg;

	_sm_list_head list_send_msg;	//发送缓冲区列表
	pthread_spinlock_t lock_send_msg;

	//rb_root_t rbroot_session;		//key - session hash, value - tirgger_session_ctx_t
}tirgger_t;

typedef struct behav_tirgger {
	uint8_t	ev;					//当前上下文的事件状态
	uint8_t		udatalen;		//用户数据长度
	uint8_t		udata[MAX_USERDATA_LEN];		//用户数据, 用户自定义

	uint32_t hash;					//绑定的session的hash
	void* session_addr;				//session的存储地址

	rwbuf_t		buf;				//消息缓冲区, 需要注意第一次初始化.
	session_event_cb event_cb;		//事件回调

	_sm_list_head elem_variable;	//这是一个变量, 他可能需要在多个list中移动
}behav_tirgger_t;

typedef enum {
	TIRGGER_SOURCE_RWTHREAD,	//调用来源, 消息读写线程
	TIRGGER_SOURCE_TGTHREAD,	//调用来源, 事件触发线程
}TIRGGER_SOURCE_E;

#ifdef __cplusplus
extern "C" {;
#endif//__cplusplus

//将newp这个消息列表添加到tg的消息列表后面
void tg_add_rcvmsg_tail(tirgger_t* tg, _sm_list_head* newp);

void tg_add_sndmsg_tail(tirgger_t* tg, _sm_list_head* newp);

//将tg的消息列表添加到newp的后面
void tg_rcvmsg_add_tail(tirgger_t* tg, _sm_list_head* newp);

void tg_sndmsg_add_tail(tirgger_t* tg, _sm_list_head* newp);

behav_tirgger_t* tg_construct_behav_tirgger(uint8_t ev, uint32_t hash, void* session_addr, const char* data, uint32_t data_len, session_event_cb ev_cb, void* udata, uint8_t udata_len, int32_t* out_err);

void tg_destruct_behav_tirgger(behav_tirgger_t* bt);

#ifdef __cplusplus
}
#endif//__cplusplus


#endif//_TIRGGER_H_