#ifndef _TIRGGER_H_
#define _TIRGGER_H_

#include "../smlist.h"
#include "../sock_manager.h"
#include "../tools/heap_timer/heap_timer.h"
#include "../tools/rwbuf/rwbuf.h"

typedef struct tirgger tirgger_t;
typedef struct behav_tirgger behav_tirgger_t;


enum {
	//连接被创建, 逻辑线程处理
	TEV_CREATE = 1 << 0,
	//有可读数据, 逻辑线程处理
	TEV_READ = 1 << 1,
	//连接断开, 可与读写结合
	TEV_DESTROY = 1 << 2,


	//有可写数据, 读写线程处理
	TEV_WRITE = 1 << 16,
	////发送数据失败提示, 逻辑线程处理
	//TEV_WRITE_FAILURE = 1 << 17,
	//设置为准备就绪, 只有设置了该标识才能广播数据
	TEV_SET_READY = 1 << 17,
	//主动断开一个session, 逻辑线程向管理线程发起
	TEV_DEL_SESSION = 1 << 18,
};

enum {
	TCTL_HAVE_RCVMSG,
	TCTL_HAVE_SNDMSG,
};

#ifdef __cplusplus
extern "C" {;
#endif//__cplusplus

tirgger_t* tg_init_tirgger();

void tg_exit_tirgger(tirgger_t* tg);

void tg_destruct_behav(behav_tirgger_t* bt);

#ifdef __cplusplus
}
#endif//__cplusplus


#endif//_TIRGGER_H_