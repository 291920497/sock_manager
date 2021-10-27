#include "tirgger.h"
//#include "../tools/stl/list.h"


#include "../tools/stl/rbtree.h"

#include "../serror.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include "rwtrd_call_tirgger.h"


typedef struct tirgger {
	_sm_list_head list_recv_tmp;	//读写线程专用的读临时列表

	_sm_list_head list_recv_msg;	//接收缓冲区的列表
	pthread_spinlock_t lock_recv_msg;

	_sm_list_head list_send_tmp;	//触发线程专用的写临时列表

	_sm_list_head list_send_msg;	//发送缓冲区列表
	pthread_spinlock_t lock_send_msg;

	heap_timer_t* ht;
	int32_t tirgger_pipe[2];		//触发器管道
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

//
//
//
//typedef struct rb_root rb_root_t;
//typedef struct rb_node rb_node_t;
//
//
//
//typedef struct tev_flag {
//	int32_t closed : 1;				//是否已经关闭
//	int32_t ready : 1;				//是否准备就绪, 例如握手/鉴权完成
//}tev_flag_t;
//
////单个消息触发
//typedef struct tirgger_session_single_ctx {
//	uint32_t	ev;					//当前上下文的事件状态
//	rwbuf_t		buf;				//消息缓冲区, 需要注意第一次初始化.
//
//	uint32_t hash;					//绑定的session的hash
//	void* session_addr;				//session的存储地址
//
//
//	_sm_list_head elem_msg_block;	//消息分块列表
//}tirgger_session_single_ctx_t;
//
////单个上下文
//typedef struct tirgger_session_ctx {
//	tev_flag_t flag;				//状态标志
//
//	uint32_t hash;					//绑定的session的hash
//	void* session_addr;				//session的存储地址
//
//	uint32_t sum;					//所有消息块长度的和
//	uint32_t value_trigger;			//当消息块的长度之和>=这个值时, 触发回调
//	uint32_t offset;				//偏移量, 为数据结尾未知准备的
//	uint64_t last_active;			//最后一次活跃的时间 unix时间戳
//
//	session_behavior_t uevent;		//用户行为
//
//	_sm_list_head list_msg_block;	//当前session的所有消息块列表
//	struct rb_node rbnode_session;	//红黑树节点
//}tirgger_session_ctx_t;
//


tirgger_t* tg_init_tirgger() {
	int32_t rt = 0;
	tirgger_t* tg = malloc(sizeof(tirgger_t));
	if (tg) {
		memset(tg, 0, sizeof(tirgger_t));
		tg->tirgger_pipe[0] = -1;
		tg->tirgger_pipe[1] = -1;
		_SM_LIST_INIT_HEAD(&tg->list_recv_msg);
		_SM_LIST_INIT_HEAD(&tg->list_send_msg);

		_SM_LIST_INIT_HEAD(&tg->list_recv_tmp);
		_SM_LIST_INIT_HEAD(&tg->list_send_tmp);

		tg->ht = ht_create_heap_timer();
		if (!tg->ht)
			goto init_tirgger_failed;
			

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, &tg->tirgger_pipe) == -1) 
			goto init_tirgger_failed;

		if (pthread_spin_init(&tg->lock_recv_msg, PTHREAD_PROCESS_PRIVATE))
			rt |= 1;
		if (pthread_spin_init(&tg->lock_send_msg, PTHREAD_PROCESS_PRIVATE))
			rt |= 2;

		//虽然从未发生过, 但是万一呢
		if(rt)
			goto init_tirgger_failed;

		return tg;
	}

	return 0;
init_tirgger_failed:
	if (tg->ht)
		ht_destroy_heap_timer(tg->ht);

	if (tg->tirgger_pipe[0] != 0) {
		close(tg->tirgger_pipe[0]);
		tg->tirgger_pipe[0] = -1;

		close(tg->tirgger_pipe[1]);
		tg->tirgger_pipe[1] = -1;
	}

	if (rt) {
		if (rt & 1)
			pthread_spin_destroy(&tg->lock_recv_msg);
		if (rt & 2)
			pthread_spin_destroy(&tg->lock_send_msg);
		free(tg);
	}

	return 0;
}

void tg_exit_tirgger(tirgger_t* tg) {
	if (tg) {
		behav_tirgger_t* pos, * n;
		pthread_spin_lock(&tg->lock_recv_msg);
		_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &tg->list_recv_msg, elem_variable) {
			_SM_LIST_DEL_INIT(&pos->elem_variable);
			tg_destruct_behav(pos);
		}
		pthread_spin_unlock(&tg->lock_recv_msg);

		pthread_spin_lock(&tg->lock_send_msg);
		_SM_LIST_FOR_EACH_ENTRY_SAFE(pos, n, &tg->list_send_msg, elem_variable) {
			_SM_LIST_DEL_INIT(&pos->elem_variable);
			tg_destruct_behav(pos);
		}
		pthread_spin_unlock(&tg->lock_send_msg);

		pthread_spin_destroy(&tg->lock_recv_msg);
		pthread_spin_destroy(&tg->lock_send_msg);

		ht_destroy_heap_timer(tg->ht);

		close(tg->tirgger_pipe[0]);
		close(tg->tirgger_pipe[1]);
		free(tg);
	}
}

int32_t tg_rwtrd_add_rcvmsg2tmp(tirgger_t* tg, uint8_t ev, uint32_t hash, void* session_addr, const char* data, uint32_t data_len, session_event_cb ev_cb, void* udata, uint8_t udata_len) {
	int32_t rt;
	behav_tirgger_t* bt = 0;

	if (udata_len > MAX_USERDATA_LEN)
		return SERROR_INPARAM_ERR;

	do {
		bt = (behav_tirgger_t*)malloc(sizeof(behav_tirgger_t));
		if (!bt)
			return SERROR_SYSAPI_ERR;

		memset(bt, 0, sizeof(behav_tirgger_t));

		//准备数据
		if (data_len) {
			rt = rwbuf_relc(&bt->buf, data_len);
			if (rt != SERROR_OK)
				break;

			rwbuf_append(&bt->buf, data, data_len);
		}

		bt->ev = ev;
		bt->hash = hash;
		bt->session_addr = session_addr;
		bt->event_cb = ev_cb;
		_SM_LIST_INIT_HEAD(&bt->elem_variable);

		if (udata && udata_len)
			memcpy(bt->udata, udata, udata_len);

		//加入到临时列表中
		_SM_LIST_ADD_TAIL(&bt->elem_variable, &tg->list_recv_tmp);

		return SERROR_OK;
	} while (0);

	if (bt) {
		rwbuf_free(&bt->buf);
		free(bt);
	}
	return SERROR_SYSAPI_ERR;
}

void tg_rwtrd_merge_rcvmsg(tirgger_t* tg) {
	pthread_spin_lock(&tg->lock_recv_msg);
	_SM_LIST_SPLICE_TAIL(&tg->list_recv_tmp, &tg->list_recv_msg);
	pthread_spin_unlock(&tg->lock_recv_msg);
}

int32_t tg_rwtrd_tirgger_pipe0(tirgger_t* tg) {
	return tg->tirgger_pipe[0];
}




void tg_add_rcvmsg_tail(tirgger_t* tg, _sm_list_head* newp) {
	pthread_spin_lock(&tg->lock_recv_msg);
	_SM_LIST_SPLICE_TAIL(newp, &tg->list_recv_msg);
	pthread_spin_unlock(&tg->lock_recv_msg);
}

void tg_add_sndmsg_tail(tirgger_t* tg, _sm_list_head* newp) {
	pthread_spin_lock(&tg->lock_send_msg);
	_SM_LIST_SPLICE_TAIL(newp, &tg->list_send_msg);
	pthread_spin_unlock(&tg->lock_send_msg);
}

//将tg的消息列表添加到newp的后面
void tg_rcvmsg_add_tail(tirgger_t* tg, _sm_list_head* newp) {
	pthread_spin_lock(&tg->lock_recv_msg);
	_SM_LIST_SPLICE_TAIL(&tg->list_recv_msg, newp);
	pthread_spin_unlock(&tg->lock_recv_msg);
}

void tg_sndmsg_add_tail(tirgger_t* tg, _sm_list_head* newp) {
	pthread_spin_lock(&tg->lock_send_msg);
	_SM_LIST_SPLICE_TAIL(&tg->list_send_msg, newp);
	pthread_spin_unlock(&tg->lock_send_msg);
}


void tg_destruct_behav(behav_tirgger_t* bt) {
	if (bt) {
		rwbuf_free(&bt->buf);
		free(bt);
	}
}