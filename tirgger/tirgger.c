#include "tirgger.h"
//#include "../tools/stl/list.h"


#include "../tools/stl/rbtree.h"

#include "../serror.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include <pthread.h>




typedef struct rb_root rb_root_t;
typedef struct rb_node rb_node_t;



typedef struct tev_flag {
	int32_t closed : 1;				//是否已经关闭
	int32_t ready : 1;				//是否准备就绪, 例如握手/鉴权完成
}tev_flag_t;

//单个消息触发
typedef struct tirgger_session_single_ctx {
	uint32_t	ev;					//当前上下文的事件状态
	rwbuf_t		buf;				//消息缓冲区, 需要注意第一次初始化.

	uint32_t hash;					//绑定的session的hash
	void* session_addr;				//session的存储地址


	_sm_list_head elem_msg_block;	//消息分块列表
}tirgger_session_single_ctx_t;

//单个上下文
typedef struct tirgger_session_ctx {
	tev_flag_t flag;				//状态标志

	uint32_t hash;					//绑定的session的hash
	void* session_addr;				//session的存储地址

	uint32_t sum;					//所有消息块长度的和
	uint32_t value_trigger;			//当消息块的长度之和>=这个值时, 触发回调
	uint32_t offset;				//偏移量, 为数据结尾未知准备的
	uint64_t last_active;			//最后一次活跃的时间 unix时间戳

	session_behavior_t uevent;		//用户行为

	_sm_list_head list_msg_block;	//当前session的所有消息块列表
	struct rb_node rbnode_session;	//红黑树节点
}tirgger_session_ctx_t;





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

behav_tirgger_t* tg_construct_behav_tirgger(uint8_t ev, uint32_t hash, void* session_addr, const char* data, uint32_t data_len, session_event_cb ev_cb, void* udata, uint8_t udata_len, int32_t* out_err) {
	int32_t rt;
	behav_tirgger_t* bt;

	if (udata_len > MAX_USERDATA_LEN) {
		if(out_err)
			*out_err = SERROR_INPARAM_ERR;
		return 0;
	}
	

	bt = (behav_tirgger_t*)malloc(sizeof(behav_tirgger_t));
	if (!bt) {
		if (out_err)
			*out_err = SERROR_SYSAPI_ERR;
		return 0;
	}

	memset(bt, 0, sizeof(behav_tirgger_t));
	
	//准备数据
	if (data_len) {
		rt = rwbuf_relc(&bt->buf, data_len);
		if (rt != SERROR_OK) {
			if (out_err)
				*out_err = rt;
			return 0;
		}

		rwbuf_append(&bt->buf, data, data_len);
	}

	bt->ev = ev;
	bt->hash = hash;
	bt->session_addr = session_addr;
	bt->event_cb = ev_cb;
	_SM_LIST_INIT_HEAD(&bt->elem_variable);

	if (udata && udata_len)
		memcpy(bt->udata, udata, udata_len);

	if (out_err)
		*out_err = SERROR_OK;
	return bt;
}

void tg_destruct_behav_tirgger(behav_tirgger_t* bt) {
	if (bt) {
		rwbuf_free(&bt->buf);
		free(bt);
	}
}