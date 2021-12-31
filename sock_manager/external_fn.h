#ifndef _EXTERNAL_FN_H_
#define _EXTERNAL_FN_H_

#ifndef _WIN32
#include "tools/stl/list.h"
#else
#include "tools/stl/wlist.h"
#endif//_WIN32

#include "types.h"
#include "types.hpp"
#include "serror.h"
#include "tools/stl/rbtree.h"
#include "tools/rwbuf/rwbuf.h"
#include "tools/common/spin_lock.h"

typedef struct external_buf {
	rwbuf_t			data;			//完整数据包
	uint32_t		type;			//数据报类型
	cds_list_head_t elem_datas;		
}external_buf_t;

/*
*	这个结构体是双向的
*	1. sm_run调用线程导出接收到的数据包
*	2. 其他线程向sm_run调用线程投递待发送的数据包
*	
*	由于以上2种情况, 以下除list_datas携带数据外其他其他均为快照, 
*/

//非sm_run调用线程发送数据报载具
typedef struct external_buf_vehicle {
	sock_session_t* address;		//completet_cb回调时保存的快照
	void* userdata;		//用户私有指针快照, 用户需要注意这个指针的生命周期, 除sm_run调用线程外, 不保证线程安全 
	uint32_t		hash;			//completet_cb回调时保存的快照
	uint32_t		total;			//数据总长度
	//session_event_cb event_cb;		//事件回调
	session_behavior_t behav;		//行为
	rb_node_t		rb_tidy;		//用红黑树来排序
	cds_list_head_t	list_datas;		//待发送的数据, external_buf_t的entry
	cds_list_head_t elem_sndbuf;	//主线程list_sndbuf的子节点
}external_buf_vehicle_t;

//创建一个数据包载具
static external_buf_vehicle_t* ef_create_vehicle(sock_session_t* address, uint32_t hash, session_behavior_t* behav, void* userdata) {
	if (!address) return 0;

	external_buf_vehicle_t* ebv = (external_buf_vehicle_t*)_sm_malloc(sizeof(external_buf_vehicle_t));
	if (ebv) {
		memset(ebv, 0, sizeof(external_buf_vehicle_t));

		ebv->address = address;
		ebv->hash = hash;
		ebv->userdata = userdata;
		ebv->total = 0;
		memcpy(&ebv->behav, behav, sizeof(session_behavior_t));
		//ebv->event_cb = event_cb;
		rb_init_node(&ebv->rb_tidy);
		CDS_INIT_LIST_HEAD(&ebv->list_datas);
		CDS_INIT_LIST_HEAD(&ebv->elem_sndbuf);
		return ebv;
	}
	return 0;
}

//销毁载具
static void ef_destory_vehicle(external_buf_vehicle_t* ebv) {
	if (ebv) {
		//断开与载具链表的连接
		cds_list_del(&ebv->elem_sndbuf);

		external_buf_t* pos, * n;
		cds_list_for_each_entry_safe(pos, n, &ebv->list_datas, elem_datas) {
			//断开与数据链表的连接
			cds_list_del(&pos->elem_datas);
			rwbuf_free(&pos->data);
			_sm_free(pos);
		}
		_sm_free(ebv);
	}
}

//buf必须由rwbuf_init初始化,rwbuf_relc/rwbuf_mlc 创建, 插入载具后将被托管
static int32_t ef_insert_msg2vehicle(external_buf_vehicle_t* ebv, rwbuf_t* buf, uint32_t type) {
	if (!ebv || !buf) {
		return SERROR_INPARAM_ERR;
	}

	external_buf_t* eb = (external_buf_t*)_sm_malloc(sizeof(external_buf_t));
	if (eb) {
		rwbuf_init(&eb->data);
		rwbuf_swap(&eb->data, buf);
		eb->type = type;
		cds_list_add_tail(&eb->elem_datas, &ebv->list_datas);

		//更新长度
		ebv->total += rwbuf_len(&eb->data);
		return SERROR_OK;
	}
	return SERROR_SYSAPI_ERR;
}

static void ef_remove_msgfvehicle(external_buf_vehicle_t* ebv, external_buf_t* eb) {
	if (ebv) {
		if (eb) {
			ebv->total -= rwbuf_len(&eb->data);

			cds_list_del(&eb->elem_datas);
			rwbuf_free(&eb->data);
			_sm_free(eb);
		}
	}
}


#if (SM_MULTI_THREAD)
//投递一组包含数据包的载具
static void ef_deliver_pkgs(session_manager_t* sm ,cds_list_head_t* vehicle) {
	if (!sm || !vehicle)
		return;

	char ch = 'r';
	int fd = sm->fdpipe[1];

	if (!cds_list_empty(vehicle)) {
		osspin_lk_lock(&sm->lk_sndbuf);
		cds_list_splice_tail(vehicle, &sm->list_sndbuf);
		osspin_lk_unlock(&sm->lk_sndbuf);
		CDS_INIT_LIST_HEAD(vehicle);

		//使epoll_wait/select 解除阻塞
		send(fd, &ch, 1, 0);
	}
}

#endif//SM_MULTI_THREAD

//rbtree
/**********************************************************/
//数据整理 rbtree function

//在其他模块需要引用
external_buf_vehicle_t* ef_tidy_search(rb_root_t* root, uint32_t hash){
	struct rb_node* n = root->rb_node;
	external_buf_vehicle_t* page;
	uint32_t rhash = 0;

	while (n)
	{
		page = rb_entry(n, external_buf_vehicle_t, rb_tidy);
		rhash = page->hash;

		if (hash < rhash)
			n = n->rb_left;
		else if (hash > rhash)
			n = n->rb_right;
		else
			return page;
	}
	return NULL;
}


static inline int32_t ef_tidy_insert(rb_root_t* root, external_buf_vehicle_t* ebv) {
	struct rb_node** new_node = &(root->rb_node), * parent = NULL;
	uint32_t rhash;
	uint32_t hash = ebv->hash;
	external_buf_vehicle_t* page;


	/* Figure out where to put new_node node */
	while (*new_node) {
		page = rb_entry(*new_node, external_buf_vehicle_t, rb_tidy);
		rhash = page->hash;

		parent = *new_node;
		if (hash < rhash)
			new_node = &((*new_node)->rb_left);
		else if (hash > rhash)
			new_node = &((*new_node)->rb_right);
		else
			return 0;
	}

	/* Add new_node node and rebalance tree. */
	rb_link_node(&ebv->rb_tidy, parent, new_node);
	rb_insert_color(&ebv->rb_tidy, root);

	return 1;
}

/**********************************************************/

#endif//_EXTERNAL_FN_H_