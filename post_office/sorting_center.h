#ifndef _SORTING_CENTER_H_
#define _SORTING_CENTER_H_

//分拣中心, 对数据分类

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif//_GNU_SOURCE


#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif//_GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>


#include "../tools/stl/compiler.h"
#include "../tools/stl/list.h"
#include "../tools/heap_timer/heap_timer.h"


#include <pthread.h>

typedef struct cds_list_head cds_list_head_t;

typedef enum {
	SORT_NEED_SORTING_INBOX,	//需要整理收件箱
	SORT_CLEN_SORTING_INBOX,	//清理需要整理的状态
};

typedef struct sorting_center {
	cds_list_head_t list_pending_inbox;		//等待整理的收件箱
	cds_list_head_t list_complate_inbox;	//整理完整的收件箱

	cds_list_head_t list_complate_outbox;	//整理完成的发件箱

	pthread_spinlock_t lock_inbox;		//整理完成收件箱的锁
	pthread_spinlock_t lock_outbox;		//整理完成发件箱

	heap_timer_t* ht;
	int32_t bells[2];				//有事按下铃铛
	uint8_t opening;				//是否在营业中

}sorting_center_t;



#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

sorting_center_t* sc_start_business();

void sc_outof_business(sorting_center_t* sc);

void sc_queuing2pending_inbox(sorting_center_t* sc, cds_list_head_t* msger_fifo);

void sc_merge_pending2complate_inbox(sorting_center_t* sc);

void sc_merge_box2complate_inbox(sorting_center_t* sc, cds_list_head_t* box);

//揽件
void sc_solicitation_inthe_inbox(sorting_center_t* sc, cds_list_head_t* box);

//发件
void sc_submit_to_outbox(sorting_center_t* sc, cds_list_head_t* box);


//如何处理从收件箱拿出来的数据
void sc_how2do_example(sorting_center_t* sc, cds_list_head_t* box);

static uint8_t sc_is_open(sorting_center_t* sc) {
	return sc->opening;
}

void* sc_thread_assembly_line(void* sc);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SORTING_CENTER_H_