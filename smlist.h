#ifndef _SMLIST_H_
#define _SMLIST_H_

//urcu
#if (ENABLE_URCU)
#include <urcu.h>
#include <urcu/rculist.h>
typedef struct cds_list_head _sm_list_head;
#define _SM_LIST_INIT_HEAD CDS_INIT_LIST_HEAD
#define _SM_LIST_ADD_TAIL cds_list_add_tail
#define _SM_LIST_DEL cds_list_del
#define _SM_LIST_DEL_INIT cds_list_del_init
#define _SM_LIST_EMPTY cds_list_empty
#define _SM_LIST_SPLICE_TAIL cds_list_splice_tail
#define _SM_LIST_ENTRY cds_list_entry
#define _SM_LIST_FOR_EACH_ENTRY cds_list_for_each_entry
#define _SM_LIST_FOR_EACH_ENTRY_SAFE cds_list_for_each_entry_safe
#else
//原本是打算用urcu的list_rcu, 后来发现结合原来的设计会让情况变得复杂
//但是从linux内核抠出来的list要加-std=gnu99挺麻烦的, 就拷贝了urcu的list.h
#include "tools/stl/list.h"
//typedef struct list_head _sm_list_head;
//#define _SM_LIST_INIT_HEAD INIT_LIST_HEAD
//#define _SM_LIST_ADD_TAIL list_add_tail
//#define _SM_LIST_DEL list_del
//#define _SM_LIST_DEL_INIT list_del_init
//#define _SM_LIST_EMPTY list_empty
//#define _SM_LIST_ENTRY list_entry
//#define _SM_LIST_FOR_EACH_ENTRY list_for_each_entry
//#define _SM_LIST_FOR_EACH_ENTRY_SAFE list_for_each_entry_safe

typedef struct cds_list_head _sm_list_head;
#define _SM_LIST_INIT_HEAD CDS_INIT_LIST_HEAD
#define _SM_LIST_ADD_TAIL cds_list_add_tail
#define _SM_LIST_DEL cds_list_del
#define _SM_LIST_DEL_INIT cds_list_del_init
#define _SM_LIST_EMPTY cds_list_empty
#define _SM_LIST_SPLICE_TAIL cds_list_splice_tail
#define _SM_LIST_ENTRY cds_list_entry
#define _SM_LIST_FOR_EACH_ENTRY cds_list_for_each_entry
#define _SM_LIST_FOR_EACH_ENTRY_SAFE cds_list_for_each_entry_safe
#endif//ENABLE_URCU

#endif//_SMLIST_H_