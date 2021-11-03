#ifndef _MESSENGER_H_
#define _MESSENGER_H_

//充当信使的角色, 完成信息的归类, 保证时序, 以及新到达的信件与当前已有信件合并

#include "../../tools/stl/list.h"
#include "../../tools/stl/rbtree.h"
#include "../../tools/rwbuf/rwbuf.h"

#include "../../sock_manager.h"

#define _msger_malloc malloc
#define _msger_realloc realloc
#define _msger_free free

typedef struct cds_list_head cds_list_head_t;
typedef struct rb_root rb_root_t;
typedef struct rb_node rb_node_t;
typedef enum etheme theme_t;

typedef struct letter_information {
//	uint32_t hash;
	uint8_t udata[MAX_USERDATA_LEN];
	uint8_t udata_len;
	uint8_t closed;	//session是否已经关闭
	uint8_t revise_udata;	//是否修改udata
//	void* address;	//session地址 组合寻址
//	session_encode_fn encode_fn;	//封包函数

	sortingcenter_ctx_t scc;
}letter_information_t;

//一封信, 包含多个段落+一句话
typedef struct letter {
	uint32_t theme;						//主题
	session_event_cb behav;				//行为
	rwbuf_t sentence;					//一句话
	cds_list_head_t elem_paragraph;		//分段
}letter_t;

//信使
typedef struct messenger {
	rb_node_t rbnode_house_number;		//门牌号
	cds_list_head_t list_paragraphs;	//多封信, 分为多个段落
	cds_list_head_t elem_fifo;		//顺序列表, 先入先出
	uint32_t character_len;				//字符数量
//	char information[0];				//变长数组, 添加自己的信息
	letter_information_t information[1];//迎合之前的变长数组, 使用这个hire入参将无效
}messenger_t;


#ifdef __cplusplus
extern "C" {
#endif//__cplusplus
;

//雇佣一个信使, 并告知抬头长度, 用户可以修改information地址下的letterhead_len长度的内存
//messenger_t* msger_hire(uint32_t letterhead_len);
messenger_t* msger_hire();

//解雇一个信使
void msger_fire(messenger_t* msger);

//添加一段话, 需要注意sentence, 将被信使代理回收,且外部将不能再次使用
int32_t msger_add_aparagraph_with_rwbuf(messenger_t* msger, rwbuf_t* sentence, theme_t theme, session_event_cb behav);

int32_t msger_add_aparagraph_with_ram(messenger_t* msger, const char* start, uint32_t len, theme_t theme, session_event_cb behav);

void msger_del_aparagraph(letter_t* lter);

//查找与插入函数
messenger_t* msger_search(rb_root_t* root, uint32_t hash);

int32_t msger_insert(rb_root_t* root, messenger_t* msger);



#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_MESSENGER_H_