#include "messenger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../serror.h"

#define _msger_malloc malloc
#define _msger_realloc realloc
#define _msger_free free


//雇佣一个信使
//messenger_t* msger_hire(uint32_t letterhead_len) {
messenger_t* msger_hire() {
	//uint32_t len = sizeof(messenger_t) + letterhead_len;
	uint32_t len = sizeof(messenger_t);
	messenger_t* msger = (messenger_t*)_msger_malloc(len);
	if (!msger)
		return 0;

	memset(msger, 0, len);

	//init 
	CDS_INIT_LIST_HEAD(&msger->list_paragraphs);
	CDS_INIT_LIST_HEAD(&msger->elem_fifo);
	rb_init_node(&msger->rbnode_house_number);

	return msger;
}

//解雇一个信使
void msger_fire(messenger_t* msger) {
	letter_t* pos, * n;

	//先从队列中移除
	cds_list_del_init(&msger->elem_fifo);

	cds_list_for_each_entry_safe(pos, n, &msger->list_paragraphs, elem_paragraph) {
		cds_list_del_init(&pos->elem_paragraph);
		rwbuf_free(&pos->sentence);
		_msger_free(pos);
	}
	_msger_free(msger);
}

int32_t msger_add_aparagraph_with_rwbuf(messenger_t* msger, rwbuf_t* sentence, theme_t theme, session_event_cb behav) {
	letter_t* lter = _msger_malloc(sizeof(letter_t));
	if (!lter)
		return SERROR_SYSAPI_ERR;

	memset(lter, 0, sizeof(letter_t));
//	CDS_INIT_LIST_HEAD(&lter->elem_paragraph);
	
	//应对什么消息也不发送
	if (sentence) {
		msger->character_len += RWBUF_GET_LEN(sentence);
		rwbuf_swap(sentence, &lter->sentence);
	}

	lter->behav = behav;
	lter->theme = theme;

	//如果出现断开连接, 那么当前所有包都携带连接已断开的标识
	if (theme & THEME_DESTORY) {
		letter_information_t* linfo = msger->information;
		linfo->closed = ~0;
	}

	//将这段话写入这封信
	cds_list_add_tail(&lter->elem_paragraph, &msger->list_paragraphs);
	return SERROR_OK;
}

int32_t msger_add_aparagraph_with_ram(messenger_t* msger, const char* start, uint32_t len, theme_t theme, session_event_cb behav) {
	int rt;
	rwbuf_t rwb;
	memset(&rwb, 0, sizeof(rwb));

	if (len && start) {
		if ((rt = rwbuf_mlc(&rwb, len)) != SERROR_OK)
			return rt;

		//这就不需要判断了
		rwbuf_append(&rwb, start, len);
	}

	//如果出现断开连接, 那么当前所有包都携带连接已断开的标识
	if (theme & THEME_DESTORY) {
		letter_information_t* linfo = msger->information;
		linfo->closed = ~0;
	}

	return msger_add_aparagraph_with_rwbuf(msger, &rwb, theme, behav);
}

void msger_del_aparagraph(letter_t* lter) {
	cds_list_del_init(&lter->elem_paragraph);
	_msger_free(lter);
}

//查找与插入函数
messenger_t* msger_search(rb_root_t* root, uint32_t hash) {
	rb_node_t* node = root->rb_node;

	while (node) {
		messenger_t* this_node = caa_container_of(node, messenger_t, rbnode_house_number);
		letter_information_t* this_info = this_node->information;

		if (hash < this_info->hash)
			node = node->rb_left;
		else if (hash < this_info->hash)
			node = node->rb_right;
		else
			return this_node;
	}
	return NULL;
}

int32_t msger_insert(rb_root_t* root, messenger_t* msger) {
	struct rb_node** new_node = &(root->rb_node), * parent = NULL;
	letter_information_t* linfo, * rinfo;

	linfo = (letter_information_t*)(msger->information);

	/* Figure out where to put new_node node */
	while (*new_node) {
		messenger_t* this_node = caa_container_of(*new_node, messenger_t, rbnode_house_number);
		rinfo = this_node->information;
		//int result = strcmp(data->string, this_node->string);


		parent = *new_node;
		if (linfo ->hash < rinfo->hash)
			new_node = &((*new_node)->rb_left);
		else if (linfo->hash < rinfo->hash)
			new_node = &((*new_node)->rb_right);
		else
			return 0;
	}

	/* Add new_node node and rebalance tree. */
	rb_link_node(&msger->rbnode_house_number, parent, new_node);
	rb_insert_color(&msger->rbnode_house_number, root);

	return 1;
}