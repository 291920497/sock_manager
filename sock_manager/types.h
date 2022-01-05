#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include "tools/stl/list.h"
#else
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2spi.h>
#include <WS2tcpip.h>
#include <Windows.h>
#endif//_WIN32

//#include "../stl_filter.h"
#include "tools/rwbuf/rwbuf.h"
#include "tools/heap_timer/heap_timer.h"

#if (ENABLE_SSL)
#define SSL_SESSION_ID "sock_manager"
#endif//ENABLE_SSL

#ifndef MAX_EPOLL_SIZE
#define MAX_EPOLL_SIZE 2048
#endif//MAX_EPOLL_SIZE

#ifndef MAX_USERDATA_LEN
#define MAX_USERDATA_LEN 16
#endif//MAX_USERDATA_LEN

#ifndef _WIN32
#define NUM_IN EPOLLIN
#define NUM_OUT EPOLLOUT
#define NUM_ET EPOLLET
#else
#define NUM_IN	(1 << 0)
#define NUM_OUT (1 << 2)
#define NUM_ET	(1 << 31)
#endif//_WIN32

#define _IN 
#define _OUT 
#define _INOUT

#define _sm_malloc malloc
#define _sm_realloc realloc
#define _sm_free	free

typedef enum {
	EV_ET		= NUM_ET,
	EV_RECV		= NUM_IN,
	EV_WRITE	= NUM_OUT
}sm_event_e;

//sock_session flag
typedef struct session_flag {
	int32_t		fin_peer : 1;				//是否连接已经关闭(客户端发起fin, 不允许读,但可以写)

	int32_t		comming : 1;				//是否有数据到来, 预防带数据的fin报文, 它也应该被处理
	int32_t		lastwork : 1;				//期望在缓冲区中的数据发送完成后断开连接

	int32_t		is_connect;					//是否是客户端

	int32_t		ws : 1;						//是否为websocket协议
	int32_t		ws_handshake : 1;			//websocket是否握手完成

	int32_t		tls : 1;					//是否启动tls协议
	int32_t		tls_handshake : 1;			//是否tls协议握手完成
	//int32_t		tls_rwantw : 1;				//是否想在可读事件发生的时候调用SSL_write
	//int32_t		tls_wwantr : 1;				//是否期望在可写事件发生的时候调用SSL_read

	int32_t		reconnect : 1;				//是否在断开连接后尝试重连
}session_flag_t;

//session_manager flag
typedef struct manager_flag {
	char running : 1;
	char dispatch : 1;
}manager_flag_t;

//以下统称sm_run函数的调用线程为主线程

/*
*	单线程模式:
*	SM_PACKET_TYPE_NONE: 用于初始化, 以及在解包回调中结合返回值控制主线程行为
*	SM_PACKET_TYPE_CREATE: 通知对应的会话被创建
*	SM_PACKET_TYPE_DESTORY: 通知对应的会话被已经断开连接
*	SM_PACKET_TYPE_DATA: 通知一个完整数据包到达
*	SM_PACKET_TYPE_PING: 通知这是一个ping包
*	SM_PACKET_TYPE_PONG: 通知这是一个pong包
* 
*	支持多线程模式:
*	主线程->子线程: 参照单线程模式
* 
*	子线程->主线程, 只特别处理以下事件:
*	SM_PACKET_TYPE_DESTORY: 使该会话直接断开连接, 注意: 这将舍弃主线程所有尚未发送的数据
*	SM_PACKET_TYPE_DATA/PING/PONG: 通知需要发送一个完整的数据包
*	SM_PACKET_TYPE_LASTWORK: 使该会话将接受到的数据发送完成后断开连接
* 
*	用户可以在解包函数中自定义数据包类型, 由decode_cb带出, 回调给complete_cb
*/

typedef enum{
	SM_PACKET_TYPE_NONE,
	SM_PACKET_TYPE_CREATE,
	SM_PACKET_TYPE_DESTORY,
	SM_PACKET_TYPE_DATA,
	SM_PACKET_TYPE_PING,
	SM_PACKET_TYPE_PONG,
	SM_PACKET_TYPE_LASTWORK,
}sm_enum_packet_type;

/*
*	关于使用openssl库完成tls协议的握手的一些说明
*	1.	具体的握手结果可能因为openssl的运行环境不同导致握手的最终结果 (如: windows/linux, 版本差异)
*		所以在依赖指定版本的openssl时, 建议使用s_client, s_server测试具体结果, 来决定tls连接是否需要自己添加证书信任
*	2.	一般来说如果你使用了自签证书, 作为客户端, 你应该信任自签根证书
*	3.	当你作为服务端且需要客户端提供证书完成校验时, 那么你应该使能verify_peer
*/
//tls协议需要用到的结构体
typedef struct tls_opt {
	const char* ca;							//信任的证书
	const char* capath;						//信任的证书列表
											//如果s/c采用了自签根证书签发, 那么至少客户端必须添加该根证书到信任列表
	const char* cert;						//证书路径
	const char* key;						//证书密钥路径
	const char* password;					//密码
	uint8_t		verify_peer;				//服务端: 将向客户端发起证书请求, 若未提供则握手失败
											//客户端: 验证从服务端接收的证书
}tls_opt_t;

typedef struct tls_info {
	void* ctx;
	void* ssl;
}tls_info_t;

typedef struct decode_mod {
	uint32_t lenght_tirgger;				//输入: 当前回调的数据长度>=当前设定值 输出: 下次回调的时机>=设置的数据长度
	uint32_t processed;						//输入: 上次回调已处理的数据索引 输出: 本次处理+上次处理的字节数 
}decode_mod_t;

typedef struct sock_session sock_session_t;
typedef struct session_manager session_manager_t;
typedef struct cds_list_head cds_list_head_t;
typedef struct rb_root rb_root_t;
typedef struct rb_node rb_node_t;
typedef struct session_behavior session_behavior_t;

typedef void (*session_rw)(sock_session_t*);
typedef void(*sm_heap_timer_cb)(uint32_t, void*, uint8_t);

/*
*	session_encode_fn 说明
*	data: 待编码的数据包
*	len: 数据包长度
*	buf: buf必须被rwbuf_init初始化, 在立即回调模式中, buf可以为sock_session::wbuf, 达到0拷贝的效果
*	return val:
*		< 0: 自定义的错误码, 或者参照serror.h
*		== 0: 成功
*/
typedef int32_t(*session_encode_fn)(const char* data, uint32_t len, _INOUT rwbuf_t* buf);

/*
*	session_decode_pkg_cb 说明: 该回调函数, 只会在主线程中被调用, 单线程同步
*	ss: 由sm_connect/sm_add_listen接收创建的sock_session上下文
*	data: 当次回调数据包的起始位置
*	len: 当次回调自data起始, 包含的数据长度
*	mod: 解包模块可能被用到的模块
*		lenght_tirgger: 设置当缓冲区长度达到该值时, 即为decode_pkg_cb调用的时机
*		processed: 已处理的长度, 用户可以记录自己处理了多少长度, 在绝大多数情况下可以减少重复解码
* 
*	return val: 
*		val < 0: 指示任意错误, 将由内部移除当前session
*		val == 0:
*			if(data_type == SM_PACKET_TYPE_NONE): 那么认为解包函数没有收到一个完整的包, 忽略, 等待下一次回调
*			if(data_type != SM_PACKET_TYPE_NONE): 那么认为解包函数收到了一个完整包, 只是这个包的长度为0
*		val > 0: 表示解包函数收到一个完整的数据包, 需要管理器处理且移除的长度
* 
*	front_offset: 只在return val > 0时生效, 指出回调到complete_cb函数的起始偏移量(一般用于去除数据包的协议头)
*	back_offset: 只在return val > 0时生效, 指出自数据末尾开始, 放弃的长度
*	data_type: 只是本次函数回调的数据包类型, 可以使用sm_enum_packet_type或者用户自定义
*/

typedef int32_t(*session_decode_pkg_cb)(sock_session_t* ss, char* data, uint32_t len, decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset, uint32_t* data_type);

//#if (SM_DISPATCH_MODEL)
#if 1
//当时使能了数据包分发模式, 那么你应该引用external_fn.h. 且使用里面的方法与主线程交互
//sock_manager.h中的方法只保证在sm_run调用线程回馈正确的结果

typedef struct external_buf_vehicle external_buf_vehicle_t;

/*
*	session_dispatch_data_cb 说明, 这是一个数据分发模式下的回调函数
*	sm: 指示由那个session管理器触发的回调
*	list_vehicle: 数据包的载具, entry 为 external_buf_vehicle_t, 参考例子
*/
typedef void (*session_dispatch_data_cb)(session_manager_t* sm, cds_list_head_t* list_vehicle);

/*
*	session_event_cb 说明
*	ss: 由sm_connect/sm_add_listen接收创建的sock_session上下文
*	hash: session唯一对应的hash值
*	pkg_type: 当前回调的数据包类型
*	total: 当前载具的总长度, 预防应用层数据堆积需要告知用户 (未升级为数据分发模式此参数无意义, 默认为NULL)
*	data: 数据包起始地址
*	len: 数据包长度
*	udata: 在主线程session创建时设置的私有数据的快照
*	behav: 在主线程初始化的行为回调 (未升级为数据分发模式此参数无意义, 默认为NULL)
*	ebv: 接收数据的载具, 通过 external_fn.h::ef_insert_msg2vehicle 投递,  (未升级为数据分发模式此参数无意义, 默认为NULL)
*/
typedef void (*session_event_cb)(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, uint32_t total, const char* data, uint32_t len, void* udata, session_behavior_t* behav, external_buf_vehicle_t* ebv);
#else
typedef void (*session_event_cb)(sock_session_t* ss, uint32_t hash, uint32_t pkg_type, const char* data, uint32_t len, void* udata);
#endif//SM_DISPATCH_MODEL

/*
*	session_behavior_t, 指示指定session的行为
*	decode_cb: 解包函数, 且只在sm_run调用线程回调, 即可以在decode_cb中使用sock_manager.h内所有的方法
*	encode_fn: 
*		立即回调模式: 使用sm_0copy_send_fn在主线程完成0拷贝发送数据
*		数据包分发模式: 参照example_dsp_cb, 在其他线程中调用
*/
typedef struct session_behavior {
	session_decode_pkg_cb	decode_cb;		//用户自定义解包协议
	session_encode_fn		encode_fn;		//用户自定义封包协议
	session_event_cb		complete_cb;	//解包成功回调
}session_behavior_t;

/*
*	rcvlen: 接收缓冲区长度
*	sndlen: 
*		立即回调模式: 发送缓冲区的默认长度
*		数据调度模式: 发送缓冲区的固定长度
*	overflow:
*		立即回调模式: 发送缓冲区可扩容的最大长度
*		数据调度模式: 待发送数据包最大滞留长度( 缓冲区内未发送数据长度 + 待发送的数据长度 = 数据包滞留长度 )
*	behav:	各事件类型对应行为
*	udata:	用户数据
*/

typedef struct session_opt {
	uint32_t rcvlen;	
	uint32_t sndlen;						
	uint32_t overflow;
	session_behavior_t behav;
	void* udata;
}session_opt_t;


/*
* 一下提供数据分发模式的示例代码
* 说明: dispatch_cb的调用线程只会在sm_run的调用线程, 即: 如果你打算直接使用以下代码, 在dispatch_cb回调用调用complete_cb, 那么你应该使用立即回调的模式
*		测试代码写完发现, 似乎使用dispatch model需要使用者投入额外的学习成本, 当然如果你需要一个业务层与网络I/O隔离, 且业务层完全隔离网络I/O的话, 那么, 这个模式是更好的选择
* 
void dispatch_cb(session_manager_t* sm, cds_list_head_t* list_vehicle) {
	uint32_t len;
	char* ptr;
	external_buf_vehicle_t* pos, * p;
	external_buf_t* pos1, * p1;

	//提供一个临时的list, 有可能在complete_cb中, 并没有数据需要发送, 减少一次malloc/free
	cds_list_head_t _list;
	CDS_INIT_LIST_HEAD(&_list);

	cds_list_for_each_entry_safe(pos, p, list_vehicle, elem_sndbuf) {
		//提供一个临时的载具, 因为不确定是否有数据需要发送
		external_buf_vehicle_t ebv;
		memset(&ebv, 0, sizeof(ebv));
		CDS_INIT_LIST_HEAD(&ebv.list_datas);
		CDS_INIT_LIST_HEAD(&ebv.elem_sndbuf);

		cds_list_for_each_entry_safe(pos1, p1, &pos->list_datas, elem_datas) {
			ptr = (char*)rwbuf_start_ptr(&pos1->data);
			len = rwbuf_len(&pos1->data);

			if (pos->behav.complete_cb)
				pos->behav.complete_cb(pos->address, pos->hash, pos1->type, pos->total, ptr, len, pos->userdata, &pos->behav, &ebv);

			//处理完一个消息即销毁, 当然你也可以不销毁该消息, 复用或者丢向其他线程/进程, 但记住断开list的连接
			ef_remove_msgfvehicle(pos, pos1);
		}

		//若有数据需要发送, 添加到临时链表
		if (!cds_list_empty(&ebv.list_datas)) {
			external_buf_vehicle_t* pebv = ef_create_vehicle(pos->address, pos->hash, &pos->behav, pos->userdata);
			pebv->total = ebv.total;
			cds_list_splice_tail(&ebv.list_datas, &pebv->list_datas);
			cds_list_add_tail(&pebv->elem_sndbuf, &_list);

			//CDS_INIT_LIST_HEAD(&ebv.list_datas);
		}

		//断开载具与链表的联系后摧毁
		cds_list_del(&pos->elem_sndbuf);
		ef_destory_vehicle(pos);
	}

	//将需要发送的数据包提交到sock_manager, 并唤起sm_run调用线程,
	ef_deliver_pkgs(sm, &_list);
	//提供直接转移这个指针的可能性, 你可以决定在何处释放这个指针, 但在这之前防止内存泄漏,你应该使用ef_destory_vehicle销毁list中的每一个元素.
	_sm_free(list_vehicle);
}
*/

#endif//_TYPES_H_