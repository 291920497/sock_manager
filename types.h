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
#define MAX_EPOLL_SIZE 512
#endif//MAX_EPOLL_SIZE

#ifndef MAX_USERDATA_LEN
#define MAX_USERDATA_LEN 16
#endif//MAX_USERDATA_LEN

#ifndef _WIN32
#define NUM_ET EPOLLET
#define NUM_IN EPOLLIN
#define NUM_OUT EPOLLOUT
#else
#define NUM_ET (1 << 31)
#define NUM_IN (1 << 0)
#define NUM_OUT (1 << 2)
#endif//_WIN32

#define _IN 
#define _OUT 

typedef enum {
	EV_ET = NUM_ET,
	EV_RECV = NUM_IN,
	EV_WRITE = NUM_OUT
}sm_event_t;

//sock_session 的状态机
typedef struct session_flag {
	int32_t		fin_peer : 1;				//是否连接已经关闭(客户端发起fin, 不允许读,但可以写)
//	int32_t		fin_local : 1;				//是否由本地发起fin/reset报文

	int32_t		comming : 1;				//是否有数据到来, 预防带数据的fin报文, 它也应该被处理
//	int32_t		last_shout : 1;				//如果fin由本地发起, 那么判断是否最后[一次]发送缓冲区内的数据

	int32_t		is_connect;					//是否是客户端
//	int32_t		is_truncated;				//数据是否发生了截断(分包)

	int32_t		ws : 1;						//是否为websocket协议
	int32_t		ws_handshake : 1;			//websocket是否握手完成

	int32_t		tls : 1;					//是否启动tls协议
	int32_t		tls_handshake : 1;			//是否tls协议握手完成
	//int32_t		tls_rwantw : 1;				//是否想在可读事件发生的时候调用SSL_write
	//int32_t		tls_wwantr : 1;				//是否期望在可写事件发生的时候调用SSL_read

	int32_t		reconnect : 1;				//是否在断开连接后尝试重连
}session_flag_t;

//session manager的状态机
typedef struct manager_flag {
	char running : 1;
	char merge : 1;							//是否应该合并
	char readable : 1;						//信箱是否可读
}manager_flag_t;

/*
*	关于使用openssl库完成tls协议的握手的一些说明
*	1.	具体的握手结果可能因为openssl的版本不同导致握手的最终结果
*		所以在依赖指定版本的openssl时, 建议使用s_client, s_server测试具体结果, 来决定tls连接是否需要自己添加证书信任
*	2.	一般来说如果你使用了自签证书, 作为客户端, 你应该信任自签根证书
*	3.	当你作为服务端且需要客户端提供证书完成校验时, 那么你应该使能verify_peer
*/
//tls协议需要用到的结构体
typedef struct tls_opt {
	const char* ca;							//信任的证书
	const char* capath;						//信任的证书列表
											//如果s/c采用了自签根证书签发, 那么双方都必须将根证书加入待校验的证书链
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

//typedef struct ws_info {
//	char* url;
//}ws_info_t;

typedef struct rcv_decode_mod {
	uint32_t lenght_tirgger;				//输入: 当前回调的数据长度>=当前设定值 输出: 下次回调的时机>=设置的数据长度
	uint32_t processed;						//输入: 上次回调已处理的数据索引 输出: 本次处理+上次处理的字节数 
}rcv_decode_mod_t;

typedef struct sock_session sock_session_t;
typedef struct session_manager session_manager_t;
typedef struct cds_list_head cds_list_head_t;
typedef struct rb_root rb_root_t;
typedef struct rb_node rb_node_t;

typedef void (*session_rw)(sock_session_t*);

typedef void(*sm_heap_timer_cb)(uint32_t, void*, uint8_t);



/*
*	session_encode_fn 说明
*	data, 需要封包的完整数据
*	len, 需要封包的数据长度, 如果对长度有限制, 也可以在这个函数中设置
*	out_buf, 传出的参数, 这个函数将数据写入out_buf后, 有上层交给信使处理,
*	若这个buf是有数据的, 那么将产生一个THEME_SEND事件在读写线程中被处理
*		val < 0: 指示自定义的错误, 或者使用serror.h内的错误码
*		val == 0: 成功
*/
typedef int32_t(*session_encode_fn)(const char* data, uint32_t len, rwbuf_t* out_buf);

/*
*	session_decode_pkg_cb 说明
*	ss, sock session上下文
*	data, 接收到的数据起始地址
*	len, data的长度
*	mod, 解包模块, 说明参照rcv_decode_mod_t
*	return value
*		val < 0: 指示任意错误, 将由内部移除当前session
*		val = 0: 内部将什么也不做, 但是依然可以通过输出mod内的参数修改解包回调的行为
*		val > 0: 表示解包函数得到一个完整的数据包, 数据包的长度即为返回值 (这里需要注意的是, 这个返回值是包括包头的(因为大多数情况都有包头))
*	offset, 最后说明这个输出参数, 当返回值 > 0的时候使用, 用于除去包头的长度, 表示真正的数据起始位置需要函数返回值偏移offset
*/
typedef int32_t(*session_decode_pkg_cb)(sock_session_t* ss, char* data, uint32_t len, rcv_decode_mod_t* mod, uint32_t* front_offset, uint32_t* back_offset);

#if (SM_NOT_SIGNEL_THREAD)

#else
//typedef void(*session_event_cb)(sock_session_t*, uint32_t ev, rwbuf_t* buf, void* udata, uint8_t udata_len);
typedef void(*session_event_cb)(sock_session_t*, uint32_t ev, const char* data, uint32_t len, void* udata);
#endif//SM_NOT_SIGNEL_THREAD



typedef struct session_behavior {
	//	session_event_cb		conn_cb;		//创建连接回调
	//	session_event_cb		disconn_cb;		//断开连接回调
	session_decode_pkg_cb	decode_cb;		//用户自定义解包协议
	session_encode_fn		encode_fn;		//用户自定义封包协议
	session_event_cb	complate_cb;		//解包成功回调
}session_behavior_t;

#endif//_TYPES_H_