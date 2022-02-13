# sock_manager
 socket session manager
 
# 描述
	这是由C语言编写的,提供一个高性能的、可拓展的网络库,它原生开发在Linux,采用epoll驱动I/O,但在Windows下采用select模型.支持定时器,信号处理. 并且在普通模式下运行是完全0拷贝的.
# 协议
	内置了websocket、TCP Binary、TLS(当然TLS是可以与websocket或TCP Binary相结合的实现wss,或普通的基于TLS加密通信), 当然如果你引入了http协议解析以及使能TLS模块,便能支持https.
# 压测
	压测环境为Centos7 4G 1CPU 2core虚拟机环境下, 同一台物理机下采用20K客户端连接服务器, 发送4K字节数据,服务器收到并回显,并在LAN下另外的物理机使用2K个套接字连接该服务,测试在该环境下的效率,数据的发送到回显时间不足2ms
	使用valgrind测试无内存泄漏,之后提交将带上perl+valgrind测试报告

# 类型说明
	@session_opt_t
		@rcvlen: 接收缓冲区的长度, 这是固定的, 将不会进行扩容
		@sndlen: 
			@即时回调模式: 发送缓冲区的默认长度(可增长的)
			@数据分发模式: 发送缓冲区的固定长度
		@overflow:
			@即时回调模式: 发送缓冲区可增长的最大长度, 发送缓冲区滞留长度达到该值将断开连接
			@数据分发模式: 发送缓冲区最大滞留长度, 超过断开连接. (缓冲区已有数据 + 待发送的数据长度 = 滞留长度)
		@behav: 
			@decode_cb: 通信协议解包函数, 该函数只会在sm_run的调用线程回调(请保证函数的可重入)
			@encode_fn: 通信协议封包函数, 这作为一个方法以供调用
			@complete_cb: 数据解包成功回调函数
		@udata: 用户私有数据
			


# 接口说明

# sock_manager.h

# sm_init_manager
# session_manager_t* sm_init_manager(uint32_t session_cache_size);
	@session_cache_size: 初始缓存的session数量, 这些session不会被提前释放, 直到sm_exit_manager被调用
	
# sm_exit_manager
# void sm_exit_manager(session_manager_t* sm);
	@sm: 由sm_init_manager方法创建的实例
	
# sm_set_running
# void sm_set_running(session_manager_t* sm, uint8_t run);
	@run: 设置管理器@sm的运行状态 0/~0

# sm_add_listen
# sock_session_t* sm_add_listen(session_manager_t* sm, uint16_t port, uint32_t max_listen, session_opt_t* opt);
	@sm: 在sm管理器下添加一个监听套接字
	@port: 监听的端口
	@max_listen: listen调用的参数, 连接未决队列长度
	@opt: 参照类型说明::session_opt_t
	
# sm_add_accepted
# sock_session_t* sm_add_accepted(session_manager_t* sm, int32_t fd, const char* ip, uint16_t port, session_opt_t* opt);
	@sm: 在sm管理器下通过监听套接字接收的客户端套接字, 一般在sm_run2内部驱动调用, 且产生 SM_PACKET_TYPE_CREATE 事件
	@fd: 客户端套接字 (当然, 作为管道套接字也可以主动调用此方法加入管理器)
	@ip: 客户端ip(或自己设置文本)
	@port: 客户端端口
	@opt: 参照类型说明::session_opt_t

# sm_add_connect
# sock_session_t* sm_add_connect(session_manager_t* sm, const char* domain, uint16_t port, uint8_t is_reconnect, session_opt_t* opt);
	@sm: 由sm管理器托管创建一个套接字连接到domain:port, , 且产生 SM_PACKET_TYPE_CREATE 事件
	@is_reconnect: 是否加入重连列表, 断开连接自动重连
	@opt: 参照类型说明::session_opt_t
	
# sm_del_session
# void sm_del_session(sock_session_t* ss);
	@ss: 移除一个session, 这个session将被回收到管理器, 且产生 SM_PACKET_TYPE_CREATE 事件
	
# sm_add_timer
# uint32_t sm_add_timer(session_manager_t* sm, uint32_t interval, int32_t delay_ms, int32_t repeat, heap_timer_cb on_timeout, void* udata, uint8_t udata_len);
	@sm: 在sm管理器下添加一个定时器
	@interval: 间隔时间(ms)
	@delay_ms: 延迟时间(ms)
	@repeat: 重复次数 (-1为无限制)
	@on_timeout: 回调函数 (将在sm_run调用线程回调)
	@udata: 私有指针
	@udata_len: udata指向内存的多少字节 (这个值与宏 tools/heap_timer/heap_timer.h::HT_USERDATA_LEN 相关)
	
# sm_0copy_send_fn
# int32_t sm_0copy_send_fn(sock_session_t* ss, const char* data, uint32_t len, uint8_t call_encode, uint8_t close_after_sending);
	@ss: 以0拷贝的方式, 向session发送数据
	@data: 要发送数据的指针
	@len: 发送的长度
	@call_encode: 是否在写入发送缓冲区前, 调用编码函数
	@close_after_sending: 是否在数据发送后关闭连接
	NOTE: 在sm_run/sm_run2调用线程保证线程安全, 且保证数据0拷贝

# sm_upgrade_dispatch_model
	@将管理器升级为数据分发模式, 这将改变管理器的行为.
	@调用后将发生以下改变
		1. 完整的数据包将一定产生数据拷贝
		2. 在非sm_run/sm_run2调用线程只能使用external_fn.h内的函数与主线程通信
	@以后补充
# int32_t sm_upgrade_dispatch_model(session_manager_t* sm, session_dispatch_data_cb dispatch_cb);
	@sm: 将sm管理器提升为数据分发模式
	@dispatch_cb: 数据分发模式的回调函数(只在sm_run/sm_run2调用线程回调), 可参照types.h::dispatch_cb实现尝试运行
	NOTE: 以后补充
	
# sm_upgrade_tls
# int32_t sm_upgrade_tls(sock_session_t* ss, tls_opt_t* tls_opt, _OUT char* errstr);
	@ss: 将session提升为tls协议
	@tls_opt: 参照types
	@errstr: 如果调用错误, 对应的错误信息
	
# sm_ws_client_upgrade
# int32_t sm_ws_client_upgrade(sock_session_t* ss, const char* host);
	@ss: 将作为客户端连接ws/wss服务的session提升为websocket协议, 发送ws upgrade报文
	@host: 报文中的host

# sm_run2
	@不引入定时器的单次驱动session管理器
# int32_t sm_run2(session_manager_t* sm, uint64_t us);
	@sm: 待驱动的管理器
	@us: 超时时间 (ms), 原定为us

# sm_run
	@引入定时器的循环驱动session管理器
# void sm_run(session_manager_t* sm);
	@sm: 待驱动的管理器