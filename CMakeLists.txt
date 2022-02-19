cmake_minimum_required(VERSION 2.8)

project(sock_manager)

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
set	(SM_STL sock_manager/tools/stl/list.h)
set (CMAKE_C_FLAGS "-std=gnu99")
ELSEIF ((CMAKE_SYSTEM_NAME MATCHES "Windows"))
set	(SM_STL sock_manager/tools/stl/wlist.h)
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

set(SM_TOOLS
	sock_manager/tools/common/common_fn.c
	sock_manager/tools/common/nofile_ctl.c
	sock_manager/tools/common/spin_lock.c
	
	sock_manager/tools/heap_timer/heap_obj.c
	sock_manager/tools/heap_timer/heap_timer.c
	
	sock_manager/tools/rwbuf/rwbuf.c
	sock_manager/tools/stl/rbtree.cpp
)

set(SM_PROTOCOL
	sock_manager/protocol/tcp_binary/tcp_binary.c
	sock_manager/protocol/tcp_default/tcp_default.c
	sock_manager/protocol/websocket/ws2.cpp
)

set(SM_SRC
	${SM_STL}
	${SM_TOOLS}
	${SM_PROTOCOL}
	sock_manager/internal_fn.h
	sock_manager/external_fn.h
	sock_manager/sock_manager.cpp
)

#单线程服务器测试用例
project(st_server)

add_executable(st_server
	${SM_SRC}
	example/st_server.c
)

target_include_directories(st_server
	PUBLIC
		${PROJECT_SOURCE_DIR}
)

target_link_libraries(st_server
	PRIVATE
		uuid
		pthread
)

#单线程客户端测试用例
project(st_client)

add_executable(st_client
	${SM_SRC}
	example/st_client.c
)

target_include_directories(st_client
	PUBLIC
		${PROJECT_SOURCE_DIR}
)

target_link_libraries(st_client
	PRIVATE
		uuid
		pthread
)

#单线程tls websocket服务器测试用例
project(st_wss_server)

add_executable(st_wss_server
	${SM_SRC}
	example/st_wss_server.c
)

target_include_directories(st_wss_server
	PUBLIC
		${PROJECT_SOURCE_DIR}
)

target_link_libraries(st_wss_server
	PRIVATE
		uuid
		pthread
		ssl
		crypto
)

target_compile_definitions(st_wss_server PRIVATE -DENABLE_SSL=1)

#单线程tls websocket客户端测试用例
project(st_wss_client)

add_executable(st_wss_client
	${SM_SRC}
	example/st_wss_client.c
)

target_include_directories(st_wss_client
	PUBLIC
		${PROJECT_SOURCE_DIR}
)

target_link_libraries(st_wss_client
	PRIVATE
		uuid
		pthread
		ssl
		crypto
)

target_compile_definitions(st_wss_client PRIVATE -DENABLE_SSL=1)