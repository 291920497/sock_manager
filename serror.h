#ifndef _SERROR_H_
#define _SERROR_H_

#define SERROR_OK				(0)		//调用成功
#define SERROR_SYSAPI_ERR		(-1)	//系统调用错误, 根据errno查看
#define SERROR_INPARAM_ERR		(-2)	//入参错误
#define SERROR_MEMALC_ERR		(-3)	//内存分配失败
#define SERROR_PEER_DISCONN		(-4)	//对端已经断开连接, reset by peer

//tls协议相关
#define SERROR_TLS_MLC_ERR		(SERROR_MEMALC_ERR)	
#define SERROR_TLS_CA_ERR		(-100)	//CA证书加载失败
#define SERROR_TLS_CERT_ERR		(-101)	//证书文件加载失败
#define SERROR_TLS_KEY_ERR		(-102)	//私钥加载失败
#define SERROR_TLS_CHECK_ERR	(-103)	//私钥校验失败
#define SERROR_TLS_WARCLS_ERR	(-104)	//因出现关闭警告关闭套接字, 一般为对端调用了SSL_shutdown
#define SERROR_TLS_SSL_ERR		(-105)	//协议发生错误
#define SERROR_TLS_LIB_ERR		(-106)	//错误码参照ssl.h:1813, 结合ERR_get_error返回的错误码判断真实原因

#define SERROR_SM_UNINIT		(-999)		//session manager尚未初始化



#endif//_SERROR_H_