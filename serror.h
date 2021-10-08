#ifndef _SERROR_H_
#define _SERROR_H_

#define SERROR_OK				(0)		//调用成功
#define SERROR_SYSAPI_ERR		(-1)	//系统调用错误, 根据errno查看
#define SERROR_INPARAM_ERR		(-2)	//入参错误
#define SERROR_MEMALC_ERR		(-3)	//内存分配失败
#define SERROR_SM_UNINIT		(-999)		//session manager尚未初始化



#endif//_SERROR_H_