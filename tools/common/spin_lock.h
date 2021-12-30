#ifndef _SPIN_LOCK_H_
#define _SPIN_LOCK_H_

#include <stdio.h>
#include <stdint.h>

#ifndef _WIN32
//-D_GNU_SOURCE=1
#include <pthread.h>
typedef pthread_spinlock_t osspin_lk_t;
#else
#include <Windows.h>
typedef CRITICAL_SECTION osspin_lk_t;
#endif//_WIN32

#ifdef __cplusplus
extern "C"
{
#endif
;

//以下函数成功返回0

int32_t osspin_lk_init(osspin_lk_t* lock);

int32_t osspin_lk_exit(osspin_lk_t* lock);

int32_t osspin_lk_trylock(osspin_lk_t* lock);

int32_t osspin_lk_lock(osspin_lk_t* lock);

int32_t osspin_lk_unlock(osspin_lk_t* lock);



#ifdef __cplusplus
}
#endif

#endif//_SPIN_LOCK_H_