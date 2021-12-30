#include "spin_lock.h"

int32_t osspin_lk_init(osspin_lk_t* lock) {
#ifndef _WIN32
	return pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
#else
	InitializeCriticalSection(lock);
	return 0;
#endif//_WIN32
}

int32_t osspin_lk_exit(osspin_lk_t* lock) {
#ifndef _WIN32
	return pthread_spin_destroy(lock);
#else
	DeleteCriticalSection(lock);
	return 0;
#endif//_WIN32
}

int32_t osspin_lk_trylock(osspin_lk_t* lock){
#ifndef _WIN32
	return pthread_spin_trylock(lock);
#else
	return (TryEnterCriticalSection(lock) != 0) ? 0 : -1;
#endif//_WIN32
}

int32_t osspin_lk_lock(osspin_lk_t* lock) {
#ifndef _WIN32
	return pthread_spin_lock(lock);
#else
	EnterCriticalSection(lock);
	return 0;
#endif//_WIN32
}

int32_t osspin_lk_unlock(osspin_lk_t* lock) {
#ifndef _WIN32
	return pthread_spin_unlock(lock);
#else
	LeaveCriticalSection(lock);
	return 0;
#endif//_WIN32
}