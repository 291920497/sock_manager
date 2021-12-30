#include "nofile_ctl.h"

#ifndef _WIN32
#include <sys/resource.h>
#else
#include <Windows.h>
#include <stdio.h>
#endif//_WIN32

#include <fcntl.h>
#include <errno.h>


#include "../../serror.h"

#ifndef _WIN32

int32_t nofile_ckup() {
	int err = errno;
	if (err != EMFILE) {
		return SERROR_OK;
	}

	struct rlimit old_r, new_r;
	getrlimit(RLIMIT_NOFILE, &old_r);

	//已经没有可以增加的空间, 需要调节资源限制
	if (old_r.rlim_cur == old_r.rlim_max) {
		//printf("old? limit: %d, max: %d\n", old_r.rlim_cur, old_r.rlim_max);
		errno = EMFILE;
		return SERROR_SYSAPI_ERR;
	}

	new_r.rlim_cur = old_r.rlim_cur * 2;
	if(new_r.rlim_cur > old_r.rlim_max)
		new_r.rlim_max = new_r.rlim_cur = old_r.rlim_max;
	else
		new_r.rlim_max = old_r.rlim_max;

	//printf("begin set limit: %d, max: %d\n", new_r.rlim_cur, new_r.rlim_max);
	if (setrlimit(RLIMIT_NOFILE, &new_r) != 0) {
		printf("[%d] setrlimit function error. errno: [%d], old1: [%d], old2: [%d] number: [%d], max: [%d]\n", __LINE__, err, old_r.rlim_cur, old_r.rlim_max, new_r.rlim_cur, new_r.rlim_max);
		//getchar();
		return SERROR_SYSAPI_ERR;
	}
	//printf("end set limit: %d, max: %d\n", new_r.rlim_cur, new_r.rlim_max);
	return SERROR_OK;
}

int32_t nofile_set_nonblocking(int32_t fd) {
	int old_opt = fcntl(fd, F_GETFL);
	int new_opt = old_opt | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_opt);
	return old_opt;
}

#else

int32_t nofile_ckup() {
	return SERROR_SYSAPI_ERR;
}

int32_t nofile_set_nonblocking(int32_t fd) {
	unsigned long opt = 1;
	int rt;
	rt = ioctlsocket(fd, FIONBIO, &opt);
	if (rt == SOCKET_ERROR)
		return SERROR_SYSAPI_ERR;
	return SERROR_OK;
}

#endif//_WIN32