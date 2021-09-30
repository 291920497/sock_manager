#include "nofile_ctl.h"

#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>

#include "../../serror.h"

int32_t nofile_ckup() {
	int err = errno;
	if (err != EMFILE) {
		SERROR_OK;
	}

	struct rlimit old_r, new_r;
	getrlimit(RLIMIT_NOFILE, &old_r);

	new_r.rlim_cur = old_r.rlim_cur * 2;

	//若超出了最大，则使用旧时最大
	if (new_r.rlim_cur > old_r.rlim_max) {
		new_r.rlim_max = new_r.rlim_cur = old_r.rlim_max;
	}
	else {
		new_r.rlim_max = old_r.rlim_max;
	}

	if (setrlimit(RLIMIT_NOFILE, &new_r) != 0) {
		//printf("[%s:%d] setrlimit function error. errno: [%d]\n", __FILENAME__, __LINE__, err);
		return SERROR_SYSAPI_ERR;
	}

	return SERROR_OK;
}

int32_t tools_set_nonblocking(int32_t fd) {
	int old_opt = fcntl(fd, F_GETFL);
	int new_opt = old_opt | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_opt);
	return old_opt;
}