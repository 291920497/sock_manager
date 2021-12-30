#ifndef _FILENO_CTL_H_
#define _FILENO_CTL_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

;
int32_t nofile_ckup();

int32_t nofile_set_nonblocking(int32_t fd);

#ifdef __cplusplus
}
#endif//__cplusplus



#endif//_FILENO_CTL_H_