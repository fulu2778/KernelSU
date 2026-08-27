/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_H_HIDE_PATH
#define __KSU_H_HIDE_PATH

#include <linux/types.h>

int ksu_hide_path_init(void);
void ksu_hide_path_exit(void);

/* 登记(隐藏)/撤销: 进程上下文 ioctl 调用 */
int ksu_hide_path_register(const char *pathname);
int ksu_hide_path_unregister(const char *pathname);

/* 判据: syscall 入口 / readdir 回调调用(只读, 无睡眠之外的限制) */
bool ksu_hide_path_match_pathname(const char *pathname);
bool ksu_hide_path_match_ino(unsigned long ino);

#endif /* __KSU_H_HIDE_PATH */