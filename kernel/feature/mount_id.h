/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_H_MOUNT_ID
#define __KSU_H_MOUNT_ID

#include <linux/mount.h>

#define DEFAULT_KSU_MNT_ID 2000000000 /* 模块挂载 id 起始 对齐官方 SUSFS */

int ksu_mount_id_init(void);
void ksu_mount_id_exit(void);

/* 开关翻转: 关闭还原低位 / 开启补标置高 (由 mount_hide feature 双控调用) */
void ksu_mount_id_restore_all(void);
void ksu_mount_id_remark_all(void);

#endif /* __KSU_H_MOUNT_ID */
