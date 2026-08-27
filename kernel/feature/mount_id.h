/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_H_MOUNT_ID
#define __KSU_H_MOUNT_ID

#include <linux/mount.h>

#define DEFAULT_KSU_MNT_ID 0x1000000 /* 模块挂载 id 起始 (susfs 同值) */

int ksu_mount_id_init(void);
void ksu_mount_id_exit(void);

#endif /* __KSU_H_MOUNT_ID */
