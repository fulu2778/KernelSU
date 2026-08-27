/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_H_MOUNT_ID
#define __KSU_H_MOUNT_ID

#include <linux/mount.h>

#define DEFAULT_KSU_MNT_ID 0x1000000 /* 模块挂载 id 起始 (susfs 同值) */

int ksu_mount_id_init(void);
void ksu_mount_id_exit(void);

/*
 * 显式登记: 把指定挂载点(路径)的 mnt_id 换到高位空间(>= DEFAULT_KSU_MNT_ID),
 * 使 mount_hide 的输出过滤对它生效。用于挂载参数无法从内核侧可靠判定的
 * 挂载(如 overlay 模块挂载): 由创建方在挂载成功后显式登记。
 * unhide 为逆操作(换回低位, 恢复可见)。
 */
int ksu_mount_id_hide_path(const char *pathname);
int ksu_mount_id_unhide_path(const char *pathname);

#endif /* __KSU_H_MOUNT_ID */
