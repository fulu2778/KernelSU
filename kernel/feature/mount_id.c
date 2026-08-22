/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 tees
 *
 * mount_id: KSU 模块挂载使用独立高位 mnt_id 空间 (仿 susfs SUS_MOUNT)。
 *
 * 背景: mount_hide 在 show 层过滤模块挂载条目, 但 mnt_id 在挂载创建时
 * 从全局 ida 顺序分配, 被过滤条目的 id 在可见序列里留下空洞——检测方
 * 发现 id 不连续即判定存在被隐藏的挂载 ("挂载间隙")。
 *
 * susfs 的解法 (本文件移植到 LKM): 挂载创建时, 模块挂载 (source 以
 * /adb/modules 开头) 的 mnt_id 从 DEFAULT_KSU_MNT_ID 起分配, 普通挂载
 * 仍从 1 起。可见序列 1..N 连续, 模块挂载的大 id 落在序列之外——空洞
 * 天然不存在。与 mount_hide 的 show 层过滤叠加后, 条目既不可见也无空洞。
 *
 * 实现: KSU 模块挂载是 bind (mount --bind /adb/modules/x ...), 走
 * clone_mnt() (复制已存在挂载), 少数新文件系统挂载走 vfs_create_mount()。
 * 两个 kretprobe 都挂: clone_mnt 为主路径 (devname 判断 source 前缀),
 * vfs_create_mount 兜底 (fc->source 判断)。命中后把 mnt_id 换成高位
 * 分配的新 id (偏移经设备实测), 旧低 id 归还 ida (mnt_free_id 释放时
 * ida_free 正常)。
 *
 * fail-safe: mnt_id_ida 符号缺失或旧 id 不在合理低值区间时整体降级,
 * 不影响 mount_hide 过滤功能。
 */

#include "mount_id.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#include <linux/cred.h>
#include <linux/fs_context.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/ptrace.h>

#define MOUNT_ID_PREFIX "/adb/modules"
#define DEFAULT_KSU_MNT_ID 0x1000000 /* 16777216, susfs 同值 */
#define MOUNT_OFF_MNT 32
#define MOUNT_OFF_MNT_ID 324 /* MIUI GKI 实测: struct mount+324 */
static struct kretprobe kr_vfs_create_mount, kr_clone_mnt;
static bool mount_id_active;

/* mnt_id_ida (fs/namespace.c static 变量, kallsyms 可寻址) */
static struct ida *mnt_id_ida_p;

static int mnt_id_of(struct vfsmount *mnt)
{
    return *(int *)((char *)mnt - MOUNT_OFF_MNT + MOUNT_OFF_MNT_ID);
}

static void set_mnt_id_of(struct vfsmount *mnt, int id)
{
    *(int *)((char *)mnt - MOUNT_OFF_MNT + MOUNT_OFF_MNT_ID) = id;
}

/* 核心: 把模块挂载的 mnt_id 换到高位空间, 低 id 归还 ida */
static void reassign_sus_mnt_id(void *mnt)
{
    struct vfsmount *vm = (struct vfsmount *)((char *)mnt + MOUNT_OFF_MNT);
    int old_id, new_id;

    if (!mount_id_active || !mnt_id_ida_p || !mnt)
        return;

    old_id = mnt_id_of(vm);
    if (old_id <= 0 || old_id >= DEFAULT_KSU_MNT_ID)
        return; /* 已是高位或偏移失配 */

    new_id = ida_alloc_min(mnt_id_ida_p, DEFAULT_KSU_MNT_ID, GFP_ATOMIC);
    if (new_id < 0)
        return;

    set_mnt_id_of(vm, new_id);
    ida_free(mnt_id_ida_p, old_id); /* 低 id 归还, 后续正常挂载可复用 */
    pr_info("mount_id: sus mount id %d -> %d\n", old_id, new_id);
}

/* clone_mnt(old, root, flag) -> struct mount*: bind 挂载的主路径。
 * root 参数即 bind 的源文件 dentry —— dentry_path_raw 可拿源路径,
 * 命中 /adb/modules 即模块挂载 (零偏移依赖)。 */
struct clone_mnt_ctx {
    struct dentry *root;
};

static int clone_mnt_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct clone_mnt_ctx *ctx = (struct clone_mnt_ctx *)ri->data;

    if (unlikely(!mount_id_active))
        return 1; /* 禁用: 不注册 ret, 零开销 */

#ifdef __x86_64__
    ctx->root = (struct dentry *)regs->si;
#else
    ctx->root = (struct dentry *)regs->regs[1];
#endif
    return 0;
}

static int clone_mnt_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct clone_mnt_ctx *ctx = (struct clone_mnt_ctx *)ri->data;
    void *new_mnt = (void *)regs->regs[0];
    char *buf;
    const char *root_path;

    if (!new_mnt || IS_ERR(new_mnt) || !ctx->root)
        return 0;

    /* dentry_path_raw 对已 unlink 的源 dentry 失败 (zygisk dex2oat 场景),
     * 与 mount_hide 判据一致: 漏判的条目可见, 不会产生空洞 */
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return 0;
    root_path = dentry_path_raw(ctx->root, buf, PATH_MAX);
    if (!IS_ERR(root_path) && strncmp(root_path, MOUNT_ID_PREFIX, sizeof(MOUNT_ID_PREFIX) - 1) == 0) {
        kfree(buf);
        reassign_sus_mnt_id(new_mnt);
        return 0;
    }
    kfree(buf);
    return 0;
}

/* vfs_create_mount(fc) -> struct vfsmount*: 新文件系统挂载 (overlay 等) */
struct vfs_create_mount_ctx {
    const char *source;
};

static int vfs_create_mount_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_create_mount_ctx *ctx = (struct vfs_create_mount_ctx *)ri->data;
    struct fs_context *fc;

    if (unlikely(!mount_id_active))
        return 1; /* 禁用: 不注册 ret, 零开销 */

#ifdef __x86_64__
    fc = (struct fs_context *)regs->di;
#else
    fc = (struct fs_context *)regs->regs[0];
#endif
    ctx->source = fc ? fc->source : NULL;
    return 0;
}

static int vfs_create_mount_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_create_mount_ctx *ctx = (struct vfs_create_mount_ctx *)ri->data;
    struct vfsmount *mnt;
    const char *source = ctx->source;

    /* 非模块挂载或创建失败: 跳过 */
    if (!source || strncmp(source, MOUNT_ID_PREFIX, sizeof(MOUNT_ID_PREFIX) - 1) != 0)
        return 0;
    mnt = (struct vfsmount *)regs->regs[0];
    if (!mnt || IS_ERR(mnt))
        return 0;
    reassign_sus_mnt_id((void *)((char *)mnt - MOUNT_OFF_MNT));
    return 0;
}

int __init ksu_mount_id_init(void)
{
    mnt_id_ida_p = (struct ida *)find_kernel_symbol_exact("mnt_id_ida");
    if (!mnt_id_ida_p) {
        pr_warn("mount_id: mnt_id_ida not found, feature degraded\n");
        return 0;
    }

    /* bind 挂载主路径 */
    kr_clone_mnt.kp.symbol_name = "clone_mnt";
    kr_clone_mnt.entry_handler = clone_mnt_entry;
    kr_clone_mnt.handler = clone_mnt_ret;
    kr_clone_mnt.data_size = sizeof(struct clone_mnt_ctx);
    kr_clone_mnt.maxactive = 32;
    if (register_kretprobe(&kr_clone_mnt)) {
        pr_warn("mount_id: register clone_mnt failed, feature degraded\n");
        kr_clone_mnt.kp.symbol_name = NULL;
        return 0;
    }

    /* 新文件系统挂载兜底 (overlay 等) */
    kr_vfs_create_mount.kp.symbol_name = "vfs_create_mount";
    kr_vfs_create_mount.entry_handler = vfs_create_mount_entry;
    kr_vfs_create_mount.handler = vfs_create_mount_ret;
    kr_vfs_create_mount.data_size = sizeof(struct vfs_create_mount_ctx);
    kr_vfs_create_mount.maxactive = 32;
    if (register_kretprobe(&kr_vfs_create_mount)) {
        pr_warn("mount_id: register vfs_create_mount failed\n");
        kr_vfs_create_mount.kp.symbol_name = NULL;
        /* clone_mnt 已注册, 功能仍可用 */
    }

    mount_id_active = true;
    pr_info("mount_id: active (sus mounts get ids >= 0x%x)\n", DEFAULT_KSU_MNT_ID);
    return 0;
}

void __exit ksu_mount_id_exit(void)
{
    mount_id_active = false;
    if (kr_clone_mnt.kp.symbol_name) {
        unregister_kretprobe(&kr_clone_mnt);
        kr_clone_mnt.kp.symbol_name = NULL;
    }
    if (kr_vfs_create_mount.kp.symbol_name) {
        unregister_kretprobe(&kr_vfs_create_mount);
        kr_vfs_create_mount.kp.symbol_name = NULL;
    }
    pr_info("mount_id: deactivated\n");
}
