/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 tees
 *
 * mount_hide: 隐藏 KSU 模块挂载，使其不出现在
 *   /proc/self/mountinfo (show_mountinfo)
 *   /proc/self/mounts    (show_vfsmnt)
 *   /proc/self/mountstat (show_vfsstat)
 * 的输出中。与 kernel_umount(真卸载) 互补：本功能保留挂载功能，
 * 仅在输出层对挂载条目做过滤。
 *
 * 过滤判据: 只看 mnt_id —— 模块挂载由 mount_id 分配独立高位 id 空间
 * (>= DEFAULT_KSU_MNT_ID), 系统挂载保持低 id。show 层对高 id 条目
 * 过滤, 低 id 序列天然连续 (无挂载间隙), 且不会误伤任何系统挂载
 * (路径无关, 与 susfs 的 SUS_MOUNT 过滤语义一致)。
 *
 * 实现: kretprobe 挂三个 show 回调。entry 记录 m->count 并判断当前
 * 条目 id 是否高位; ret 时对高位条目把 m->count 回退到 entry 值——
 * 该行内容被"抹掉", seq 迭代自动继续下一行。无指令跳转、无缓冲改写,
 * arm64/x86_64 通用。
 *
 * 行为由 KSU_FEATURE_MOUNT_HIDE 开关控制(默认开启)。卸载 kernel 时
 * 注销探针恢复。
 */

#include "mount_hide.h"
#include "mount_id.h"
#include "arch.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/ptrace.h>

static bool ksu_mount_hide_enabled __read_mostly = true;

static struct kretprobe kr_mountinfo, kr_vfsmnt, kr_vfsstat;

struct hide_ctx {
    struct seq_file *m;
    unsigned long count_before;
};

static int mnt_id_of(struct vfsmount *vm)
{
    return container_of(vm, struct mount, mnt)->mnt_id;
}

/* 高位 id = 模块挂载 (mount_id 分配), 过滤之 */
static bool is_sus_mount_id(struct vfsmount *mnt)
{
    int id = mnt_id_of(mnt);

    return id >= DEFAULT_KSU_MNT_ID;
}

static int hide_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct hide_ctx *ctx = (struct hide_ctx *)ri->data;
    struct seq_file *m;
    struct vfsmount *mnt;

    if (unlikely(!ksu_mount_hide_enabled))
        return 1; /* 禁用: 不注册 ret, 零开销 */

    /* root 读者(自己人)不过滤: 调试可见真实挂载 */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return 1;

    m = (struct seq_file *)PT_REGS_PARM1(regs);
    mnt = (struct vfsmount *)PT_REGS_PARM2(regs);

    ctx->m = m;
    ctx->count_before = m ? m->count : 0;
    if (!m || !mnt || !is_sus_mount_id(mnt))
        return 1; /* 可见条目: 跳过 ret, 零开销 */

    /* 模块挂载: 注册 ret, 输出后抹掉本行 */
    return 0;
}

static int hide_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct hide_ctx *ctx = (struct hide_ctx *)ri->data;
    struct seq_file *m = ctx->m;

    /* 回退 count: 本行内容从输出中消失, seq 迭代继续下一行 */
    if (m && m->count >= ctx->count_before)
        m->count = ctx->count_before;
    return 0;
}

static int kr_setup(struct kretprobe *kr, const char *name)
{
    kr->kp.symbol_name = name;
    kr->entry_handler = hide_entry;
    kr->handler = hide_ret;
    kr->data_size = sizeof(struct hide_ctx);
    kr->maxactive = 64;
    if (register_kretprobe(kr)) {
        pr_warn("mount_hide: register %s failed\n", name);
        kr->kp.symbol_name = NULL;
        return -1;
    }
    return 0;
}

static void kr_teardown(struct kretprobe *kr)
{
    if (kr->kp.symbol_name) {
        unregister_kretprobe(kr);
        kr->kp.symbol_name = NULL;
    }
}

static int ksu_mount_hide_feature_get(u64 *value)
{
    *value = ksu_mount_hide_enabled ? 1 : 0;
    return 0;
}

bool ksu_mount_hide_is_enabled(void)
{
    return ksu_mount_hide_enabled;
}

static int ksu_mount_hide_feature_set(u64 value)
{
    ksu_mount_hide_enabled = value != 0;
    if (value)
        ksu_mount_id_remark_all();
    else
        ksu_mount_id_restore_all();
    pr_info("mount_hide: set to %d\n", ksu_mount_hide_enabled);
    return 0;
}

static const struct ksu_feature_handler mount_hide_handler = {
    .feature_id = KSU_FEATURE_MOUNT_HIDE,
    .name = "mount_hide",
    .get_handler = ksu_mount_hide_feature_get,
    .set_handler = ksu_mount_hide_feature_set,
};

int __init ksu_mount_hide_init(void)
{
    /* 内核已集成 susfs 输出过滤时让位, 避免重复 hook */
    if (find_kernel_symbol_exact("susfs_show_mountinfo")) {
        pr_info("mount_hide: susfs already present, skip\n");
        return 0;
    }

    if (kr_setup(&kr_mountinfo, "show_mountinfo"))
        return 0;
    if (kr_setup(&kr_vfsmnt, "show_vfsmnt"))
        goto err_vfsmnt;
    if (kr_setup(&kr_vfsstat, "show_vfsstat"))
        goto err_vfsstat;

    ksu_register_feature_handler(&mount_hide_handler);

    pr_info("mount_hide: active (filter ids >= 0x%x)\n", DEFAULT_KSU_MNT_ID);
    return 0;

err_vfsmnt:
    kr_teardown(&kr_vfsmnt);
err_vfsstat:
    kr_teardown(&kr_mountinfo);
    return 0;
}

void __exit ksu_mount_hide_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
    kr_teardown(&kr_vfsstat);
    kr_teardown(&kr_vfsmnt);
    kr_teardown(&kr_mountinfo);
    pr_info("mount_hide: deactivated\n");
}
