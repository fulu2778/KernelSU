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
 * 机制: kprobe 挂在三个 show 回调入口，pre_handler 检查挂载根路径
 * (dentry_path_raw(mnt_root)) 是否命中 KSU 模块挂载前缀(默认为
 * "/adb/modules"，KSU 的模块挂载由用户空间以该路径绑定)，命中则将
 * 指令流重定向到 trampoline 直接返回 0 (seq_file 语义: 该条目不输出)。
 * 过滤对所有进程生效(包含 isolated process)。susfs 内核自带输出过滤，
 * 检测到 susfs_show_mountinfo 符号时自动让位，避免重复。
 *
 * 行为由 KSU_FEATURE_MOUNT_HIDE 开关控制(默认开启)，可通过 ioctl/
 * Manager 切换。卸载 kernel (kernel_umount 或 rmmod kernelsu) 时由
 * ksu_mount_hide_exit 注销 kprobe 恢复。
 */

#include "mount_hide.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <asm/ptrace.h>

#define MOUNT_HIDE_PREFIX "/adb/modules"
#define MOUNT_HIDE_BUF_SIZE (PATH_MAX * 2)

static bool ksu_mount_hide_enabled __read_mostly = true;

/* pre_handler 运行于原子上下文(本 CPU 关抢占)，per-cpu 双缓冲替代
 * 每条目 16KB 的 GFP_ATOMIC 分配；show_* 入口不可能同 CPU 嵌套 */
static DEFINE_PER_CPU(char[2][MOUNT_HIDE_BUF_SIZE], mount_hide_buf);

static struct kprobe kp_mountinfo, kp_vfsmnt, kp_vfsstat;

/* trampoline: 命中挂载后跳入，直接返回 0 (seq_file: 当前条目不输出) */
static int mount_hide_skip_show(struct seq_file *m, struct vfsmount *vfsmnt)
{
    return 0;
}

/* 系统分区: 挂载点(而非 root) 命中这些带尾斜杠前缀，天然排除分区根本身
 * (如 /system 不命中 /system/)。模块挂载点必然落在只读系统分区内的文件上,
 * 这是无法伪装的结构性特征, 与 mountsource/config 无关。 */
static const char *const sys_partitions[] = {
    "/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/vendor_dlkm/", "/system_dlkm/",
};

static bool mount_root_is_sus_mount(struct vfsmount *mnt)
{
    char(*buf)[MOUNT_HIDE_BUF_SIZE];
    const char *path, *root;
    bool hit = false;
    int i;

    if (unlikely(!mnt || !mnt->mnt_root || !ksu_mount_hide_enabled))
        return false;

    buf = get_cpu_var(mount_hide_buf);

    /* 判据1 (结构性): d_path 沿挂载边界返回挂载点全路径。
	 * 系统自身挂载点全是分区根(/system /product /vendor...), 不命中;
	 * 任何覆盖系统文件的模块挂载(bind / overlay / 任意 mountsource)命中。 */
    path = d_path(&(struct path){ .mnt = mnt, .dentry = mnt->mnt_root }, buf[0], MOUNT_HIDE_BUF_SIZE);
    if (likely(!IS_ERR(path))) {
        for (i = 0; i < ARRAY_SIZE(sys_partitions); i++) {
            if (strncmp(path, sys_partitions[i], strlen(sys_partitions[i])) == 0) {
                hit = true;
                goto out;
            }
        }
    }

    /* 判据2 (兜底): root 字段(dentry_path_raw 不跨挂载边界)命中
	 * KSU 模块挂载前缀 /adb/modules, 覆盖传统 bind staging 与
	 * /apex 内文件覆盖(如 zygisk dex2oat) */
    root = dentry_path_raw(mnt->mnt_root, buf[1], MOUNT_HIDE_BUF_SIZE);
    if (likely(!IS_ERR(root)) && strncmp(root, MOUNT_HIDE_PREFIX, sizeof(MOUNT_HIDE_PREFIX) - 1) == 0)
        hit = true;

out:
    put_cpu_var(mount_hide_buf);
    return hit;
}

/* kprobe pre_handler: x86-64: rdi=seq_file*, rsi=vfsmnt* */
static int mount_hide_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct vfsmount *mnt =
#ifdef __x86_64__
        (struct vfsmount *)regs->si;
    if (mount_root_is_sus_mount(mnt)) {
        regs->ip = (unsigned long)mount_hide_skip_show;
        return 1; /* 跳过原指令单步，直接执行 trampoline */
    }
#else
        (struct vfsmount *)regs->regs[1];
    if (mount_root_is_sus_mount(mnt)) {
        regs->pc = (unsigned long)mount_hide_skip_show;
        return 1; /* 跳过原指令单步，直接执行 trampoline */
    }
#endif
    return 0;
}

static int mount_hide_kp_setup(struct kprobe *kp, const char *name)
{
    int ret;

    kp->symbol_name = name;
    kp->pre_handler = mount_hide_pre;
    ret = register_kprobe(kp);
    if (ret)
        kp->symbol_name = NULL; /* 未注册成功, exit 时不可 unregister */
    return ret;
}

static void mount_hide_kp_teardown(struct kprobe *kp)
{
    if (kp->symbol_name) {
        unregister_kprobe(kp);
        kp->symbol_name = NULL;
    }
}

static int ksu_mount_hide_feature_get(u64 *value)
{
    *value = ksu_mount_hide_enabled ? 1 : 0;
    return 0;
}

static int ksu_mount_hide_feature_set(u64 value)
{
    ksu_mount_hide_enabled = value != 0;
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
    int ret;

    /* 内核已集成 susfs 输出过滤时让位，避免重复 hook */
    if (find_kernel_symbol_exact("susfs_show_mountinfo")) {
        pr_info("mount_hide: susfs already present, skip\n");
        return 0;
    }

    ret = mount_hide_kp_setup(&kp_mountinfo, "show_mountinfo");
    if (ret) {
        pr_warn("mount_hide: register show_mountinfo failed: %d\n", ret);
        /* 非 fatal: 特性降级，不影响 KSU 主体 */
        return 0;
    }
    ret = mount_hide_kp_setup(&kp_vfsmnt, "show_vfsmnt");
    if (ret) {
        pr_warn("mount_hide: register show_vfsmnt failed: %d\n", ret);
        goto err_vfsmnt;
    }
    ret = mount_hide_kp_setup(&kp_vfsstat, "show_vfsstat");
    if (ret) {
        pr_warn("mount_hide: register show_vfsstat failed: %d\n", ret);
        goto err_vfsstat;
    }

    ksu_register_feature_handler(&mount_hide_handler);

    pr_info("mount_hide: active (%s)\n", MOUNT_HIDE_PREFIX);
    return 0;

err_vfsstat:
    mount_hide_kp_teardown(&kp_vfsmnt);
err_vfsmnt:
    mount_hide_kp_teardown(&kp_mountinfo);
    return 0;
}

void __exit ksu_mount_hide_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
    mount_hide_kp_teardown(&kp_vfsstat);
    mount_hide_kp_teardown(&kp_vfsmnt);
    mount_hide_kp_teardown(&kp_mountinfo);
    pr_info("mount_hide: deactivated\n");
}
