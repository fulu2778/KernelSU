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
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#define MOUNT_HIDE_PREFIX "/adb/modules"
#define MOUNT_HIDE_BUF_SIZE (PATH_MAX * 2)

static bool ksu_mount_hide_enabled __read_mostly = true;

/* /data/adb/modules 目录 dentry 缓存: 判据0 的纯指针快路径。
 * LKM 在 ramdisk 阶段加载时 /data 尚未挂载, 由 delayed work 重试解析;
 * 持引用(dget)防释放, 若 /data 重挂导致 dentry 陈旧, 判据0 失配后
 * 仍由判据1/2 字符串兜底, 不产生误放行。 */
static struct dentry *modules_dentry __read_mostly;
static struct delayed_work modules_dentry_work;
#define MODULES_DENTRY_PATH "/data/adb/modules"

/* 系统分区: 挂载点(而非 root) 命中这些带尾斜杠前缀，天然排除分区根本身
 * (如 /system 不命中 /system/)。模块挂载点必然落在只读系统分区内的文件上,
 * 这是无法伪装的结构性特征, 与 mountsource/config 无关。 */
static const char *const sys_partitions[] = {
    "/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/vendor_dlkm/", "/system_dlkm/",
};

/* 系统分区真实 st_dev 缓存 (stat 一致性层改写目标), delayed work 填充 */
static u32 sys_part_devs[ARRAY_SIZE(sys_partitions)];

static void modules_dentry_resolve(struct work_struct *w)
{
    struct path path;
    static int attempts;

    /* 缓存系统分区真实 dev (供 stat 一致性层改写), 首轮即完成, 与 /data 无关 */
    {
        int i;

        for (i = 0; i < ARRAY_SIZE(sys_partitions); i++) {
            char buf[32];
            size_t len = strlen(sys_partitions[i]) - 1; /* 去尾斜杠 */

            if (sys_part_devs[i] || len >= sizeof(buf))
                continue;
            memcpy(buf, sys_partitions[i], len);
            buf[len] = '\0';
            if (kern_path(buf, LOOKUP_FOLLOW, &path) == 0) {
                sys_part_devs[i] = path.mnt->mnt_sb->s_dev;
                path_put(&path);
            }
        }
    }

    if (kern_path(MODULES_DENTRY_PATH, LOOKUP_FOLLOW, &path) == 0) {
        struct dentry *old = xchg(&modules_dentry, path.dentry);
        if (old)
            dput(old);
        mntput(path.mnt); /* 只释放 mnt 引用, dentry 引用移交缓存 */
        pr_info("mount_hide: fast path armed (%s)\n", MODULES_DENTRY_PATH);
        return;
    }
    if (++attempts < 12) /* 每 5s 重试, 1 分钟后放弃 */
        schedule_delayed_work(&modules_dentry_work, msecs_to_jiffies(5000));
}

/* pre_handler 运行于原子上下文(本 CPU 关抢占)，per-cpu 双缓冲替代
 * 每条目 16KB 的 GFP_ATOMIC 分配；show_* 入口不可能同 CPU 嵌套。
 * 注意: 不能用静态 DEFINE_PER_CPU——模块 percpu 段预留区
 * (PERCPU_MODULE_RESERVE) 仅 8KB, 16KB 缓冲会令 insmod 直接
 * -ENOMEM 失败; 改为 init 时 __alloc_percpu 走动态 percpu 池。 */
static char __percpu *mount_hide_buf; /* 2 * MOUNT_HIDE_BUF_SIZE */

static struct kprobe kp_mountinfo, kp_vfsmnt, kp_vfsstat;

/* trampoline: 命中挂载后跳入，直接返回 0 (seq_file: 当前条目不输出) */
static int mount_hide_skip_show(struct seq_file *m, struct vfsmount *vfsmnt)
{
    return 0;
}

/* ---- stat 一致性层: 修补"挂载间隙" ----
 * 隐藏挂载列表后, 落在系统分区路径上的 bind/overlay 文件 stat 出的
 * st_dev 仍是源文件系统(如 /data)的设备号, 与"列表里没有该挂载"矛盾,
 * 构成可检测的挂载间隙。kretprobe 挂 vfs_statx (覆盖 stat/lstat/statx/
 * fstatat 家族), 对非 root 读者: 路径命中系统分区前缀且 dev 与分区
 * 真实 dev 不符时, 改写为分区 dev, 使 stat 结果与过滤后的挂载列表
 * 处于同一世界观。分区的真实 dev 由 delayed work 开机后缓存。 */
static struct kretprobe kr_statx;

struct statx_ctx {
    const char *name;
    struct kstat *stat;
};

static int statx_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct statx_ctx *ctx = (struct statx_ctx *)ri->data;
    struct filename *fn;
    struct kstat *stat;

    /* 快路径: 功能关闭或 root 读者(自己人)时跳过 ret handler */
    if (!ksu_mount_hide_enabled || uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return 1;

#ifdef __x86_64__
    fn = (struct filename *)regs->si;
    stat = (struct kstat *)regs->cx;
#else
    fn = (struct filename *)regs->regs[1];
    stat = (struct kstat *)regs->regs[3];
#endif
    ctx->name = fn ? fn->name : NULL;
    ctx->stat = stat;
    return 0;
}

static int statx_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct statx_ctx *ctx = (struct statx_ctx *)ri->data;
    const char *name = ctx->name;
    struct kstat *stat = ctx->stat;
    int i;

    if (!name || !stat || regs_return_value(regs) != 0)
        return 0;

    for (i = 0; i < ARRAY_SIZE(sys_partitions); i++) {
        size_t plen = strlen(sys_partitions[i]);

        if (strncmp(name, sys_partitions[i], plen) == 0 && sys_part_devs[i] && stat->dev != sys_part_devs[i]) {
            stat->dev = sys_part_devs[i];
            break;
        }
    }
    return 0;
}

static bool mount_root_is_sus_mount(struct vfsmount *mnt)
{
    char *buf;
    const char *path, *root;
    struct dentry *cached;
    bool hit = false;
    int i;

    if (unlikely(!mnt || !mnt->mnt_root || !ksu_mount_hide_enabled || !mount_hide_buf))
        return false;

    /* root 读者(自己人)直接放行: 调试可见真实挂载, 也省掉其全部开销 */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return false;

    /* 判据0 (快路径, 纯指针): bind mount 的 mnt_root 即源文件 dentry,
	 * 落在 /data/adb/modules 树内则必为模块挂载, 无需任何字符串运算。
	 * dentry 由 delayed work 异步解析(LKM 加载时 /data 尚未挂载),
	 * 解析成功前该判据静默跳过, 由判据1/2 兜底。 */
    cached = READ_ONCE(modules_dentry);
    if (cached) {
        bool sub;
        rcu_read_lock();
        sub = is_subdir(mnt->mnt_root, cached);
        rcu_read_unlock();
        if (sub)
            return true;
    }

    buf = get_cpu_ptr(mount_hide_buf);

    /* 判据1 (结构性): d_path 沿挂载边界返回挂载点全路径。
	 * 系统自身挂载点全是分区根(/system /product /vendor...), 不命中;
	 * 任何覆盖系统文件的模块挂载(bind / overlay / 任意 mountsource)命中。 */
    path = d_path(&(struct path){ .mnt = mnt, .dentry = mnt->mnt_root }, buf, MOUNT_HIDE_BUF_SIZE);
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
    root = dentry_path_raw(mnt->mnt_root, buf + MOUNT_HIDE_BUF_SIZE, MOUNT_HIDE_BUF_SIZE);
    if (likely(!IS_ERR(root)) && strncmp(root, MOUNT_HIDE_PREFIX, sizeof(MOUNT_HIDE_PREFIX) - 1) == 0)
        hit = true;

out:
    put_cpu_ptr(mount_hide_buf);
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

    /* 双缓冲必须先于 kprobe 注册就绪: 动态 percpu 池分配, 见变量声明处注释 */
    mount_hide_buf = __alloc_percpu(2 * MOUNT_HIDE_BUF_SIZE, __alignof__(u64));
    if (!mount_hide_buf) {
        pr_warn("mount_hide: percpu buffer alloc failed, feature degraded\n");
        return 0;
    }

    ret = mount_hide_kp_setup(&kp_mountinfo, "show_mountinfo");
    if (ret) {
        pr_warn("mount_hide: register show_mountinfo failed: %d\n", ret);
        /* 非 fatal: 特性降级，不影响 KSU 主体 */
        goto err_percpu;
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

    /* stat 一致性层 (vfs_statx 为 static 符号, 走 kallsyms 定位) */
    kr_statx.kp.symbol_name = "vfs_statx";
    kr_statx.entry_handler = statx_entry;
    kr_statx.handler = statx_ret;
    kr_statx.data_size = sizeof(struct statx_ctx);
    kr_statx.maxactive = 64;
    ret = register_kretprobe(&kr_statx);
    if (ret) {
        pr_warn("mount_hide: register vfs_statx kretprobe failed: %d, stat spoofing degraded\n", ret);
        kr_statx.kp.symbol_name = NULL;
    }

    ksu_register_feature_handler(&mount_hide_handler);

    INIT_DELAYED_WORK(&modules_dentry_work, modules_dentry_resolve);
    schedule_delayed_work(&modules_dentry_work, msecs_to_jiffies(5000));

    pr_info("mount_hide: active (%s)\n", MOUNT_HIDE_PREFIX);
    return 0;

err_vfsstat:
    mount_hide_kp_teardown(&kp_vfsmnt);
err_vfsmnt:
    mount_hide_kp_teardown(&kp_mountinfo);
err_percpu:
    free_percpu(mount_hide_buf);
    mount_hide_buf = NULL;
    return 0;
}

void __exit ksu_mount_hide_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
    cancel_delayed_work_sync(&modules_dentry_work);
    if (modules_dentry)
        dput(modules_dentry);
    mount_hide_kp_teardown(&kp_vfsstat);
    mount_hide_kp_teardown(&kp_vfsmnt);
    mount_hide_kp_teardown(&kp_mountinfo);
    if (kr_statx.kp.symbol_name) {
        unregister_kretprobe(&kr_statx);
        kr_statx.kp.symbol_name = NULL;
    }
    if (mount_hide_buf) {
        free_percpu(mount_hide_buf);
        mount_hide_buf = NULL;
    }
    pr_info("mount_hide: deactivated\n");
}
