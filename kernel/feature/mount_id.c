/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 tees
 *
 * mount_id: KSU 模块挂载使用独立高位 mnt_id 空间 (对齐官方 SUSFS)。
 *
 * 机制:
 * - 判据 = SELinux 域: 挂载创建时 current_sid() == ksu 域 SID
 *   ("u:r:ksu:s0")。模块脚本由 init rc 以 ksu 域 exec ksud 拉起(继承域),
 *   与挂载参数(source/挂载点/类型)完全无关 —— 字符串判据(如 /adb/modules
 *   前缀)覆盖不了 overlay(元模块自定义 source)的问题不再存在。
 * - 结构访问 = 编译期: 本模块按 KMI 分别编译(build-all.sh 逐 KMI 出 ko),
 *   头文件含完整 struct mount —— mnt_id 用 container_of 直接字段存取,
 *   不需要任何硬编码偏移(BTF/魔数/设备实测皆不需要)。与官方 SUSFS
 *   "编译期结构访问"同哲学, 只是以 LKM 模块形态实现。
 * - 置高位 = 官方同值: ida_alloc_min(&mnt_id_ida, 2000000000) 起分配,
 *   可见序列 1..N 连续, 模块挂载的大 id 落在序列之外 —— 无空洞。
 * - 开关双控("隐藏挂载记录" feature):
 *   开 → 命中判据的挂载置高位并记入跟踪表;
 *   关 → 表中全部归还低位(输出原样连续), 不再标记新的。
 *   跟踪表对每个挂载持 vfsmount 引用(mntget), 翻转/卸载不悬空。
 */

#include "mount_id.h"
#include "mount_hide.h"
#include "fs/mount.h"
#include "arch.h"
#include "infra/symbol_resolver.h"
#include "klog.h"
#include "selinux/selinux.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/ptrace.h>

#define MAX_MARKED_MOUNTS 64

static struct ida *mnt_id_ida_p;
static bool mount_id_active;

/* 判据: 纯数值 SID 比较 —— init 时一次性把 ksu 域 context 解析为 u32,
 * 挂载时仅比较 current_sid() == ksu_sid。不做任何运行时字符串比较
 * (无 secid_to_secctx/strcmp 回退)。 */

typedef int (*ctx_to_sid_t)(const char *scontext, u32 scontext_len, u32 *out_sid);
typedef u32 (*cur_sid_t)(void);
static ctx_to_sid_t ctx_to_sid_fn;
static cur_sid_t cur_sid_fn;
static u32 ksu_sid;
static bool ksu_sid_valid;

/* 跟踪表: 命中判据的挂载, 开关翻转用 */
struct marked_mount {
    struct list_head list;
    struct vfsmount *vm;
    bool high;
};
static LIST_HEAD(marked_list);
static DEFINE_SPINLOCK(marked_lock);
static int marked_count;

static int mnt_id_of(struct vfsmount *vm)
{
    return container_of(vm, struct mount, mnt)->mnt_id;
}

static void set_mnt_id_of(struct vfsmount *vm, int id)
{
    container_of(vm, struct mount, mnt)->mnt_id = id;
}

/* 判据: 当前进程是否 ksu 域(纯 u32 比较, 无字符串回退) */
static bool ksu_mount_id_ksu_domain(void)
{
    return ksu_sid_valid && cur_sid_fn && cur_sid_fn() == ksu_sid;
}

/* 置高位(标记): 低位 id 归还 ida, 换到 >= DEFAULT_KSU_MNT_ID */
static void reassign_sus_mnt_id(struct vfsmount *vm)
{
    int old_id = mnt_id_of(vm), new_id;

    if (old_id <= 0 || old_id >= DEFAULT_KSU_MNT_ID)
        return; /* 已是高位或无意义 id */

    new_id = ida_alloc_min(mnt_id_ida_p, DEFAULT_KSU_MNT_ID, GFP_ATOMIC);
    if (new_id < 0)
        return;

    set_mnt_id_of(vm, new_id);
    ida_free(mnt_id_ida_p, old_id);
    pr_info("mount_id: sus mnt id %d -> %d\n", old_id, new_id);
}

/* 归还低位(撤销标记): 恢复可见序列连续性 */
static void restore_sus_mnt_id(struct vfsmount *vm)
{
    int old_id = mnt_id_of(vm), new_id;

    if (old_id < DEFAULT_KSU_MNT_ID)
        return; /* 已是低位 */

    new_id = ida_alloc_min(mnt_id_ida_p, 1, GFP_ATOMIC);
    if (new_id < 0)
        return;

    set_mnt_id_of(vm, new_id);
    ida_free(mnt_id_ida_p, old_id);
    pr_info("mount_id: unhide mnt id %d -> %d\n", old_id, new_id);
}

/* 挂载创建命中: 登记进跟踪表; 开关开启时置高位 */
static void ksu_mount_id_maybe_mark(struct vfsmount *vm)
{
    struct marked_mount *e;
    bool found = false;

    if (!mount_id_active || !mnt_id_ida_p || IS_ERR_OR_NULL(vm))
        return;
    if (!ksu_mount_id_ksu_domain())
        return;

    spin_lock(&marked_lock);
    list_for_each_entry (e, &marked_list, list) {
        if (e->vm == vm) {
            found = true;
            break;
        }
    }
    if (!found && marked_count < MAX_MARKED_MOUNTS) {
        e = kzalloc(sizeof(*e), GFP_ATOMIC);
        if (e) {
            mntget(vm);
            e->vm = vm;
            e->high = false;
            list_add_tail(&e->list, &marked_list);
            marked_count++;
            found = true;
        }
    }
    spin_unlock(&marked_lock);

    if (!found)
        return;
    if (ksu_mount_hide_is_enabled() && !e->high && mnt_id_of(vm) < DEFAULT_KSU_MNT_ID) {
        reassign_sus_mnt_id(vm);
        e->high = true;
    }
}

/* 开关关闭: 表中全部归还低位 */
void ksu_mount_id_restore_all(void)
{
    struct marked_mount *e;

    spin_lock(&marked_lock);
    list_for_each_entry (e, &marked_list, list) {
        if (e->high) {
            restore_sus_mnt_id(e->vm);
            e->high = false;
        }
    }
    spin_unlock(&marked_lock);
}

/* 开关开启: 表中全部补标置高 */
void ksu_mount_id_remark_all(void)
{
    struct marked_mount *e;

    spin_lock(&marked_lock);
    list_for_each_entry (e, &marked_list, list) {
        if (!e->high && mnt_id_of(e->vm) < DEFAULT_KSU_MNT_ID) {
            reassign_sus_mnt_id(e->vm);
            e->high = true;
        }
    }
    spin_unlock(&marked_lock);
}

/* ---- 挂载创建拦截: clone_mnt / vfs_create_mount ---- */

static int clone_mnt_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfsmount *vm = (struct vfsmount *)PT_REGS_RC(regs);

    ksu_mount_id_maybe_mark(vm);
    return 0;
}

static int vfs_create_mount_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfsmount *vm = (struct vfsmount *)PT_REGS_RC(regs);

    ksu_mount_id_maybe_mark(vm);
    return 0;
}

static struct kretprobe kr_clone_mnt, kr_vfs_create_mount;

static int kr_setup(struct kretprobe *kr, const char *name, kretprobe_handler_t ret)
{
    kr->kp.symbol_name = name;
    kr->handler = ret;
    kr->maxactive = 32;
    if (register_kretprobe(kr)) {
        pr_warn("mount_id: register %s failed\n", name);
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

/* ksu 域 SID 一次性解析(init): context -> sid, 之后判据只比 u32 */
static void sid_init(void)
{
    ctx_to_sid_fn = (ctx_to_sid_t)find_kernel_symbol_exact("security_context_to_sid");
    cur_sid_fn = (cur_sid_t)find_kernel_symbol_exact("current_sid");
    if (!ctx_to_sid_fn || !cur_sid_fn) {
        pr_warn("mount_id: sid symbols unavailable, judge disabled\n");
        return;
    }
    if (ctx_to_sid_fn(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid) == 0) {
        ksu_sid_valid = true;
        pr_info("mount_id: ksu sid = %u\n", ksu_sid);
    } else {
        pr_warn("mount_id: ksu domain sid unresolvable, judge disabled\n");
    }
}

int __init ksu_mount_id_init(void)
{
    mnt_id_ida_p = (struct ida *)find_kernel_symbol_exact("mnt_id_ida");
    if (!mnt_id_ida_p) {
        pr_warn("mount_id: mnt_id_ida not found, feature degraded\n");
        return 0;
    }

    sid_init();

    if (kr_setup(&kr_clone_mnt, "clone_mnt", clone_mnt_ret)) {
        pr_warn("mount_id: clone_mnt register failed, feature degraded\n");
        return 0;
    }
    if (kr_setup(&kr_vfs_create_mount, "vfs_create_mount", vfs_create_mount_ret))
        pr_warn("mount_id: vfs_create_mount register failed, overlay not covered\n");

    mount_id_active = true;
    pr_info("mount_id: active (ksu-domain mounts get ids >= %d)\n", DEFAULT_KSU_MNT_ID);
    return 0;
}

void __exit ksu_mount_id_exit(void)
{
    struct marked_mount *e, *tmp;

    mount_id_active = false;
    ksu_mount_id_restore_all();
    spin_lock(&marked_lock);
    list_for_each_entry_safe (e, tmp, &marked_list, list) {
        list_del(&e->list);
        mntput(e->vm);
        kfree(e);
        marked_count--;
    }
    spin_unlock(&marked_lock);
    kr_teardown(&kr_vfs_create_mount);
    kr_teardown(&kr_clone_mnt);
    pr_info("mount_id: deactivated\n");
}