/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 tees
 *
 * hide_path: 路径隐藏(独立 feature, 与 hide-mount 互补)。
 *
 * 设计(非 SUSFS namei 三层的 LKM 翻译):
 * - SUSFS 在 namei 层(lookup_dcache/lookup_fast/__lookup_slow)每个路径分量判
 *   一次 —— pathwalk 热路径, 还要处理 RCU 上下文。LKM 复刻这层不划算。
 * - 本实现只挂两个"一次判"点:
 *   1. syscall 入口(stat/access/openat): 检测器用这三个 syscall 探测路径,
 *      每次调用判一次(非每分量), 命中返回 -ENOENT。复用 KernelSU 已有的
 *      syscall dispatcher 框架(不新造 kprobe)。
 *   2. readdir(filldir64/compat_filldir64): 目录列举时按 ino 跳过条目 ——
 *      arm64 安全的 kretprobe: 命中时 ret 回退 current_dir 指针(该条目数据
 *      留在缓冲由下一条覆盖), 不动 pos(不重读, 无死循环)。
 * - 判据 = 登记制(与 hide-mount 同一哲学): 创建方用 hide-path 登记, 系统
 *   路径不登记就不隐藏, 零误伤。登记存 {pathname, ino}, syscall 入口按
 *   pathname 精确匹配, readdir 按 ino 精确匹配。
 */

#include "hide_path.h"
#include "arch.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/ptrace.h>

#define HIDE_PATH_MAX_LEN 256
#define HIDE_PATH_MAX_ENTRIES 64

/* 登记表 */
struct hide_path_entry {
    struct list_head list;
    char pathname[HIDE_PATH_MAX_LEN];
    unsigned long ino;
};

static LIST_HEAD(hide_path_list);
static DECLARE_RWSEM(hide_path_lock);
static int hide_path_count;

/* getdents64 callback 内嵌 dir_context 后第 16 字节是 current_dir 指针(arm64) */
#define GETDENTS64_CURDIR_OFF 16

/* filldir64 的 reclen 公式(与 fs/readdir.c 一致) */
/* linux_dirent64 布局: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) -> d_name@19 */
#define DIRENT64_NAME_OFF 19

static int filldir64_reclen(int namlen)
{
    return ALIGN(DIRENT64_NAME_OFF + namlen + 1, sizeof(u64));
}

/* 判据: syscall 入口用 —— pathname 精确匹配登记路径 */
bool ksu_hide_path_match_pathname(const char *pathname)
{
    struct hide_path_entry *e;
    bool hit = false;

    if (hide_path_count == 0)
        return false;

    down_read(&hide_path_lock);
    list_for_each_entry(e, &hide_path_list, list) {
        if (strcmp(e->pathname, pathname) == 0) {
            hit = true;
            break;
        }
    }
    up_read(&hide_path_lock);
    return hit;
}

/* 判据: readdir 用 —— ino 精确匹配 */
bool ksu_hide_path_match_ino(unsigned long ino)
{
    struct hide_path_entry *e;
    bool hit = false;

    if (hide_path_count == 0)
        return false;

    down_read(&hide_path_lock);
    list_for_each_entry(e, &hide_path_list, list) {
        if (e->ino == ino) {
            hit = true;
            break;
        }
    }
    up_read(&hide_path_lock);
    return hit;
}

/* 登记(隐藏): 解析路径取 ino, 存 {pathname, ino}。进程上下文, 可睡眠 */
int ksu_hide_path_register(const char *pathname)
{
    struct hide_path_entry *new_e, *e;
    struct path path;
    int err;

    if (hide_path_count >= HIDE_PATH_MAX_ENTRIES)
        return -ENOSPC;

    err = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (err)
        return err;
    /* 文件必须存在才能隐藏(dentry 在) */
    if (!path.dentry || !path.dentry->d_inode) {
        path_put(&path);
        return -ENOENT;
    }
    new_e = kzalloc(sizeof(*new_e), GFP_KERNEL);
    if (!new_e) {
        path_put(&path);
        return -ENOMEM;
    }
    strscpy(new_e->pathname, pathname, HIDE_PATH_MAX_LEN);
    new_e->ino = path.dentry->d_inode->i_ino;
    path_put(&path);

    down_write(&hide_path_lock);
    list_for_each_entry(e, &hide_path_list, list) {
        if (strcmp(e->pathname, new_e->pathname) == 0) {
            up_write(&hide_path_lock);
            kfree(new_e);
            return -EEXIST;
        }
    }
    list_add_tail(&new_e->list, &hide_path_list);
    hide_path_count++;
    up_write(&hide_path_lock);
    pr_info("hide_path: register '%s' (ino %lu)\n", new_e->pathname, new_e->ino);
    return 0;
}

/* 撤销登记(恢复可见) */
int ksu_hide_path_unregister(const char *pathname)
{
    struct hide_path_entry *e, *tmp;
    int found = -ENOENT;

    down_write(&hide_path_lock);
    list_for_each_entry_safe(e, tmp, &hide_path_list, list) {
        if (strcmp(e->pathname, pathname) == 0) {
            list_del(&e->list);
            hide_path_count--;
            pr_info("hide_path: unregister '%s'\n", e->pathname);
            kfree(e);
            found = 0;
            break;
        }
    }
    up_write(&hide_path_lock);
    return found;
}

/* ---- readdir 隐藏: filldir64 / compat_filldir64 ---- */

struct filldir_ctx {
    struct dir_context *ctx;
    int curdir_off;
    int reclen;
};

static int filldir64_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct filldir_ctx *fc = (struct filldir_ctx *)ri->data;
    struct dir_context *ctx;
    const char *name;
    int namlen;
    unsigned long ino;

    if (hide_path_count == 0)
        return 1; /* 无登记: 不注册 ret, 零开销 */

    ctx = (struct dir_context *)PT_REGS_PARM1(regs);
    name = (const char *)PT_REGS_PARM2(regs);
    namlen = (int)PT_REGS_PARM3(regs);
    ino = (unsigned long)PT_REGS_PARM5(regs); /* 第 5 参 = ino (arm64 x4) */

    if (!ksu_hide_path_match_ino(ino))
        return 1;

    fc->ctx = ctx;
    fc->curdir_off = GETDENTS64_CURDIR_OFF;
    fc->reclen = filldir64_reclen(namlen);
    return 0;
}

static int filldir64_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct filldir_ctx *fc = (struct filldir_ctx *)ri->data;
    struct dir_context *ctx = fc->ctx;
    char **current_dir;

    if (!ctx)
        return 0;
    /* 回退 current_dir: 该条目录项数据留在缓冲, 由下一条覆盖;
     * 不回退 ctx->pos —— 迭代不重读, 无死循环 */
    current_dir = (char **)((char *)ctx + fc->curdir_off);
    *current_dir -= fc->reclen;
    return 0;
}

/* compat_filldir64: 参数同 filldir64(x0=ctx, x1=name, x2=namlen, x3=offset, x4=ino) */
static int compat_filldir64_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct filldir_ctx *fc = (struct filldir_ctx *)ri->data;
    struct dir_context *ctx;
    const char *name;
    int namlen;
    unsigned long ino;

    if (hide_path_count == 0)
        return 1;

    ctx = (struct dir_context *)PT_REGS_PARM1(regs);
    name = (const char *)PT_REGS_PARM2(regs);
    namlen = (int)PT_REGS_PARM3(regs);
    ino = (unsigned long)PT_REGS_PARM5(regs); /* 第 5 参 = ino (arm64 x4) */

    if (!ksu_hide_path_match_ino(ino))
        return 1;

    fc->ctx = ctx;
    fc->curdir_off = GETDENTS64_CURDIR_OFF; /* compat 回调也嵌 dir_context 打头 */
    fc->reclen = filldir64_reclen(namlen); /* compat 布局同 19 */
    return 0;
}

static struct kretprobe kr_filldir64, kr_compat_filldir64;

static int kr_setup(struct kretprobe *kr, const char *name,
                    kretprobe_handler_t entry, kretprobe_handler_t ret)
{
    kr->kp.symbol_name = name;
    kr->entry_handler = entry;
    kr->handler = ret;
    kr->data_size = sizeof(struct filldir_ctx);
    kr->maxactive = 64;
    if (register_kretprobe(kr)) {
        pr_warn("hide_path: register %s failed\n", name);
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

int ksu_hide_path_init(void)
{
    /* filldir64 是 static 符号, 依赖 KALLSYMS_ALL; GKI 6.6 开, 5.10 可能未开。
     * 注册失败 -> readdir 层降级, syscall 层(stat/access/openat)不受影响。 */
    if (kr_setup(&kr_filldir64, "filldir64", filldir64_entry, filldir64_ret)) {
        pr_warn("hide_path: filldir64 unavailable (KALLSYMS_ALL?), syscall-layer only\n");
        return 0;
    }
    /* compat 失败仅跳过 32 位路径, 不拆 64 位 */
    if (kr_setup(&kr_compat_filldir64, "compat_filldir64",
                 compat_filldir64_entry, filldir64_ret))
        pr_warn("hide_path: compat_filldir64 unavailable, 32-bit dirs not hidden\n");
    pr_info("hide_path: active (filldir64%s)\n",
            kr_compat_filldir64.kp.symbol_name ? "/compat_filldir64" : "");
    return 0;
}

void ksu_hide_path_exit(void)
{
    kr_teardown(&kr_compat_filldir64);
    kr_teardown(&kr_filldir64);
    pr_info("hide_path: deactivated\n");
}