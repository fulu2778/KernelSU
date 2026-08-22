/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 tees
 *
 * bootconfig_hide: 对非 root 读者伪装 /proc/bootconfig 中的引导链状态。
 *
 * resetprop 只能改属性区, 改不了 /proc/bootconfig (内核 xbc 快照)。
 * 检测应用若能读到 bootconfig, 可与 getprop 交叉比对发现属性伪装。
 * 本特性在启动后快照真实 bootconfig, 做与 FakeLock (ksud 原生属性
 * 伪装) 一致的替换后缓存; kprobe 挂在 boot_config_proc_show 入口,
 * 非 root 读者重定向到 trampoline 输出替换版本, root 读者与禁用时
 * 原样透传。
 *
 * 行为由 KSU_FEATURE_BOOTCONFIG_HIDE 开关控制(默认关闭), 与 ksud 的
 * fakelock 子命令联动: ksud fakelock enable/disable 会同时切换本
 * feature 并重放属性伪装, 两者永远处于同一状态。
 * 替换常量必须与 ksud fakelock 模块的属性表保持一致。
 */

#include "bootconfig_hide.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#define BOOTCONFIG_MAX_LEN (128 * 1024)

static bool ksu_bootconfig_hide_enabled __read_mostly = false;
static char *fake_bootconfig;
static struct delayed_work bootconfig_snapshot_work;
static struct kprobe kp_bootconfig;

/* trampoline: 非 root 读者进入, 输出替换后的 bootconfig */
static int fake_boot_config_proc_show(struct seq_file *m, void *v)
{
    const char *content = smp_load_acquire(&fake_bootconfig);

    if (content)
        seq_puts(m, content);
    return 0;
}

static int bootconfig_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (!fake_bootconfig || !ksu_bootconfig_hide_enabled)
        return 0;
    /* root 读者(自己人)透传真实内容 */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return 0;
#ifdef __x86_64__
    regs->ip = (unsigned long)fake_boot_config_proc_show;
#else
    regs->pc = (unsigned long)fake_boot_config_proc_show;
#endif
    return 1;
}

/* 值级替换: unlocked/orange 全局出现即替换为锁定态值 (仅存在于这两个
 * 值; avb_version/size 等其余条目保持真实, 与 ksud fakelock 的
 * 属性表策略一致: 不伪造不指示锁状态的值) */
static int subst_line(char *dst, size_t dst_size, const char *line)
{
    if (strstr(line, "unlocked") || strstr(line, "orange")) {
        const char *src = line;
        char *out = dst;
        while (*src && (size_t)(out - dst) < dst_size - 16) {
            if (strncmp(src, "unlocked", 8) == 0) {
                out += snprintf(out, dst_size - (out - dst), "locked");
                src += 8;
            } else if (strncmp(src, "orange", 6) == 0) {
                out += snprintf(out, dst_size - (out - dst), "green");
                src += 6;
            } else {
                *out++ = *src++;
            }
        }
        *out = '\0';
        return out - dst;
    }

    return snprintf(dst, dst_size, "%s", line);
}

static char *read_file_all(const char *path, size_t max_len)
{
    struct file *fp;
    char *buf;
    loff_t pos = 0;
    ssize_t n;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp))
        return NULL;

    buf = kmalloc(max_len, GFP_KERNEL);
    if (!buf) {
        filp_close(fp, 0);
        return NULL;
    }

    n = kernel_read(fp, buf, max_len - 1, &pos);
    filp_close(fp, 0);
    if (n <= 0) {
        kfree(buf);
        return NULL;
    }
    buf[n] = '\0';
    return buf;
}

static void bootconfig_snapshot(struct work_struct *w)
{
    static int attempts;
    char *real, *fake, *line, *dst;
    size_t fake_len;

    real = read_file_all("/proc/bootconfig", BOOTCONFIG_MAX_LEN);
    if (!real) {
        /* /proc 尚未就绪则重试 (最多 1 分钟) */
        if (++attempts < 12)
            schedule_delayed_work(&bootconfig_snapshot_work, msecs_to_jiffies(5000));
        return;
    }

    fake = kmalloc(BOOTCONFIG_MAX_LEN, GFP_KERNEL);
    if (!fake) {
        kfree(real);
        return;
    }

    dst = fake;
    line = real;
    while (line && *line && (size_t)(dst - fake) < BOOTCONFIG_MAX_LEN - 256) {
        char *nl = strchr(line, '\n');
        size_t left = BOOTCONFIG_MAX_LEN - (dst - fake) - 1;
        int n;

        if (nl)
            *nl = '\0';
        n = subst_line(dst, left, line);
        if (n > 0)
            dst += n;
        else
            break;
        line = nl ? nl + 1 : NULL;
    }
    *dst = '\0';
    kfree(real);

    fake_len = dst - fake + 1;
    {
        char *shrunk = kmalloc(fake_len, GFP_KERNEL);
        if (shrunk) {
            memcpy(shrunk, fake, fake_len);
            kfree(fake);
            fake = shrunk;
        }
    }

    smp_store_release(&fake_bootconfig, fake);
    pr_info("bootconfig_hide: snapshot ready (%zu bytes, enabled=%d)\n", fake_len - 1,
            ksu_bootconfig_hide_enabled);
}

static int ksu_bootconfig_hide_feature_get(u64 *value)
{
    *value = ksu_bootconfig_hide_enabled ? 1 : 0;
    return 0;
}

static int ksu_bootconfig_hide_feature_set(u64 value)
{
    ksu_bootconfig_hide_enabled = value != 0;
    pr_info("bootconfig_hide: set to %d\n", ksu_bootconfig_hide_enabled);
    return 0;
}

static const struct ksu_feature_handler bootconfig_hide_handler = {
    .feature_id = KSU_FEATURE_BOOTCONFIG_HIDE,
    .name = "bootconfig_hide",
    .get_handler = ksu_bootconfig_hide_feature_get,
    .set_handler = ksu_bootconfig_hide_feature_set,
};

int __init ksu_bootconfig_hide_init(void)
{
    int ret;

    kp_bootconfig.symbol_name = "boot_config_proc_show";
    kp_bootconfig.pre_handler = bootconfig_pre;
    ret = register_kprobe(&kp_bootconfig);
    if (ret) {
        /* 非 fatal: 特性降级, 不影响 KSU 主体 */
        pr_warn("bootconfig_hide: register kprobe failed: %d\n", ret);
        kp_bootconfig.symbol_name = NULL;
        return 0;
    }

    ksu_register_feature_handler(&bootconfig_hide_handler);

    INIT_DELAYED_WORK(&bootconfig_snapshot_work, bootconfig_snapshot);
    schedule_delayed_work(&bootconfig_snapshot_work, msecs_to_jiffies(5000));

    pr_info("bootconfig_hide: active\n");
    return 0;
}

void __exit ksu_bootconfig_hide_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_BOOTCONFIG_HIDE);
    cancel_delayed_work_sync(&bootconfig_snapshot_work);
    if (kp_bootconfig.symbol_name) {
        unregister_kprobe(&kp_bootconfig);
        kp_bootconfig.symbol_name = NULL;
    }
    if (fake_bootconfig) {
        kfree(fake_bootconfig);
        fake_bootconfig = NULL;
    }
    pr_info("bootconfig_hide: deactivated\n");
}
