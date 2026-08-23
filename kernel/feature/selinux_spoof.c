// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 tees
 *
 * selinux_spoof: avc 审计日志伪装 (回调入口双字段替换)。
 *
 * 手法: kprobe 挂 avc_audit_post_callback 入口, 在其执行前把
 *   sad->ssid / sad->tsid 中 == ksu_sid 的字段替换为 priv_app_sid。
 *   与 SUSFS 源码级 goto 改 tcontext 语义一致 (回调局部), 单探针、
 *   无状态传递、无窗口、不依赖返回地址/PAC。
 *
 * 相对原版的修正 (原版两类缺陷, 设备实测 6 条 ksu 审计全部裸输出):
 *   1. 惰性解析顺序 bug: ksu 域事件先发生时 priv_app_sid 永远停在 -1
 *      (后续事件 goto check 短路), 替换永不生效 -> 本版 enable 时
 *      一次解析 ksu/priv_app 两个 sid。
 *   2. 只盖 tcontext: scontext 经 ssid 同样打印, 本版 ssid/tsid 一起换。
 *
 * 为什么不在 security_sid_to_context 出口做: 输出被 LSPosed/Zygisk
 * 等作实际逻辑使用 (getcon 判断自身域), 曾实测导致 LSPosed 失败;
 * 回调入口改数据只影响该回调的日志渲染, 无全局作用面。
 *
 * 行为由 KSU_FEATURE_SELINUX_SPOOF 开关控制(默认关闭)。卸载 kernel
 * 时注销探针恢复。
 */

#include "selinux_spoof.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#include "arch.h"
#include "klog.h"
#include "selinux/selinux.h"

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/string.h>
#include <asm/ptrace.h>

#include "avc.h"

static bool ksu_selinux_spoof_enabled __read_mostly;
static bool spoof_inited __read_mostly;

static struct kprobe kp_avc_cb;

static u32 ksu_sid = (u32)-1;
static u32 priv_app_sid = (u32)-1;

/* security_sid_to_context 无 EXPORT (ss/services.c), 经符号解析调用。
 * KCFI 下函数指针间接调用须经 __nocfi 包装 (属性只适用于函数)。 */
typedef int (*sid_to_context_t)(u32 sid, char **scontext, u32 *scontext_len);
static sid_to_context_t sid_to_context_fn;

static int __nocfi call_sid_to_context(u32 sid, char **scontext, u32 *len)
{
    return sid_to_context_fn(sid, scontext, len);
}

static int avc_cb_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct common_audit_data *ad;
    struct selinux_audit_data *sad;

    if (unlikely(!ksu_selinux_spoof_enabled || !spoof_inited))
        return 0;

    ad = (struct common_audit_data *)PT_REGS_PARM2(regs);
    if (!ad)
        return 0;
    sad = ad->selinux_audit_data;
    if (!sad)
        return 0;

    /* scontext/tcontext 双字段: 只替换 ksu 域, 其余域原样 (不影响
     * 任何其他审计内容, 与 SUSFS 注释语义一致) */
    if (sad->ssid == ksu_sid)
        sad->ssid = priv_app_sid;
    if (sad->tsid == ksu_sid)
        sad->tsid = priv_app_sid;
    if (sad->ssid == ksu_sid)
        sad->ssid = priv_app_sid;
    if (sad->tsid == ksu_sid)
        sad->tsid = priv_app_sid;
    return 0;
}

static int ksu_selinux_spoof_feature_get(u64 *value)
{
    *value = ksu_selinux_spoof_enabled ? 1 : 0;
    return 0;
}

static int ksu_selinux_spoof_feature_set(u64 value)
{
    bool enable = value != 0;

    if (enable && !spoof_inited) {
        char *ctx = NULL;
        u32 len = 0;

        if (security_secctx_to_secid(KERNEL_SU_CONTEXT,
                                     strlen(KERNEL_SU_CONTEXT), &ksu_sid) ||
            security_secctx_to_secid("u:r:priv_app:s0", strlen("u:r:priv_app:s0"),
                                     &priv_app_sid)) {
            pr_warn("selinux_spoof: sid resolve failed (policy loaded?)\n");
            return -EINVAL;
        }
        /* 校验 priv_app 上下文真实可解析 (域存在性), 数值作替换目标 */
        sid_to_context_fn = find_kernel_symbol_exact("security_sid_to_context");
        if (!sid_to_context_fn) {
            pr_warn("selinux_spoof: security_sid_to_context not found\n");
            return -ENOSYS;
        }
        if (call_sid_to_context(priv_app_sid, &ctx, &len) || !ctx) {
            pr_warn("selinux_spoof: priv_app context unresolvable\n");
            return -EINVAL;
        }
        kfree(ctx);
        spoof_inited = true;
    }

    ksu_selinux_spoof_enabled = enable;
    pr_info("selinux_spoof: set to %d\n", ksu_selinux_spoof_enabled);
    return 0;
}

static const struct ksu_feature_handler selinux_spoof_handler = {
    .feature_id = KSU_FEATURE_SELINUX_SPOOF,
    .name = "selinux_spoof",
    .get_handler = ksu_selinux_spoof_feature_get,
    .set_handler = ksu_selinux_spoof_feature_set,
};

int __init ksu_selinux_spoof_init(void)
{
    kp_avc_cb.symbol_name = "avc_audit_post_callback";
    kp_avc_cb.pre_handler = avc_cb_pre;
    if (register_kprobe(&kp_avc_cb)) {
        pr_warn("selinux_spoof: avc_audit_post_callback not available, disabled\n");
        kp_avc_cb.symbol_name = NULL;
        return 0;
    }

    ksu_register_feature_handler(&selinux_spoof_handler);
    pr_info("selinux_spoof: active (callback s/tsid swap)\n");
    return 0;
}

void __exit ksu_selinux_spoof_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_SPOOF);
    if (kp_avc_cb.symbol_name)
        unregister_kprobe(&kp_avc_cb);
    kp_avc_cb.symbol_name = NULL;
    ksu_selinux_spoof_enabled = false;
    spoof_inited = false;
    pr_info("selinux_spoof: deactivated\n");
}
