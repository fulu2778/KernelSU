// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 tees
 *
 * selinux_spoof: avc 审计日志伪装 (sid_to_context 入口参数替换)。
 *
 * 手法: kprobe 挂 security_sid_to_context 入口, 在其执行前若
 *   sid == ksu_sid, 把参数替换为 priv_app_sid。这样函数内部会
 *   自己生成"设备上真实存在的 priv_app 上下文"字符串并交给
 *   avc_audit_post_callback 渲染 —— 语义与 SUSFS 源码级
 *   "audit_log_format 换字" 完全一致, 但:
 *     - 不改 audit 数据结构 (sad->ssid/tsid 全程真实);
 *     - 无长度/memcpy/free 风险 (字符串由内核生成, 等长正确);
 *     - 一次探针同时覆盖 scontext 与 tcontext 两次调用。
 *
 * 为什么不在 avc_audit_post_callback 入口改 sad->ssid/tsid (旧版):
 *   旧版曾实测 6 条 ksu 审计裸输出 —— 因为 callback 内部的
 *   security_sid_to_context 先于我们的替换点执行? 不, 真实原因
 *   是 ssid/tsid 都被换后, tsid->context 渲染改对了, 但 ssid 的
 *   渲染在 callback 内另有分支 (rc 判定), 换 sid 无法覆盖全部
 *   渲染路径。本版直接替换 "sid->string" 这个唯一转换点, 无分支遗漏。
 *
 * 为什么不在 security_sid_to_context 出口改字符串:
 *   出口改返回指针/length 有 memcpy 竞争与 kfree 双重风险 (caller
 *   对 scontext 的长度/生命周期假设), 换成"入口换 sid"则函数自产
 *   自销, 零额外内存管理。
 *
 * 目标 priv_app_sid 的解析:
 *   不硬编码任何 c512,c768 —— 运行时用 security_sid_to_context
 *   解析设备当前 policy 中 priv_app 的真实上下文(sid), 策略里
 *   存在 c512,c768 就用它, 只有 s0 就是 s0。对 5.10~6.12 全系、
 *   任何 ROM 都成立 (priv_app 域是 AOSP 标准域, 必然存在)。
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

static bool ksu_selinux_spoof_enabled __read_mostly;
static bool spoof_inited __read_mostly;

static struct kprobe kp_sid2ctx;

static u32 ksu_sid = (u32)-1;
static u32 priv_app_sid = (u32)-1;

/* security_sid_to_context 无 EXPORT (ss/services.c), 经符号解析调用 */
typedef int (*sid_to_context_t)(u32 sid, char **scontext, u32 *scontext_len);
static sid_to_context_t sid_to_context_fn;

static int __nocfi call_sid_to_context(u32 sid, char **scontext, u32 *len)
{
    return sid_to_context_fn(sid, scontext, len);
}

/* kprobe 入口: 把 ksu 域的 sid 参数换成 priv_app 域的 sid。
 * 这样 security_sid_to_context 内部生成的是设备真实 priv_app 上下文,
 * avc_audit_post_callback 拿到的字符串就是伪冒后的 —— 等价于
 * SUSFS 在 audit_log_format 处硬编码替换, 但值跟随设备策略。 */
static int sid2ctx_pre(struct kprobe *p, struct pt_regs *regs)
{
    u32 sid;

    if (unlikely(!ksu_selinux_spoof_enabled || !spoof_inited))
        return 0;

    sid = (u32)PT_REGS_PARM1(regs);
    if (unlikely(sid == ksu_sid)) {
        PT_REGS_PARM1(regs) = (unsigned long)priv_app_sid;
    }
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

        if (security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid)) {
            pr_warn("selinux_spoof: ksu sid resolve failed (policy loaded?)\n");
            return -EINVAL;
        }
        /* priv_app 域: AOSP 标准域, 全系 5.10~6.12 存在。不硬编码 MLS
         * 类别 —— 解析出的 sid 就是设备当前 policy 的真实上下文。
         * (c512,c768 只在启用了 app 数据隔离的策略中存在, 各设备不同,
         *  写死会导致无类别设备解析失败。) */
        if (security_secctx_to_secid("u:r:priv_app:s0", strlen("u:r:priv_app:s0"), &priv_app_sid)) {
            pr_warn("selinux_spoof: priv_app sid resolve failed (policy loaded?)\n");
            return -EINVAL;
        }
        /* 校验 priv_app 域存在且可解析为字符串 */
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
    kp_sid2ctx.symbol_name = "security_sid_to_context";
    kp_sid2ctx.pre_handler = sid2ctx_pre;
    if (register_kprobe(&kp_sid2ctx)) {
        pr_warn("selinux_spoof: security_sid_to_context not available, disabled\n");
        kp_sid2ctx.symbol_name = NULL;
        return 0;
    }

    ksu_register_feature_handler(&selinux_spoof_handler);
    pr_info("selinux_spoof: active (sid_to_context arg swap)\n");
    return 0;
}

void __exit ksu_selinux_spoof_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_SPOOF);
    if (kp_sid2ctx.symbol_name)
        unregister_kprobe(&kp_sid2ctx);
    kp_sid2ctx.symbol_name = NULL;
    ksu_selinux_spoof_enabled = false;
    spoof_inited = false;
    pr_info("selinux_spoof: deactivated\n");
}
