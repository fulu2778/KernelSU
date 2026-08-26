// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 tees
 *
 * selinux_spoof: avc 审计日志伪装 (回调入口 tcontext 替换)。
 *
 * 手法: kprobe 挂 avc_audit_post_callback 入口, 在其执行前把
 *   sad->tsid == ksu_sid 的字段替换为 priv_app_sid。
 *   语义与 SUSFS 源码级 audit_log_format 换字一致 (回调局部),
 *   单探针、无状态传递、无窗口。
 *
 * 关键: 只换 tsid (目标域), 不换 ssid (源域)。
 *   检测方从 avc 日志嗅探"su 对象存在"的途径 = 其他 domain 访问
 *   ksu 对象被拒时打印的 tcontext=u:r:su:s0; 换掉 tsid 即隐身。
 *   源域(通常是 app/system)保真, 避免"谁访问谁"交叉分析矛盾;
 *   且 su 域自身几乎不触发 denied, 换 ssid 无实际收益、徒增痕迹。
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

    /* 只替换 tsid (被访问对象域), 与 SUSFS 语义一致:
     * 检测方从 avc 日志能嗅到"su 对象存在"的途径, 是别的域访问
     * ksu 对象被拒时打印的 tcontext=u:r:su:s0。把 tsid 换成
     * priv_app_sid, "su 对象"就隐身了。
     * 不动 scontext (源域): 触发者通常是 app/system 等其他域,
     * 保留真实源不影响隐藏, 且避免"谁访问谁"交叉分析出矛盾。
     * (su 域自身几乎不触发 denied, 不需要处理 ssid。) */
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

        if (security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid) ||
            security_secctx_to_secid("u:r:priv_app:s0", strlen("u:r:priv_app:s0"), &priv_app_sid)) {
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
