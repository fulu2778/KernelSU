// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 tees
 *
 * selinux_spoof: avc 审计日志伪造 (独立于 selinux_hide 的开关)。
 *
 * 应用触发涉及 ksu 域的 avc 审计时, dmesg/logcat 里会出现
 * tcontext=u:r:ksu:s0, 暴露 root 域。kprobe 挂 avc_audit_post_callback,
 * 在审计格式化前把 sad->tsid 从 ksu_sid 替换为 priv_app_sid
 * (经 security_sid_to_context 惰性解析并缓存)。
 *
 * 注意: 本 feature 不做 avd allowed 伪装——在 context_struct_compute_av
 * 层修改 avd 会污染 avc 全局缓存 (app 查询 "ksu 域对 X" 的 deny 结果被
 * 缓存后, root 的 ksu 进程访问 X 也会命中 deny), 已实测导致 root 权限
 * 受限。access 查询伪装由 selinux_hide 的 backup 策略重定向覆盖。
 *
 * 行为由 KSU_FEATURE_SELINUX_SPOOF 开关控制(默认关闭)。卸载 kernel 时
 * 注销探针恢复。
 */

#include "selinux_spoof.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#include "arch.h"
#include "klog.h"

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/ptrace.h>

// security/selinux/include/avc.h (see kernel/Kbuild -I paths)
#include "avc.h"

static bool ksu_selinux_spoof_enabled __read_mostly = false;

static struct kprobe kp_avc_audit;

static u32 ksu_sid = (u32)-1;
static u32 priv_app_sid = (u32)-1;

static int avc_audit_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct common_audit_data *ad;
    struct selinux_audit_data *sad;

    if (unlikely(!ksu_selinux_spoof_enabled))
        return 0;

    ad = (struct common_audit_data *)PT_REGS_PARM2(regs);
    if (!ad)
        return 0;
    sad = ad->selinux_audit_data;
    if (!sad)
        return 0;

    /* 惰性解析 sid: 首次遇到 ksu/priv_app 的 tsid 时缓存 */
    if (ksu_sid == (u32)-1 || priv_app_sid == (u32)-1) {
        char *ctx = NULL;
        u32 len = 0;

        if (sad->tsid == ksu_sid || sad->tsid == priv_app_sid)
            goto check;
        if (security_sid_to_context(sad->tsid, &ctx, &len) == 0) {
            if (strcmp(ctx, "u:r:ksu:s0") == 0)
                ksu_sid = sad->tsid;
            else if (strncmp(ctx, "u:r:priv_app:", 13) == 0)
                priv_app_sid = sad->tsid;
            kfree(ctx);
        }
    }

check:
    if (sad->tsid == ksu_sid && priv_app_sid != (u32)-1)
        sad->tsid = priv_app_sid; /* 审计日志中 ksu 域显示为 priv_app */
    return 0;
}

static int ksu_selinux_spoof_feature_get(u64 *value)
{
    *value = ksu_selinux_spoof_enabled ? 1 : 0;
    return 0;
}

static int ksu_selinux_spoof_feature_set(u64 value)
{
    ksu_selinux_spoof_enabled = value != 0;
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
    kp_avc_audit.symbol_name = "avc_audit_post_callback";
    kp_avc_audit.pre_handler = avc_audit_pre;
    if (register_kprobe(&kp_avc_audit)) {
        pr_warn("selinux_spoof: avc_audit_post_callback not available, disabled\n");
        kp_avc_audit.symbol_name = NULL;
        return 0;
    }

    ksu_register_feature_handler(&selinux_spoof_handler);
    pr_info("selinux_spoof: active (avc log spoofing)\n");
    return 0;
}

void __exit ksu_selinux_spoof_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_SPOOF);
    if (kp_avc_audit.symbol_name) {
        unregister_kprobe(&kp_avc_audit);
        kp_avc_audit.symbol_name = NULL;
    }
    pr_info("selinux_spoof: deactivated\n");
}
