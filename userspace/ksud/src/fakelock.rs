// SPDX-License-Identifier: GPL-2.0-only
/*
 * ksud fakelock: 伪装 BL 锁状态 (参照 FolkPatch fpd prop_patch 的守护进程集成)
 *
 * 通过 ksud 内置的 resetprop API 在进程内完成属性伪装, 不依赖外部
 * 脚本或 resetprop 二进制。开关状态持久化于 /data/adb/ksu/.fakelock_enabled,
 * post-fs-data 阶段自动重放 (resetprop 改的是内存属性, 重启即失效)。
 * 内核侧 /proc/bootconfig 伪装 (KSU_FEATURE_BOOTCONFIG_HIDE) 与属性
 * 伪装同开同关, 保证 getprop 与 bootconfig 交叉比对永远一致。
 *
 * 与 FolkPatch fpd/src/prop_patch.rs 保持逐条一致的语义 (该实现已验证
 * 不触发属性区结构检测):
 * - 只修改设备上已存在的属性, 绝不创建
 * - 空值条目设为空串而非删除——删除会在属性区留下空洞, 正是
 *   "Property Modified" 类检测的靶点
 * - bootmode 含 recovery 时改写为 unknown
 */

use anyhow::{Context, Result};
use const_format::concatcp;
use log::{info, warn};
use std::fs;
use std::path::Path;

use crate::defs;
use crate::feature::{FeatureId, set_kernel_feature};
use prop_rs_android::resetprop::ResetProp;
use prop_rs_android::sys_prop;

const FLAG_PATH: &str = concatcp!(defs::WORKING_DIR, ".fakelock_enabled");

/// (属性, 伪装值)。值与 FolkPatch fpd PATCH_LIST 逐条一致;
/// 空串 = 设为空值 (不是删除)。
const FAKE_PROPS: &[(&str, &str)] = &[
    ("ro.boot.vbmeta.device_state", "locked"),
    ("ro.boot.verifiedbootstate", "green"),
    ("ro.boot.flash.locked", "1"),
    ("ro.boot.veritymode", "enforcing"),
    ("vendor.boot.vbmeta.device_state", "locked"),
    ("vendor.boot.verifiedbootstate", "green"),
    ("ro.boot.vbmeta.invalidate_on_error", "yes"),
    ("ro.boot.vbmeta.avb_version", "1.0"),
    ("ro.boot.vbmeta.hash_alg", "sha256"),
    ("ro.boot.vbmeta.size", "4096"),
    ("ro.boot.warranty_bit", "0"),
    ("ro.warranty_bit", "0"),
    ("ro.vendor.boot.warranty_bit", "0"),
    ("ro.vendor.warranty_bit", "0"),
    ("sys.oem_unlock_allowed", "0"),
    ("ro.build.type", "user"),
    ("ro.build.tags", "release-keys"),
    ("ro.secureboot.lockstate", "locked"),
    ("ro.debuggable", "0"),
    ("ro.force.debuggable", "0"),
    ("ro.secure", "1"),
    ("ro.adb.secure", "1"),
    ("ro.boot.realmebootstate", "green"),
    ("ro.boot.realme.lockstate", "1"),
    ("persist.logd.size", ""),
    ("persist.logd.size.crash", ""),
    ("persist.logd.size.system", ""),
    ("persist.logd.size.main", ""),
];

/// bootmode 伪装 (FolkPatch patch_boot_keys)。
const BOOT_KEYS: &[&str] = &["ro.bootmode", "ro.boot.bootmode", "vendor.boot.bootmode"];

const fn make_rp() -> ResetProp {
    ResetProp {
        skip_svc: true,
        persistent: false,
        persist_only: false,
        verbose: false,
        show_context: false,
        rebuild: false,
    }
}

pub fn is_enabled() -> bool {
    Path::new(FLAG_PATH).exists()
}

fn apply_props() -> Result<()> {
    sys_prop::init().context("Failed to initialize system property API")?;
    let rp = make_rp();

    let mut set = 0usize;
    for (name, value) in FAKE_PROPS {
        // 只改已存在的属性, 绝不创建; 空值 = 设为空串 (保持属性区无空洞)
        if rp.get(name).is_some() {
            match rp.set(name, value) {
                Ok(()) => set += 1,
                Err(e) => warn!("fakelock: set {name} failed: {e}"),
            }
        }
    }
    for key in BOOT_KEYS {
        if let Some(val) = rp.get(key)
            && val.contains("recovery")
            && let Err(e) = rp.set(key, "unknown")
        {
            warn!("fakelock: patch bootmode {key} failed: {e}");
        }
    }
    info!("fakelock: applied disguise to {set} props");
    Ok(())
}

/// 启用: 写标志 + 属性伪装立即生效 + 内核 bootconfig 伪装同开。
/// 禁用后已伪装的属性在下一次重启恢复真实值。
pub fn enable() -> Result<()> {
    fs::write(FLAG_PATH, b"1").with_context(|| format!("write {FLAG_PATH}"))?;
    apply_props()?;
    set_kernel_feature(FeatureId::BootconfigHide, 1)?;
    info!("fakelock: enabled");
    Ok(())
}

/// 禁用: 移除标志 + 内核 bootconfig 伪装同关。
pub fn disable() -> Result<()> {
    let _ = fs::remove_file(FLAG_PATH);
    set_kernel_feature(FeatureId::BootconfigHide, 0)?;
    info!("fakelock: disabled (props revert on next reboot)");
    Ok(())
}

pub fn status() {
    println!(
        "FakeLock: {}",
        if is_enabled() { "enabled" } else { "disabled" }
    );
    println!("Flag: {FLAG_PATH}");
}

/// post-fs-data 钩子: resetprop 是内存属性, 每次开机重放;
/// feature 同步重设, 与标志保持一致。
pub fn on_post_fs_data() {
    if !is_enabled() {
        return;
    }
    if let Err(e) = apply_props() {
        warn!("fakelock: replay props failed: {e}");
    }
    if let Err(e) = set_kernel_feature(FeatureId::BootconfigHide, 1) {
        warn!("fakelock: ensure bootconfig_hide failed: {e}");
    }
    info!("fakelock: replayed at post-fs-data");
}
