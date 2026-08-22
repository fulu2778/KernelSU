package me.weishu.kernelsu.data.fakelock

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.ui.util.getRootShell

/**
 * 伪装 BL 锁状态 (仿 FolkPatch fpd -hide / 8e_fake_lock.sh)
 *
 * 开关状态与 post-fs-data.d 开机脚本合一：脚本存在即启用。
 * resetprop 修改的是内存属性，重启即失效，因此每次开机由
 * ksud 执行 post-fs-data.d 脚本重新伪装，早于任何应用启动。
 */
class FakeLockRepository {
    companion object {
        const val SCRIPT = "/data/adb/post-fs-data.d/fakelock.sh"
        const val RESETPROP = "/data/adb/ksu/bin/resetprop"

        // 属性伪装列表 (FolkPatch prop_patch + 8e_fake_lock)。
        // 运行时只修改设备上已存在的属性, 绝不创建——在错误的机型上
        // 出现本不该存在的属性本身就是指纹。
        // 注意: 不伪造 avb_version/vbmeta.size 等值——它们全机型存在但
        // 不指示锁状态, 且工具硬编码的伪值(1.0/4096)是已知指纹。
        // value 为空串表示: 属性存在则删除 (resetprop -d)。
        val PATCH_LIST = listOf(
            "ro.boot.vbmeta.device_state" to "locked",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.veritymode" to "enforcing",
            "vendor.boot.vbmeta.device_state" to "locked",
            "vendor.boot.verifiedbootstate" to "green",
            "ro.boot.warranty_bit" to "0",
            "ro.warranty_bit" to "0",
            "ro.vendor.boot.warranty_bit" to "0",
            "ro.vendor.warranty_bit" to "0",
            "sys.oem_unlock_allowed" to "0",
            "ro.build.type" to "user",
            "ro.build.tags" to "release-keys",
            "ro.secureboot.lockstate" to "locked",
            "ro.debuggable" to "0",
            "ro.force.debuggable" to "0",
            "ro.secure" to "1",
            "ro.adb.secure" to "1",
            "ro.boot.realmebootstate" to "green",
            "ro.boot.realme.lockstate" to "1",
            "persist.logd.size" to "",
            "persist.logd.size.crash" to "",
            "persist.logd.size.system" to "",
            "persist.logd.size.main" to "",
        )

        private fun scriptBody(): String = buildString {
            append("#!/system/bin/sh\n")
            append("# KernelSU FakeLock: disguise bootloader as locked. Managed by Manager; do not edit.\n")
            append("# only touch props that already exist; never create new ones\n")
            append("RP=$RESETPROP\n")
            append("sp() { [ -n \"$(\"$RP\" \"$1\" 2>/dev/null)\" ] && \"$RP\" -n \"$1\" \"$2\" >/dev/null 2>&1; }\n")
            append("dp() { [ -n \"$(\"$RP\" \"$1\" 2>/dev/null)\" ] && \"$RP\" -d \"$1\" >/dev/null 2>&1; }\n")
            for ((name, value) in PATCH_LIST) {
                if (value.isEmpty()) {
                    append("dp \"$name\"\n")
                } else {
                    append("sp \"$name\" \"$value\"\n")
                }
            }
            append("exit 0\n")
        }
    }

    /** 是否已启用 (开机脚本存在) */
    suspend fun isEnabled(): Boolean = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val out = shell.newJob()
                .add("test -f $SCRIPT && echo yes").to(ArrayList<String>(), null).exec().out
            out.firstOrNull()?.trim()?.contains("yes") == true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 启用: 写入开机脚本并立即生效; 禁用: 删除脚本.
     * 禁用后已伪装的属性在下一次重启恢复真实值.
     */
    suspend fun setEnabled(enabled: Boolean) = withContext(Dispatchers.IO) {
        val shell = getRootShell()
        if (enabled) {
            val b64 = Base64.encodeToString(scriptBody().toByteArray(), Base64.NO_WRAP)
            shell.newJob()
                .add("mkdir -p /data/adb/post-fs-data.d")
                // base64 中转, 避免引号/换行被 shell 展开破坏
                .add("echo $b64 | base64 -d > $SCRIPT")
                .add("chmod 700 $SCRIPT")
                .add("sh $SCRIPT") // 立即生效, 无需重启
                .exec()
        } else {
            shell.newJob()
                .add("rm -f $SCRIPT")
                .exec()
        }
    }
}
