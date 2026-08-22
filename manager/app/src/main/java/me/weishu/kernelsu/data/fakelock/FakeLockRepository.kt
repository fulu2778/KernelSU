package me.weishu.kernelsu.data.fakelock

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.ui.util.getRootShell

/**
 * 伪装 BL 锁状态 (仿 FolkPatch fpd -hide / 8e_fake_lock.sh)
 * 通过 resetprop 隐藏 bootloader 解锁状态
 */
class FakeLockRepository {
    companion object {
        const val FLAG_FILE = "/data/adb/ksu/fakelock/enabled"
        const val RESETPROP = "/data/adb/ksu/bin/resetprop"

        // 属性伪装列表 (FolkPatch prop_patch + 8e_fake_lock)
        val PATCH_LIST = listOf(
            "ro.boot.vbmeta.device_state" to "locked",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.veritymode" to "enforcing",
            "vendor.boot.vbmeta.device_state" to "locked",
            "vendor.boot.verifiedbootstate" to "green",
            "ro.boot.vbmeta.invalidate_on_error" to "yes",
            "ro.boot.vbmeta.avb_version" to "1.0",
            "ro.boot.vbmeta.hash_alg" to "sha256",
            "ro.boot.vbmeta.size" to "4096",
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
    }

    /** 是否已启用 (标志文件存在) */
    suspend fun isEnabled(): Boolean = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val out = shell.newJob()
                .add("test -f $FLAG_FILE && echo yes").to(ArrayList<String>(), null).exec().out
            out.firstOrNull()?.trim()?.contains("yes") == true
        } catch (_: Exception) {
            false
        }
    }

    /** 启用/禁用伪装 */
    suspend fun setEnabled(enabled: Boolean) = withContext(Dispatchers.IO) {
        val shell = getRootShell()
        val job = shell.newJob()
            .add("mkdir -p /data/adb/ksu/fakelock")
        if (enabled) {
            // 合并成单条 shell 链, 空值属性跳过 (会破坏 shell 命令)
            val cmds = PATCH_LIST
                .filter { it.second.isNotBlank() }
                .map { "$RESETPROP -n \"${it.first}\" \"${it.second}\"" }
                .joinToString(" && ")
            job.add(cmds)
            job.add("touch $FLAG_FILE")
        } else {
            job.add("rm -f $FLAG_FILE")
        }
        job.exec()
    }
}
