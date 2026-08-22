package me.weishu.kernelsu.data.fakelock

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.ui.util.getRootShell

/**
 * 伪装 BL 锁状态 (仿 FolkPatch fpd -hide 的守护进程集成方式)
 *
 * 全部逻辑由 ksud fakelock 子命令原生实现: 属性伪装走 ksud 内置
 * resetprop API (只改已存在属性, 绝不创建), 内核 /proc/bootconfig
 * 伪装 (KSU_FEATURE_BOOTCONFIG_HIDE) 与属性伪装同开同关, 重启后由
 * ksud 的 post-fs-data 钩子自动重放。此处仅负责调用与状态读取。
 */
class FakeLockRepository {
    companion object {
        const val KSUD = "/data/adb/ksud"
        const val FLAG_FILE = "/data/adb/ksu/.fakelock_enabled"
    }

    /** 是否已启用 (ksud 的持久化标志) */
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

    /**
     * 启用/禁用。启用后立即生效 (属性+bootconfig 同步伪装);
     * 禁用后已伪装的属性在下一次重启恢复真实值。
     */
    suspend fun setEnabled(enabled: Boolean) = withContext(Dispatchers.IO) {
        val shell = getRootShell()
        shell.newJob()
            .add("$KSUD fakelock ${if (enabled) "enable" else "disable"}")
            .exec()
    }
}
