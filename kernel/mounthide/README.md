# Mounthide

Hide KernelSU module mounts from `/proc` mounts output via a lightweight LKM.

通过轻量 LKM 在内核输出层将 KernelSU 模块挂载从 `/proc` 挂载输出中隐藏。

## What it does / 作用

Intercepts the kernel callbacks behind `/proc` mounts files and drops mount
entries whose **root path** matches `/adb/modules` (configurable), uniformly
for **all processes** — module mounts keep working, but no process can ever
see them.

拦截 `/proc` 挂载文件底层的内核回调，对**所有进程统一**地丢弃**根路径**命中
`/adb/modules`（可配置）的挂载条目——模块挂载功能照常生效，但没有任何
进程能看到它。

## How it works / 原理

```
register_kprobe x3
  ├─ show_mountinfo  (/proc/*/mountinfo)
  ├─ show_vfsmnt     (/proc/*/mounts)
  └─ show_vfsstat    (/proc/*/mountstat)
       └─ pre_handler: dentry_path_raw(mnt_root) 前缀命中
            → regs->pc = trampoline (return 0)
            → 该行静默消失
```

Equivalent to susfs's mount hiding, but pure LKM — no kernel source changes.

与 susfs 的挂载隐藏行为等价，但纯 LKM 实现，不改内核源码。

## Build / 构建

Same build environment as the official `kernelsu.ko` (DDK container,
CFI/KMI aligned):

与官方 `kernelsu.ko` 相同的构建环境（DDK 容器，CFI/KMI 对齐）：

```bash
podman run --rm -v "$PWD:/mnt/src" -w /mnt/src/kernel/mounthide \
  ghcr.io/ylarod/ddk-min:android15-6.6-20260313 sh -c '
    unset ARCH CROSS_COMPILE; export ARCH=arm64
    make -C /opt/ddk/kdir/android15-6.6 M=/mnt/src/kernel/mounthide modules
  '
```

Requires target kernel config: `CONFIG_KPROBES=y`, `CONFIG_KALLSYMS_ALL=y`,
`CONFIG_CFI_CLANG=y` (must match).

要求目标内核配置：`CONFIG_KPROBES=y`、`CONFIG_KALLSYMS_ALL=y`、
`CONFIG_CFI_CLANG=y`（必须与目标内核一致）。

## Usage / 使用

Manual / 手动：

```bash
su -c 'insmod /data/adb/ksu/modules/mounthide.ko'
su -c 'rmmod mounthide'                              # 卸载恢复
```

Parameter / 参数：

```bash
insmod mounthide.ko hide_prefix="/adb/modules;/data/your_path"   # 分号分隔多前缀
```

KernelSU module / KSU 模块：`mounthide-module.zip` 可由 KernelSU Manager
直接安装（`service.sh` 开机自动加载，失败不影响启动）。

## Verification / 验证

Tested on 6.6.118 GKI with PrivIsolated v1.1:

在 6.6.118 GKI / PrivIsolated v1.1 上实测：

| Item / 项 | Result / 结果 |
|---|---|
| `/proc/1/mountinfo` `/adb/` entries | 192 → **189**（仅隐藏 3 个 KSU 挂载）|
| System mounts / 系统挂载 | 无误伤 |
| **PrivIsolated v1.1** | **OK: Not found** |
| Module function / 模块功能 | 保留（仅输出层隐藏）|
| Rollback / 回滚 | `rmmod` 完全恢复 |

## License

GPL-2.0
