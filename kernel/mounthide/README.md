# Mounthide

Hide KernelSU module mounts from `/proc` mounts output via a lightweight LKM.

通过轻量 LKM 在内核输出层将 KernelSU 模块挂载从 `/proc` 挂载输出中隐藏。

---

## Abstract / 摘要

Mounthide is a Loadable Kernel Module (LKM) that intercepts the kernel
`show_mountinfo` / `show_vfsmnt` / `show_vfsstat` callbacks — the functions
behind `/proc/self/mountinfo`, `/proc/self/mounts` and `/proc/self/mountstat`
— and silently drops mount entries whose **mount root path** matches a
feature prefix (e.g. `/adb/modules`), for **all processes uniformly**.

Mounthide 是一个可加载内核模块（LKM），它拦截内核的 `show_mountinfo` /
`show_vfsmnt` / `show_vfsstat` 回调（即 `/proc/self/mountinfo`、
`/proc/self/mounts`、`/proc/self/mountstat` 三个 proc 文件底层的输出函数），
对**所有进程统一**地静默丢弃**挂载根路径**命中特征前缀（如 `/adb/modules`）
的挂载条目。

| 特性 | 说明 |
|---|---|
| 形态 | 独立 LKM (`mounthide.ko`)，不修改内核源码 |
| 机制 | `kprobe` ×3 拦截 seq_file show 回调 |
| 判据 | `dentry_path_raw(mnt_root)` 前缀匹配（默认 `/adb/modules`，可配） |
| 生效范围 | 所有进程视图一致（mountinfo/mounts/mountstat 三件套） |
| 兼容性 | 与官方 `kernelsu.ko` 同款 DDK 构建环境（CFI/KMI 对齐） |
| 回滚 | `rmmod mounthide` 即恢复 |

---

## 1. Background / 背景

KernelSU module mounts are real kernel mounts. On this device the leaking
line in `/proc/1/mountinfo` was:

KernelSU 模块挂载是真实的内核挂载。本机检测暴露的挂载行为：

```
357 176 254:63 /adb/modules/add_aod_fullscreen/system/product/etc/device_features/annibale.xml /product/etc/device_features/annibale.xml ro,noatime shared:69 - f2fs /dev/block/dm-63 rw,lazytime...
```

It was flagged by **PrivIsolated** (LSPosed, `org.lsposed.privisolated`,
v1.0/v1.1) with:

该挂载被 **PrivIsolated** 检测报告：

```
WARN: /dev/block/dm-63 /adb/modules/add_aod_fullscreen/... /product/etc/device_features/annibale.xml f2fs ...
```

### 1.1 Detector internals / 检测器原理

Detector logic (from jADX decompilation of the APK and the open-source repo
`LSPosed/Privisolated`, `PrivIsolatedService.java`):

检测逻辑（来自 APK 反编译与开源仓库源码）：

```java
// readProc(), running in an isolated process (bindIsolatedService)
for (each numeric dir in /proc):
    infos = scan(pid + "/mountinfo")
    optional = infos.get(0).optional();            // propagation flag
    if (optional.startsWith("shared")) expected |= 1;
    else if (optional.startsWith("master")) expected |= 2;
    for (info in infos):
        str = source + root + point + type + options + superOptions
        if (str contains "magisk" || "KSU" || "/adb/"):
            return "WARN: " + str;                 // feature hit => instant WARN
        builder.append(str)
    set.add(builder.toString())
if (set.size() != Integer.bitCount(expected))
    return "WARN: Found hidden mount points"      // view divergence => WARN
else return "OK: Not found"
```

Two detection surfaces:

两层检测面：

1. **特征 grep**：任意进程的 mountinfo 内出现
   `magisk` / `KSU` / `/adb/` 子串 → 立即 `WARN: <该行>`（本机触发的就是这一条）
2. **视图一致性**：所有进程的挂载视图去重后的种数与期望值
   （`bitCount(shared|1, master|2)`）不符 → `WARN: Found hidden mount points`

### 1.2 Isolated process / 隔离进程

Android isolated processes share the global mount namespace and the global
`/proc` view (they are uid-isolated, not namespace-isolated). The detector
deliberately runs inside one, giving it a full-device mountinfo read without
any privileges — this is the root of why any process-level detector can see
module mounts.

Android 隔离进程共享全局挂载命名空间与全局 `/proc` 视图（它们只做 uid
隔离，不做命名空间隔离）。检测器故意运行在隔离进程内，无任何特权即可
读取全设备挂载视图——这就是任何进程级检测器都能看到模块挂载的根本原因。

---

## 2. Root cause / 根因

| 层 | 事实 |
|---|---|
| Linux | 挂载一旦存在，`show_mountinfo` 就必须输出它；**没有任何"隐藏挂载"标志** |
| KSU 模块 | 模块生效 = 真实内核 mount；挂载根路径必定含 `/adb/modules/`（模块仓库路径） |
| Android | isolated process 天然拥有全局挂载视图（设计如此，修复即破坏隔离语义） |

结论：**只要模块挂载存在，任何能读 mountinfo 的进程都能看到它**。
要"保留挂载功能 + 检测不可见"，唯一根本手段是**输出层过滤**
（susfs 正是如此：`if (mnt_id >= DEFAULT_KSU_MNT_ID) return 0;`）。

---

## 3. Design / 方案

### 3.1 Mechanism / 机制

```
ksud / service.sh 加载 mounthide.ko
  └─ register_kprobe × 3
       ├─ show_mountinfo  (/proc/*/mountinfo)
       ├─ show_vfsmnt     (/proc/*/mounts)
       └─ show_vfsstat    (/proc/*/mountstat)
            └─ pre_handler: dentry_path_raw(mnt_root) 前缀命中特征
                 → regs->pc = trampoline (直接 return 0)
                 → 该挂载行对所有进程静默消失
```

Resembling susfs semantics:

与 susfs 语义一致：

| susfs（源码级） | mounthide（纯 LKM） |
|---|---|
| 改写 `mounts_open_common` 分支切换 show 函数 | kprobe 拦截 show 函数 |
| 用 mnt_id 阈值（`DEFAULT_KSU_MNT_ID=2000000000`，需改 ida 分配器） | 用挂载根路径特征前缀（无需改分配器） |

### 3.2 Why dentry_path_raw / 为什么用 dentry_path_raw

Getting the same string the kernel prints as the mountinfo `root` field
(field 4) is not as simple as it looks:

拿到与 mountinfo `root` 字段（第 4 字段）完全相同的内容并不简单：

| API | 语义 | 导出？ | 可用 |
|---|---|---|---|
| `d_path(&path)` | 走**全局路径**（跨挂载边界）→ 返回**挂载点**路径（如 `/product/...`），不是 root 字段 | ✅ | ✗ 判据失配 |
| `dentry_path()` | 沿 dentry 链（= root 字段语义） | ❌ **未导出** → `Unknown symbol (err -2)` | ✗ 链接失败 |
| `dentry_path_raw()` | 同 `dentry_path` 语义 | ✅ `EXPORT_SYMBOL` | ✅ 正确 |

> `d_path` 在 kprobe 中返回的是挂载点全路径（跨了挂载边界），因此用它对
> `/adb/modules` 前缀匹配永远失败；`dentry_path` 语义正确但未导出，模块
> 引用它会导致 `init_module` 返回 `ENOENT`（`err -2`）。`dentry_path_raw`
> 二者兼顾。

### 3.3 kprobe trampoline / 跳板语义

```c
static int mounthide_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct vfsmount *mnt = (struct vfsmount *)regs->regs[1];  // x1 = mnt (arm64)
    if (mnt && mnt_root_matches(mnt)) {
        regs->pc = (unsigned long)mounthide_skip_show;        // 跳到 trampoline
        return 1;                                             // 跳过原函数单步
    }
    return 0;
}

static int mounthide_skip_show(struct seq_file *m, struct vfsmount *mnt)
{
    return 0;   // seq_file 语义: 当前条目不输出, 继续下一行
}
```

`pre_handler` 返回非 0 会跳过被探测指令的单步执行；配合改写 `regs->pc`
把执行流重定向到 trampoline，trampoline 按调用约定直接 `return 0`（seq
迭代器语义：该条目不输出）。

---

## 4. Build environment / 构建环境

Build with the **same DDK container** as the official KernelSU LKM
(`.github/workflows/ddk-lkm.yml`):

使用与官方 KernelSU LKM 相同的 DDK 容器构建：

```
ghcr.io/ylarod/ddk-min:android15-6.6-20260313
    /opt/ddk/kdir/android15-6.6    (预构建 ARM64 内核树: .config/Module.symvers/vmlinux)
    /opt/ddk/src/android15-6.6     (内核源码)
    /opt/ddk/clang/clang-r510928   (官方 clang 18 工具链)
```

```bash
podman run --rm -v "$PWD:/mnt/src" -w /mnt/src/kernel/mounthide \
  ghcr.io/ylarod/ddk-min:android15-6.6-20260313 sh -c '
    unset ARCH CROSS_COMPILE
    export ARCH=arm64
    export KDIR=/opt/ddk/kdir/android15-6.6
    make -C $KDIR M=/mnt/src/kernel/mounthide modules
  '
```

Key config of the DDK tree (must match the target GKI kernel):

DDK 树的关键配置（必须与目标 GKI 内核一致）：

```kconfig
CONFIG_CFI_CLANG=y        # KCFI — 模块必须 CFI 编译, 否则 kprobe 回调 panic
CONFIG_KPROBES=y          # kprobe 机制
CONFIG_KALLSYMS_ALL=y     # kallsyms(show_mountinfo 等 static 符号可见)
CONFIG_MODULES=y
```

---

## 5. Lessons learned / 排坑记录

### 5.1 CFI panic (deadliest)

非 CFI 编译的模块加载到 `CONFIG_CFI_CLANG=y` 内核，**kprobe 机制间接调用
`pre_handler` 时 CFI 校验失败** → 立刻 panic：

```
Kernel panic - not syncing: Oops - CFI: Fatal exception
```

手机黑盒日志（pstore/blackbox 分区）证实 2026-08-22 5:14 那次 panic 即源此。
**规则：目标内核实开 CFI 时，模块必须用与内核一致的 CFI 配置编译
（官方 DDK 树已包含）**

### 5.2 kprobe regs 语义

- arm64：`x0=seq_file*`, `x1=vfsmount*`（`regs->regs[0/1]`）；指令指针是
  `regs->pc`（不是 x86 的 `ip`）
- `register_kprobe` 的 `symbol_name` 可直接找 static 符号（如 `show_mountinfo`），
  无需依赖 `kallsyms_lookup_name` 导出

### 5.3 符号导出 vs kallsyms 可见

`/proc/kallsyms`（KALLSYMS_ALL）能看到**未导出**符号，但模块链接/加载时
内核只允许引用 `EXPORT_SYMBOL*` 的符号。模块引用未导出符号时 `insmod`
报 `No such file or directory`（内核侧 `err -2`/ENOENT，dmesg：
`Unknown symbol xxx (err -2)`），**很容易被误判为路径/文件问题**。

---

## 6. Usage / 使用

### 6.1 Manual / 手动

```bash
su -c 'insmod /data/adb/ksu/modules/mounthide.ko'
su -c 'rmmod mounthide'                      # 卸载回滚
su -c 'grep adb /proc/1/mountinfo'           # 应无 /adb/modules 条目
```

Optional module parameter / 可选参数：

```bash
insmod mounthide.ko hide_prefix="/adb/modules;/data/ksu_data"   # 分号分隔多前缀
```

### 6.2 KernelSU Module / KSU 模块安装

Package as a standard KernelSU module (zip installable via KernelSU Manager):

打包为标准 KernelSU 模块（KernelSU Manager 可直接安装）：

```
mounthide-module/
├── module.prop          # id/name/version/description
├── service.sh           # post-boot insmod (失败自动忽略, 不影响启动)
└── mounthide.ko         # LKM 产物
```

### 6.3 Verification / 验证结果

实测（6.6.118 GKI / KernelSU 内嵌内核 / PrivIsolated v1.1）：

| 验证项 | 结果 |
|---|---|
| `/proc/1/mountinfo` 中 `/adb/` 挂载条目 | 192 → **189 行**（仅隐藏 3 个 KSU 挂载：add_aod_fullscreen、zygisk_lsposed dex2oat ×2）|
| 系统挂载误伤 | 无（`adbd`/`usb-ffs`/`debugfs` 等正常保留）|
| **PrivIsolated v1.1** | **`OK: Not found`** |
| 模块功能保留 | 挂载仍然存在（仅输出层隐藏），模块内容对系统继续生效 |
| 回滚 | `rmmod` 后完全恢复，无残留 |

### 6.4 Limitations / 局限

- 判据是挂载**根路径前缀**匹配：模块挂载根路径若被改到不含特征前缀的
  路径，检测器仍然可见（但那样特征 grep 本身就不命中了 —— 语义上是
  "内容侧改为无特征路径"，是另一条对抗路径）
- 只覆盖 `/proc` 的 mountinfo/mounts/mountstat 三个输出面；
  fdinfo/maps 等其他泄露面未覆盖（可扩展同样的 kprobe 手法）
- 依赖 `CONFIG_KPROBES` / `CONFIG_KALLSYMS_ALL` / CFI 配置与目标内核一致
- 非 GKI 官方工具的客户内核（如 OEM 深度魔改）符号可能不同，需按机型适配

---

## 7. Files / 文件清单

| 路径 | 说明 |
|---|---|
| `kernel/mounthide/mounthide.c` | 模块源码（kprobe ×3 + 判据 + trampoline + 参数）|
| `kernel/mounthide/Makefile` | 独立构建入口（KDIR 指向 DDK 树）|
| `kernel/mounthide/README.md` | 本文档 |
| `mounthide-module.zip` | 打包好的 KernelSU 模块（Manager 可装）|

## 8. License

GPL-2.0（内核模块惯例）。
