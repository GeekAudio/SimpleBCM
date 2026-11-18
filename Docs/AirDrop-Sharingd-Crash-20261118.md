# AirDrop / sharingd 崩溃（exit 139）根因报告

- 日期：2026-11-18
- 机器：Mac15,14，macOS 27.2（26B123，Darwin 27.2.0 x86_64）
- 对象：`/usr/libexec/sharingd`（a2x 宿主，`Identifier=.a2xhost-mac`、`Signature=adhoc`，sha256 `456e86a98dc0fb21c0b48493650e76ca11caa935684c40dfc1fc1830d797f657`）
- 源码：`liberator-devkit/src/interpreter/candidate/interp`（r27，host.c 319 KB）
- 结论一句话：**崩溃不是 launchd 的 `EnableTransactions`/`POSIXSpawnType=Interactive`/`EnablePressuredExit=false` 造成的，而是 ControlCenter 每次查询 AirDrop 可发现性时触发的一条 Swift Concurrency 异步任务返回路径；a2x 的 native→guest 蹦床在 guest 异步函数“返回时 sp 反而下移 16 字节”的情况下仍按普通/异步弹出量修正 x86 栈，导致 `swift_job_runImpl` 的返回槽被错位，最终 `ret` 到 0（SIGSEGV，rip=0）。**

---

## 0. 证据摘要（先看这一段）

| 证据 | 内容 |
|---|---|
| launchd 日志 | `exited due to exit(139)`（不是 `signal 11`）——说明是 a2x 的 ship 故障处理器捕获 SIGSEGV 后 `_exit(139)`，不是 launchd 杀死 |
| 触发者 | 每次崩溃前 10–20 ms 都有 `Invocation [_TtCO7Sharing20SFAirDropInvocations24AvailableDiscoverability:com.apple.controlcenter:<pid>] END -- Daemon` |
| 崩溃环起点 | 2026-11-18 14:29:13（3 小时 launchd 日志中第一条 exit 139）；此前 sharingd 根本没在运行（`failed lookup ... No such process`），14:29:00 一个临时 agent `local.sharingd.debug` 被加载，随即系统 job 被 `launching: ipc (mach)` 唤醒并在 13.6 s 后 exit 139 |
| 可重复性 | 自建同 Label、同 15 个 MachServices 的 LaunchAgent（程序为 `/tmp/sharingd.orig`，与系统文件逐字节相同）可稳定复现：`killall ControlCenter` 或 `open "airdrop://"` 后 1–2 s 内 exit 139；一次运行抓到 14 条 `a2x-stop` 记录 |
| ship 记录 | `FATAL: SIGSEGV / signal SIGSEGV fault 0x0`，**没有 guest pc、没有 frame**——因为故障发生在一个从未解释过 guest 代码的 native Swift 工作线程上，`a64_cur_state == NULL` |
| lab 记录（关键） | `native rip 0000000000000000`、`[rsp]=0x0`、`exc trapno 14 err 0x14 faultvaddr 0x0`；栈上可见 `swift_job_runImpl+0x8c`、`objc_autoreleasePoolPush+0x74`、dispatch root queue；崩溃前最后一行是 `[tramp] 0x1001c5e24: guest sp moved by -16 on return, ignored` |
| guest 0x1001c5e24 | 反汇编显示 `pacibsp; orr x29,x29,#0x1000000000000000; sub sp,sp,#0x80` —— 典型的 **Swift async 函数序言** |
| launchd 三键 | 用完全相同的 `EnableTransactions=true`、`POSIXSpawnType=Interactive`、`EnablePressuredExit=false`、同 Label、同 MachServices、同二进制副本做的对照 agent **稳定运行**；crash 只在 ControlCenter 真正把 invocation 送进来时发生 |

---

## 1. 基线：系统上到底是什么在崩

### 1.1 二进制与签名

```
/usr/libexec/sharingd: Mach-O universal binary with 3 architectures:
  [x86_64] [arm64e] [arm64e.x1]
Identifier=.a2xhost-mac
CodeDirectory v=20400 flags=0x2(adhoc)
Signature=adhoc
sha256 456e86a98dc0fb21c0b48493650e76ca11caa935684c40dfc1fc1830d797f657
```

x86_64 切片是 a2x host，arm64e 切片是真正的 sharingd（guest，已 strip，仅有导入符号）。
宿主自带 guest 的 139 项 entitlements（含 `com.apple.developer.hardened-process`、`com.apple.private.airdrop.client` 等），没有 `get-task-allow`。

### 1.2 系统 plist（只读，未修改）

`/System/Library/LaunchAgents/com.apple.sharingd.plist`：
`RunAtLoad=true`、`KeepAlive=true`、`EnablePressuredExit=false`、`EnableTransactions=true`、`POSIXSpawnType=Interactive`、`LimitLoadToSessionType=Aqua`、15 个 MachServices、无 `StandardErrorPath`/`StandardOutPath`。

### 1.3 exit 139 的真实含义

`launchctl print` 只显示 `last exit code = 139`，但 launchd 日志把它说清楚了：

```
2026-11-18 14:29:13.921 Df launchd[1:254b] [gui/501/com.apple.sharingd [2668]:]
    exited due to exit(139), ran for 13600ms
```

`exited due to exit(139)` = 进程自己调用 `_exit(139)`。这正是 `host.c` 中 ship 分支的故障处理器：

```c
/* host.c:2414-2418 */
a2x_stop_record(nm, 0, sig, si ? si->si_addr : 0, uc);
#if A2X_SHIP
    _exit(139);
#endif
```

所以 **a2x 确实捕获到了 SIGSEGV**，并且写了 `a2x-stop` 记录——只是记录去了我们看不到的地方。

### 1.4 为什么 `/var/tmp/a2x-reports/sharingd.log` 不存在

`a2x_report_to_file()`（host.c:1883-1915）只在 `fd 2` 是 `/dev/null` 时把 fd 2 重定向到 `/var/tmp/a2x-reports/<program>.log`。但同一个 `main()` 在更早的位置（host.c:4677-4679）已经做了这件事：

```c
if (getppid() == 1) {
    struct stat e2, dn;
    if (!fstat(2, &e2) && !stat("/dev/null", &dn) && e2.st_rdev == dn.st_rdev && S_ISCHR(e2.st_mode)) {
        int c = open("/dev/console", O_WRONLY | O_NOCTTY); if (c >= 0) { dup2(c, 2); ... }
    }
}
```

launchd 启动的 job（ppid=1）stderr 是 `/dev/null` → 被换成 `/dev/console`；等 `a2x_report_to_file()` 再看时 fd 2 已不是 `/dev/null`，于是**永远不会建报告文件**，`a2x-stop` 只写进了图形控制台（不可读、不落盘）。
这解释了“有崩溃、无 .ips、无报告文件”的全部现象：崩溃被 a2x 自己处理掉了，ReportCrash 根本没机会介入。

> 诊断改进建议（与崩溃修复独立）：`a2x_report_to_file()` 不应因为 fd 2 被换成 `/dev/console` 就放弃文件；至少要把记录同时写到 `/var/tmp/a2x-reports/<program>.log`，否则所有 launchd job 的崩溃记录都会丢失。

---

## 2. 触发条件：不是 launchd 三键，是 ControlCenter 的 XPC 调用

### 2.1 时间线（来自 3 小时 launchd 日志，`log show --last 3h --process launchd`）

```
14:28:38  a2xhost-mac[2494] / WiFiAgent[2507] 查询 com.apple.sharingd.nsxpc
          → failed lookup: No such process（sharingd 当时根本没运行）
14:28:58  launchd: This service is defined to be constantly running and is inherently inefficient.
          pending spawn, domain in on-demand-only mode: com.apple.sharingd
14:29:00  gui/501/local.sharingd.debug 被 bootstrap：
          The endpoint "com.apple.sharingd" ... already exists and is owned by: com.apple.sharingd
14:29:00  gui/501/com.apple.sharingd: launching: ipc (mach)   ← 客户端 lookup 把系统 job 唤醒
14:29:13  exited due to exit(139), ran for 13600ms            ← 第一条崩溃
14:29:13  Invocation [...AvailableDiscoverability:com.apple.controlcenter:2653] END -- Daemon
          （END 后 18 ms 进程退出）
...       此后 185+ 次 exit(139)，几乎每次都带同一条 invocation
15:16     把系统 job bootout + 用系统 plist 重新 bootstrap 后，实例稳定运行 10+ 分钟
15:27     killall ControlCenter（重启 CC）后，15:28 起崩溃环恢复
15:35     open "airdrop://" 后 ControlCenter 立刻再次查询 → 崩溃
15:44     最后一次系统 job 崩溃（34185）
```

崩溃环的每一帧都长这样（pid 12951，14:54:19）：

```
14:54:19.932  [com.apple.sharing:SDXPCServer] DeviceDiscoveryUpdate: SFDeviceDiscovery (CLink) ...
14:54:19.934  [com.apple.sharing:SFBLEScanner] [NearbyInfo] Starting scan ...
14:54:19.964  [com.apple.sharing:xpc] Invocation [...AvailableDiscoverability:com.apple.controlcenter:2653] START -- Daemon
14:54:19.971  [com.apple.sharing:xpc] Invocation [...AvailableDiscoverability:com.apple.controlcenter:2653] END -- Daemon
14:54:19.986  exited due to exit(139), ran for 1178ms
```

**结论：崩溃与 AirDrop 的 BLE 扫描本身无关**（当前稳定实例同样在扫描、同样有 `SFBLEScanner`，不崩），只与 ControlCenter 的 `SFAirDropInvocations.AvailableDiscoverability` 这条 NSXPC 调用相关。

### 2.2 用自建 agent 复现（无需 root、不改系统文件）

`/tmp/sharingd.orig` 是 `/usr/libexec/sharingd` 的逐字节副本（`cmp` 相同，sha256 同上）。用**相同 Label `com.apple.sharingd`**、相同 15 个 MachServices、相同 6 个键，加上 `StandardErrorPath` 的临时 agent 启动它：

- 稳定阶段：`runs=1, never exited`，可达 10+ 分钟；
- `killall ControlCenter` 或 `open "airdrop://"` 之后：1–2 s 内 `last exit code = 139`，`/tmp/diag-sys.err` 每次追加一条记录。

抓到 14 条 ship 记录，全部相同：

```
FATAL: SIGSEGV
a2x-stop: build a2x r27 cd14be8c macos 26B123 pid 30347
a2x-stop: program /tmp/sharingd.orig
a2x-stop: signal SIGSEGV fault 0x0
a2x-stop: end
```

没有 `guest pc`、没有 `frame`：`a2x_stop_record()` 只在 `pc || a64_cur_state` 时打印 guest pc/frame（host.c:2244-2277），而这次 `a64_cur_state == NULL`，且 ucontext 的 `rip == 0`，native frame 链从 `rbp` 一步都走不动。

### 2.3 排除 launchd 三键（对照实验）

| 实验 | Label | 键 | MachServices | 结果 |
|---|---|---|---|---|
| A 系统 job | com.apple.sharingd | 6 个键全有 | 15 个 | 崩（每次收到 invocation） |
| B 自建 job | com.apple.sharingd | 6 个键全有 | 15 个 | **稳定**（直到 invocation 到来才崩） |
| C 自建 job，不同 Label | com.a2x.diag.sharingd | 6 个键全有 | 15 个 | 稳定；但 stderr 明确 `Unable to bootstrap_check_in() ... appleid.aps`，即 **MachServices 被系统 job 占用，它根本没真正服务这些端口** |
| D 自建 job，不同 Label | local.sharingd.debug | 无三键 | 15 个 | 稳定；launchd 日志：所有 endpoint `already exists and is owned by: com.apple.sharingd` —— 同样是**假阴性** |

因此：

- `EnableTransactions` / `POSIXSpawnType=Interactive` / `EnablePressuredExit=false` **不是**本次崩溃的原因（B 全带也稳定；崩溃只由 invocation 触发）；
- 之前“临时 agent 稳定、系统 job 崩”的对照是**被 MachServices 所有权污染的假阴性**：临时 agent 换了 Label 后无法 check-in，永远不会收到 ControlCenter 的调用，当然不会崩；
- 反过来，14:29 那次 `local.sharingd.debug` 的加载/客户端 lookup 恰好把系统 job 唤醒，才点燃了持续 25 分钟的崩溃环。

---

## 3. 崩溃栈

### 3.1 ship 构建给不出栈的原因

- 故障地址 0、native rip 0；
- `a64_cur_state` 为空（该线程从未执行 guest 代码）；
- ucontext 的 `rbp` 链不可用，`[rsp]` 为 0；
- 记录格式本身只保留最多 8 native + 8 guest 帧，且完全依赖 `rbp` 链。

### 3.2 lab 构建（`mkhost-mac3.sh`，不设 `A2X_SHIP`）拿到的完整报告

构建命令（实际执行，成功）：

```bash
PATH=/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin:$PATH \
HOST_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX27.2.sdk \
HOST_LD_DIR=/Library/Developer/CommandLineTools/usr/bin \
HOST_MINOS=27.2 \
ARM2X86_LLVM=/Users/geek/Documents/Macintosh/a2x-work/llvmbin \
bash mkhost-mac3.sh /tmp/a2xlab/a2xhost-lab
```

产物先 `codesign -f -s - --entitlements <sharingd 的 entitlements>`（否则会在启动时因
`FindMyLocate/Session+Internal.swift:46: Fatal error: Missing entitlement: com.apple.findmy.findmylocate.settings`
提前 SIGILL），再作为**同 Label、同 MachServices** 的 LaunchAgent 程序运行（CLI 模式：`a2xhost-lab /usr/libexec/sharingd`）。
`killall ControlCenter` 后复现，`/tmp/lab.err` 全文：

```
objc_bridge: guest protocol SDXPCInterface carries NO extended method types (size 96) — an NSXPCInterface over it will raise
[tramp] 0x1001c5e24: guest sp moved by -16 on return, ignored
FATAL: SIGSEGV
a2x-stop: build a2x dev macos 26B123 pid 34683
a2x-stop: program /usr/libexec/sharingd
a2x-stop: signal SIGSEGV fault 0x0
a2x-stop: end

[host] SIGSEGV at guest pc 0x0 (insn 0x00000000), faulting address 0x0 | pid 34683 /usr/libexec/sharingd | pc in ?+0x0
[host]   native rip 0000000000000000 (? in ?)  rsp 00000001b9580e70
[host]   exc trapno 14 err 0x14 faultvaddr 0x0 si_code 1
[host]   [rsp]=0x0 rip_is_fstart=0 rip_in_text=0
[host]   frame0 0x0 ?+0x0 (?)
[host]   rax f00ffffffffffff rbx 62 rbp 7f91edb3a600 r8 30 r9 fffffffffffff000 r10 7ff85a691048 r11 7ff81fad6fde r15 7f91edb3a600 rflags 10202
[host]   stack[3] 0x7ff81ec8560c _ZL17swift_job_runImplPN5swift3JobENS_17SerialExecutorRefE+0x8c (/usr/lib/swift/libswift_Concurrency.dylib)
[host]   stack[9] 0x7ff81a761b01 objc_autoreleasePoolPush+0x74 (/usr/lib/libobjc.A.dylib)
[host]   stack[14] 0x7ff85a692fc0 _dispatch_root_queues+0x700 (/usr/lib/system/libdispatch.dylib)
[host]   stack[15] 0x7ff85a686ad0 _ZL16taskHeapMetadata+0x18 (/usr/lib/swift/libswift_Concurrency.dylib)
[host]   stack[17] 0x7ff81fb07dfa _dispatch_root_queue_drain.cold.4+0xe0 (/usr/lib/system/libdispatch.dylib)
[host]   stack[23] 0x7ff85a692ff0 _dispatch_root_queues+0x730 (/usr/lib/system/libdispatch.dylib)
[host]   stack[28] 0x7ff85a692fc0 _dispatch_root_queues+0x700 (/usr/lib/system/libdispatch.dylib)
[host]   stack[31] 0x7ff81fae591a _dispatch_root_queue_drain+0x54 (/usr/lib/system/libdispatch.dylib)
[host]   stack[33] 0x7ff85a692fc0 _dispatch_root_queues+0x700 (/usr/lib/system/libdispatch.dylib)
[host]   stack[35] 0x7ff81fae5dbc _dispatch_worker_thread2+0xb3 (/usr/lib/system/libdispatch.dylib)
[host]   stack[39] 0x7ff81a8af821 _pthread_wqthread+0xe9 (/usr/lib/system/libsystem_pthread.dylib)
[host]   stack[45] 0x7ff81a8ae85b start_wqthread+0xf (/usr/lib/system/libsystem_pthread.dylib)
[host]   type report: scanned 50 read 12 named 0
[host]   bytes@rip unreadable (rip 0x0)
[host]   rdi 0000000000000000 rsi 00007ff838b829ab rdx 00007ff85a691048 rcx 0000000000000000 r12 0000000000000000 r13 0000000000000000 r14 0000000000000000
[host] load stage: guest-running  image 0  index 0  /usr/libexec/sharingd
[host]   image 0 is /usr/libexec/sharingd
[host] faulting thread 0x1b9581000; the stage was published by thread 0x7ff85a644680 — A DIFFERENT THREAD, so guest pc 0 may only mean this thread never interpreted
```

### 3.3 关键帧解释

- **故障线程是 Swift Concurrency 工作线程**：`_dispatch_worker_thread2 → _dispatch_root_queue_drain → swift_job_runImpl → （这里出错）`。
  `swift_job_runImpl` 是 libswift_Concurrency 运行一个 Job 的函数：它取出 job 的 resume 函数指针并调用。
- **`[rsp] = 0`、`native rip = 0`、`trapno 14 err 0x14`**：不是空指针“调用”，而是控制流回到地址 0（`ret`/`jmp` 到了 0），栈顶那格是 0。
- **`[tramp] 0x1001c5e24: guest sp moved by -16 on return, ignored`**：崩溃前最后一次 native→guest 调用，guest 函数（地址 `0x1001c5e24`）返回时 `sp` 比进入时**低 16 字节**，a2x 认为这是非法值（`a2x_gpop > 64 || (a2x_gpop & 7)` 对无符号的 `-16` 成立）→ 直接 `a2x_gpop = 0` 忽略。
- **`0x1001c5e24` 的反汇编**（`lipo -thin arm64e` 后 `llvm-objdump`）：

```
1001c5e24: d503237f   pacibsp
1001c5e28: b24403bd   orr  x29, x29, #0x1000000000000000   ; Swift async frame 位
1001c5e2c: d10203ff   sub  sp, sp, #0x80
...        （保存 x27..x19、x29/x30，0x80 字节栈帧）
```

  这是**一个 Swift async 函数的入口**，不是普通函数。`swift_job_runImpl` 正是通过蹦床调用它来 resume 一个 async job。

---

## 4. 根因判定

### 4.1 因果链（按证据强度排序）

1. ControlCenter 通过 NSXPC 调 `com.apple.sharing.airdrop.service` 的
   `SFAirDropInvocations.AvailableDiscoverability`（日志 START/END，客户端 `com.apple.controlcenter`）。
2. sharingd 的 handler 把工作交给 Swift Concurrency（`Task`/async 续体），返回/reply 之后，libswift_Concurrency 在工作线程上 `swift_job_runImpl` 调用该 job 的 resume 函数。
3. a2x 蹦床进入 guest async 函数 `0x1001c5e24`；该函数返回时 guest `sp` 比进入时低 16 字节。
4. a2x 把该值当非法（无符号 `-16` > 64）清零，并仍按“普通返回 +8”/“async 弹出 area”修正 x86 栈（host.c:1759、1790-1800）。
5. `swift_job_runImpl` 的返回地址槽被错位；下一次 `ret` 取到 0 → `rip=0`，SIGSEGV（fault 0）。
6. ship 处理器把这次崩溃记成最小的 `a2x-stop` 并 `_exit(139)`；记录写到 `/dev/console`，丢失。launchd 只看到 `exit(139)`，ReportCrash 没有 .ips。

### 4.2 为什么不是 launchd 配置

第 2.3 节的 A/B/C/D 四组实验已经把三个键、路径、MachServices 数量、Aqua session 全部隔离：

- B 组（同 Label、同 15 个 MachServices、**三个键全带**、同二进制副本）在 invocation 到来前稳定运行 10+ 分钟；
- 只有真的收到 ControlCenter invocation 的实例才崩；
- 系统 job 被 bootout 再用**原系统 plist** bootstrap 后同样稳定，直到下一次 invocation。

因此 `EnableTransactions`/`POSIXSpawnType`/`EnablePressuredExit` 与本次 SIGSEGV 无因果关系；它们最多影响 job 的调度/节流，不影响 guest 异步返回的栈。

### 4.3 与已知 a2x 修复的关系

- host.c:1785-1789 已经记录过 sharingd 的同类问题：
  “A SWIFTTAILCC CALLEE POPS ITS WHOLE ARGUMENT AREA… sharingd: N = 16 -> 0x28; popping 8 left rsp 0x20 low and the job runner returned to 0 (exit 139 every launch).”
  那次是 **正方向**的弹出量（N=16）没算对；这次是 **负方向**（返回时 sp 下移 16），现有代码把负值直接忽略，仍然按固定规则加 8/area，等价地再次把 `job runner` 的返回地址算错。**同一个函数、同一类返回路径，只是符号相反。**
- host.c:1644-1649 也写明：Swift Concurrency 用 `callq *0x38(%r15)`（Job::ResumeTask）resume 任务，`[rsp]` 就是返回点；该注释说明这条路径已经被识别/特判过，但显然没有覆盖“guest 返回 sp 下移”的情形。

---

## 5. 修复方案

### 5.1 最小改动（a2x 源码，host.c）

**位置**：`a2x_cb_call()`（native→guest 蹦床的返回处），host.c:1740-1800。

现状：

```c
unsigned long a2x_gpop = xs[31] - asp;                 /* 1746 */
if (a2x_gpop > 64 || (a2x_gpop & 7)) {                 /* 1747：无符号，-16 变成巨大值 */
    fprintf(..., "guest sp moved by %ld on return, ignored\n", (long)a2x_gpop);
    a2x_gpop = 0;                                      /* 1749 */
}
...
ss->__rsp += 8;                                        /* 1759：弹出 return address */
...
if (a2x_async) {                                       /* 1791 */
    unsigned long argb = a2x_gpop ? a2x_gpop + 16 : 0; /* 1792 */
    unsigned long area = ((argb + 8 + 15) & ~15UL) - 8;
    ss->__rsp += area;                                 /* 1794 */
}
```

问题：`a2x_gpop` 是 `unsigned long`，`-16` 被当成非法值清零；随后仍按“async 至少弹 8 字节（area=8）”修正 x86 栈。
对于 `swift_job_runImpl` 的这次 call，native 侧并没有压入 guest 栈参数，多弹的 8 字节让调用者的返回槽错位。

建议的最小改动（先做诊断版，确认后再定稿）：

1. 用**有符号**差值：
   ```c
   long gdelta = (long)(xs[31] - asp);          /* guest 实际 sp 变化 */
   ```
2. `gdelta < 0` 时不要静默清零，而是打印并**不追加任何 async area**：
   ```c
   if (gdelta < 0) {
       fprintf(a2x_errf(), "[tramp] 0x%lx: guest sp moved DOWN by %ld (async resume?); no area added\n",
               tgt, -gdelta);
       gdelta = 0;
   }
   ...
   if (a2x_async) {
       unsigned long argb = (unsigned long)gdelta + 16u;
       unsigned long area = ((argb + 8 + 15) & ~15UL) - 8;
       ss->__rsp += area;
   }
   ```
   关键点是：**area 只在 guest 确实向上弹了（gdelta > 0）时才追加**；`gdelta == 0` 或负值时保留 `+8`（仅 return address），不要凭空再弹。
3. 同时把 `a2x_cb_async_return()`（host.c:1628）的判定扩展：当返回地址 `ret` 落在 `swift_job_runImpl` 的 `call` 之后、或 `[rsp]`/`[rsp+8]` 为 0 时，明确识别为 Job resume 返回，走上面的保守分支，并把 `tgt`、`gdelta`、`x30`、`[rsp]` 打到 stderr。

> 注意：第 3 步是定位用的；第 2 步是真正的行为改动。不要在未验证前同时改“async area = gdelta+16”这种激进公式——先把“负值不加 area”验证通过，再考虑更精确的布局。

### 5.2 诊断/可观测性改动（强烈建议同时上）

1. **报告文件不再被 `/dev/console` 重定向吞掉**：`a2x_report_to_file()` 里，即使 fd 2 是 `/dev/console`，也把 `a2x-stop` 同时写到 `/var/tmp/a2x-reports/<program>.log`（`tee` 语义），否则所有 launchd job 的崩溃永远无法诊断。
2. ship 构建也打印 `[tramp]` 的 `gdelta`（当前 `[tramp]` 行在 ship 下也存在，但 `guest sp moved ... ignored` 这条已经会打印，说明这条路径可观测——只要 stderr 能落盘）。
3. 在 `a2x_stop_record()` 中，当 `uc->rip == 0` 且 `a64_cur_state == NULL` 时，额外扫描 `rsp..rsp+512` 的返回地址（lab 已经有 `stack[k]` 扫描，把它搬进 stop record，限制 8 行即可），这样最小的 ship 记录也能看到 `swift_job_runImpl`。

### 5.3 修复后的验证方法（可执行）

1. **构建 ship 宿主**（带 patch），先不装系统：
   ```bash
   # 同 mkhost-mac3.sh 命令，但设 A2X_SHIP=1
   ```
2. 用**同 Label `com.apple.sharingd` + 同 15 个 MachServices + StandardErrorPath** 的临时 LaunchAgent 运行新宿主（先把系统 job `bootout`）。确保 `launchctl print` 里各 endpoint `active = 1`。
3. `killall ControlCenter`，等它重启后观察 10 分钟；再 `open "airdrop://"` 2–3 次。验收：
   - `runs` 不增长、`last exit code = (never exited)`；
   - `StandardErrorPath` 中不再出现 `FATAL: SIGSEGV`；
   - unified log 中 `AvailableDiscoverability` 的 START/END 正常成对出现，实例不退出。
4. 恢复系统 job，复测：
   - `launchctl print gui/501/com.apple.sharingd` 在多次 ControlCenter 刷新后 `runs` 稳定；
   - iPhone → Mac AirDrop：接收端出现设备、传输完成；
   - `log show` 中 `SFDeviceDiscovery ### Interrupted` / `Restarting after interruption` 不再周期性刷屏。
5. 回归：Swift Concurrency 相关 app（Music/TV/App Store 等）与 async 网络路径；因为改动在通用蹦床的 async 返回处，必须跑 a2x 的 async/await 回归样本。

### 5.4 如果最终证明根因在 guest 侧（备选）

若 5.1 的“负值不弹”仍不能消除崩溃，则问题可能是 `0x1001c5e24` 这个 async 函数的**续体返回路径**（await resume 点）在 a2x 下的栈布局与入口不同。备选修复点：
- `a2x_ret_is_task_resume()` / `a2x_callee_uses_async_ctx()`（host.c:1592-1642）对“resume partial function”的识别；
- `swift_door.s` / `swift_vlb.c` 里 Swift async 函数指针/续体的装载路径。
验证方式相同：同 Label agent + ControlCenter invocation，比较 `[tramp]` 行的 `tgt`/`gdelta`。

---

## 6. 未验证项与风险

### 6.1 未验证

1. **`0x1001c5e24` 对应的 Swift 函数名**：guest arm64e 切片已 strip，只有入口反汇编（`pacibsp` + async frame 位 + `sub sp,#0x80`）；无法从符号确认它是哪个 resume 续体。
2. **崩溃时 `a2x_async` 是 true 还是 false**：lab 报告只打了 `gdelta=-16` 的忽略行，没有打 `[tramp] async ... popped ...`（该行只在 `a2x_gpop && shown_pop < 3` 时打印）。这决定 area 是 8 还是别的值，修复前建议先加一行无条件日志确认。
3. **launchd 三键的完整排除**：B 组已经证明“三键全带 + 同 Label + 同 MachServices + 同副本”可以稳定，直到 invocation；但 B 组是手工 `bootstrap` 的 job，不是登录时由 launchd 从 `/System/Library/LaunchAgents` 载入的 job。理论上 `LimitLoadToSessionType`/登录时序仍可能有细微差异，不过所有崩溃实例都精确对应 invocation，三键不构成因果。
4. **系统 job 的崩溃环是否会在我们恢复后再次出现**：恢复后当前实例 `runs=1` 稳定；只要 ControlCenter 再次发起 `AvailableDiscoverability`，按本报告的证据它仍会崩。这不是修复，只是恢复了原状。
5. **真正的系统文件替换验证**：本次没有 root（`sudo` 需要密码，`launchctl debug` 明确要求 root），因此**没有**替换 `/usr/libexec/sharingd`；所有复现都在 `/tmp` 副本 + 用户 LaunchAgent 上完成。最终 ship 补丁需要 root 安装后按 5.3 复测。

### 6.2 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| 改动通用蹦床影响所有 app | host.c:1740-1800 是 native→guest 的公共返回路径，async 判定改错会影响全部 Swift async 调用 | 只用“负值不加 area”这一最小行为改动；先在同 Label agent 上跑 10 分钟 + Music/TV/App Store 回归 |
| lab 构建与安装版差异 | lab 是 `mkhost-mac3.sh` 通用 CLI host，签名用 guest entitlements；安装版是 per-app host（带 guest Info.plist） | 崩溃签名（rip 0 + swift_job_runImpl + gdelta -16）在两者一致；最终必须用 ship per-app host 验证 |
| MachServices 所有权陷阱 | 换 Label 的临时 agent 无法 check-in，会给出“稳定”的假阴性（本次 14:29 的对照就是这样被误导的） | 任何复现实验必须用**同 Label**，并确认 `launchctl print` 中每个 endpoint `active=1` |
| 系统 job 被反复 bootout/bootstrap | 会短暂中断 AirDrop/Handoff 的 XPC 端点 | 实验窗口已尽量短；结束后已恢复系统 plist 的 job；未改任何系统文件 |
| 报告丢失 | ship 的 `a2x-stop` 仍会写到 `/dev/console`（除非同时修 5.2） | 诊断期用 lab host + StandardErrorPath；长期修 5.2 |

---

## 7. 附录

### 7.1 本次实际执行的只读/临时操作

- 备份：`cp -p /usr/libexec/sharingd /tmp/sharingd.orig`（`cp` 因 SIP 无法复制 flags，内容一致，`cmp` 通过，sha256 同上）。
- 所有实验 job 都在 `gui/501`，Label `com.apple.sharingd` 或 `com.a2x.diag.sharingd`，plist 在 `/tmp/diag-*.plist`；实验后均已 `bootout`。
- 系统 job 已用
  `launchctl bootstrap gui/501 /System/Library/LaunchAgents/com.apple.sharingd.plist`
  恢复（当前 `runs=1`、`state=running`）。
- 未修改 `/System` 下任何文件，未改 EFI，未重启。
- `lldb` attach 被 taskgated 拒绝（即使对副本重签 `get-task-allow`、去掉 `hardened-process` 仍拒绝）；`launchctl debug` 需要 root。最终用 lab host 的崩溃报告拿到栈。

### 7.2 复现命令（任何人可重复）

```bash
# 1) 备份并复制（只读系统文件）
cp -p /usr/libexec/sharingd /tmp/sharingd.orig
cmp /tmp/sharingd.orig /usr/libexec/sharingd && echo identical

# 2) 同 Label、同 15 MachServices、同 6 键，StandardErrorPath=/tmp/diag-sys.err
launchctl bootout gui/501/com.apple.sharingd
launchctl bootstrap gui/501 /tmp/diag-sd-syslabel.plist

# 3) 触发 ControlCenter 的 AvailableDiscoverability
killall ControlCenter
# 或：open "airdrop://"

# 4) 看结果
launchctl print gui/501/com.apple.sharingd | grep -E 'runs|last exit'
cat /tmp/diag-sys.err        # FATAL: SIGSEGV / fault 0x0

# 5) 恢复
launchctl bootout gui/501/com.apple.sharingd
launchctl bootstrap gui/501 /System/Library/LaunchAgents/com.apple.sharingd.plist
```

### 7.3 关键源码位置索引

| 文件:行 | 内容 |
|---|---|
| host.c:1746-1749 | `a2x_gpop = xs[31] - asp`，无符号判非法后清零（本次 -16 被忽略） |
| host.c:1759 | `ss->__rsp += 8`（普通返回弹 return address） |
| host.c:1785-1800 | swifttailcc/async 弹出量 `area` 计算与 `ss->__rsp += area` |
| host.c:1628-1642 | `a2x_cb_async_return()`：async 返回判定 |
| host.c:1644-1649 | 注释：Job::ResumeTask `callq *0x38(%r15)` 与 `[rsp]` 返回点 |
| host.c:2414-2418 | ship 故障处理器 `_exit(139)` |
| host.c:1883-1902 | `a2x_report_to_file()`：仅在 fd2==/dev/null 时建报告 |
| host.c:4677-4679 | ppid==1 时把 fd2 重定向到 `/dev/console`（压掉报告文件） |
| vararg.c:50-70 | 同类私有变参修复（IO8Log2/NSAppendPrintF），说明 a2x 的 ABI 修复模式 |

### 7.4 关键日志原文

```
2026-11-18 14:29:13.921 Df launchd[1:254b] [gui/501/com.apple.sharingd [2668]:] exited due to exit(139), ran for 13600ms
2026-11-18 15:36:33.498 Df launchd[30347:2dc55] [com.apple.sharing:xpc] Invocation [_TtCO7Sharing20SFAirDropInvocations24AvailableDiscoverability:com.apple.controlcenter:30554] END -- Daemon
2026-11-18 15:36:33.516 Df launchd[1:2c9c5] [gui/501/com.apple.sharingd [30347]:] exited due to exit(139), ran for 47302ms
```

```
FATAL: SIGSEGV
a2x-stop: build a2x r27 cd14be8c macos 26B123 pid 30347
a2x-stop: program /tmp/sharingd.orig
a2x-stop: signal SIGSEGV fault 0x0
a2x-stop: end
```

（全文完）
