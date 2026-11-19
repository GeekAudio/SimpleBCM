# Finder「隔空投送」`SFXPCResilientAsyncSequence` 逆向：切片、`iterationError` 触发条件与 sharingd 崩溃链

- 日期：2026-11-18（Asia/Shanghai）
- 机器：Mac15,14，macOS 27.2（26B123，Darwin 27.2.0，x86_64 Intel），a2x 转译层
- 对象：
  - Finder：`/Users/geek/Documents/Macintosh/finder-malloc-r27/search-source-v5/a2xhost-finder-source-v5`（pid 9752，`Identifier=.a2xhost-mac`，adhoc），`A2X_GUEST=/Library/NullMoth/golden-gate/orig/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder`（arm64e only）
  - sharingd：`/usr/local/libexec/sharingd`（a2x lab 构建，universal x86_64+arm64e；guest = 自身的 arm64e 切片，`A2X_ASYNC_NEG_AREA=16`）
  - Sharing.framework：`/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing`（磁盘上没有该文件，只有 dyld shared cache 里的 x86_64 镜像；见 §2）
- 边界：只读分析 + `/tmp/a2xdsc` 实验；未改 `/System`、`/Library`、EFI；未重启；`sharingd` 的 `nwnode://AirDrop` 复现只触发了 Finder 打开隔空投送窗口，没有改任何系统文件。
- 结论一句话：**Finder 里失败的 `SFXPCResilientAsyncSequence` 代码是 native x86_64 Sharing（不是 guest arm64e），`Unable to recreate sequence/iterationError` 是「sharingd（guest arm64e，a2x 解释执行）在 Finder 连上来时崩溃 → Finder 与 sharingd 的 XPC 连接中断 → 序列用同一个 `SFXPCConnection` 重建失败」的下游症状；真正根因在 a2x 的 async 返回栈修正（`host.c` 的负 gdelta 分支），不在 Finder 的序列逻辑。**

---

## 0. 结论摘要（先看这一段）

1. **切片判定：native x86_64，不是 guest arm64e。**
   - Finder guest 对这两个符号是 import（`nm -arch arm64e -u` 显示 `U`），不是定义：
     ```
     U _$s7Sharing15SFAirDropClientC24registerTransfersMonitorAA27SFXPCResilientAsyncSequenceVyAA0bC0O0F0VGyYaKF
     U _$s7Sharing27SFXPCResilientAsyncSequenceV04makeC8IteratorAC0cF0Cyx_GyF
     U _$s7Sharing27SFXPCResilientAsyncSequenceV0C8IteratorCMn
     ```
   - a2x 的依赖加载规则（`liberator-devkit/src/interpreter/candidate/interp/host.c`，`scan_deps()` 的 `dlopen(nm)` 分支，≈2947–2960 行）：**只有 `dlopen("/System/Library/.../Sharing")` 失败时才**用 `a2x_sysdylib_guest_path()` 找 arm64e 文件并 `load_guest()`。Sharing 在 x86_64 dyld cache 里有 x86_64 镜像，`dlopen` 成功 → 不加载 guest 镜像 → Finder 的 import 由 `dlsym(RTLD_DEFAULT)` 绑到 native x86_64 Sharing。
   - 旁证：`orig` 树、`/System`、`/System/Volumes/Preboot/Cryptexes/OS` 三处都没有 Sharing 的 arm64e 文件（`lipo -info` 均 "file not found"），a2x 根本没有可加载的 guest Sharing。
   - **注意**：不要拿 Finder 的 stderr（`finder-source-v5.log`）里没有 `loaded as a guest image` 当证据——该 host 是 ship 构建，`strings a2xhost-finder-source-v5` 里连 `has no x86_64 slice` / `guest image` / `[stage]` 都是 0 条，诊断被编译掉了。真正的判据是 dlopen 规则 + 无 arm64e 文件 + vmmap。
   - 运行态：`vmmap 9752` 中 Sharing 的 `__TEXT` 在 **0x7ff82212a000**（slid）；unslid 镜像 `__TEXT=0x7FF8214B1000`，boot slide `0xC79000`；从 `/System/Library/dyld/dyld_shared_cache_x86_64` 按 `__TEXT` 文件偏移 `0x214b1000` 抽出的就是 x86_64 镜像（`magic 0xfeedfacf, cputype 0x01000007`）。
   - 因此：**`registerTransfersMonitor` / `makeIterator` / `Iterator.next` 全部是 native x86_64 代码**（Apple 的 Sharing 客户端的 Intel 切片），由 Finder 的 guest arm64e Swift 代码通过 a2x 的 native door 调用；不是被解释执行的 arm64e Sharing。

2. **`makeIterator`（0x7ff82171e250，≈0x110 字节）只做构造**：取 `AsyncIterator` 的 metadata/布局、在栈上建临时值、分配 iterator 对象，把序列结构里的 `name`(String)、`log`(Logger)、`body`(16B 闭包)、`shouldRetryBlock`(16B 闭包) 四个字段拷进 iterator，`innerIterator` 置空。它本身不建 XPC 连接。
   iterator 的 ivar 表（`__IVARS__TtCV7Sharing27SFXPCResilientAsyncSequence13AsyncIterator`，`0x7ff8430e3718`）实测字段正是：`$defaultActor`(96B)、`name`(16B)、`log`、`body`(16B)、`shouldRetryBlock`(16B)、`innerIterator`(16B)。

3. **`Iterator.next`（0x7ff82171e800，async，长度到 0x7ff8217205d0 ≈ 0x1dd0）是一个完整的「初次创建 / 重试 / 重建」状态机**，日志字符串（都在 `__oslogstring`，地址为 unslid）：
   | 地址 | 字符串 |
   |---|---|
   | 0x7ff821810d70 | `XPCResilientAsyncSequence[%s] FAILED. Failed to create initial sequence.  {error: %@}` |
   | 0x7ff821810dd0 | `XPCResilientAsyncSequence[%s] START. Created initial sequence.` |
   | 0x7ff821810e10 | `XPCResilientAsyncSequence[%s] FAILED. Non retryable error {error: %@}` |
   | 0x7ff821810e60 | `XPCResilientAsyncSequence[%s] FAILED. Unable to recreate sequence. Throwing iterationError {error: %@, iterationError: %@}` |
   | 0x7ff821810ee0 | `XPCResilientAsyncSequence[%s] CONTINUE. Recreated sequence after error {error: %@}` |
   | 0x7ff821810f40 | `XPCResilientAsyncSequence[%s] RETRY. Recreating sequence {error: %@}` |
   | 0x7ff821810f90 | `XPCResilientAsyncSequence[%s] END. Inner sequence finished` |
   | 0x7ff821810fd0 | `... Evaluated shouldRetryBlock {shouldRetry: %{bool}d, error: %@}` |
   | 0x7ff821811030 | `... Evaluated Cocoa Error {isXPCConnectionError: %{bool}d, error: %@}` |
   失败日志 `0x7ff821810e60` 在 `next` 里有两处引用：`0x7ff82171fb84` 与 `0x7ff82171fe1c`；两处都是同一个模式：先把两个 error 描述装进 `os_log` 消息（调用 `0x7ff821870500`），再用 mangled name `0x7ff82181a868` 实例化 `_SFXPCError`（type metadata 在 `0x7ff844559270`），写 code=2 后 `swift_allocError`/throw。
   **触发条件：** 内层 `SFXPCAsyncSequence` 的 `next()` 抛错后，`shouldRetryBlock`（对 Cocoa XPC 连接错误还先做 `NSCocoaErrorDomain` 判定，字符串 `0x7ff821811030`）返回 true；随后 `body` 闭包被再次调用以重建内层序列。若 `body` 抛错，或新建序列的 `makeIterator()` 抛错（对应两处日志点），就记 `Unable to recreate sequence` 并抛出 `SFXPCError.iterationError`。所以 **`iterationError` 不是"第一次连接失败"，而是"第一次失败后重建也失败"**。

4. **重建失败的根因不在序列：sharingd 在 Finder 连上来时崩溃。**
   18:34:49 的复现（`open "nwnode://AirDrop"`，不需要 UI 自动化权限）时间线（`/tmp/a2xdsc/try.log`，`log stream --level debug`）：
   ```
   18:34:49.436 Finder asyncXPC [BecomeTransferPresenter] START -- Client
   18:34:49.438 sharingd[11302] New AirDrop Client; BecomeTransferPresenter START -- Daemon
   18:34:49.442 sharingd[11302] AccessReporting: RD13622867.com.apple.finder:9752 is missing
                com.apple.private.airdrop.client for BecomeTransferPresenter -- serving anyway, reporting
   18:34:49.444 sharingd[11302] Becoming presenter for connectionID
   18:34:49.445 sharingd[11302] Invocation [...] END -- Daemon
   18:34:49.448 Finder  [com.apple.xpc:connection] Re-initialization successful; calling out to event handler
                with XPC_ERROR_CONNECTION_INTERRUPTED
   18:34:49.448 Finder  [com.apple.sharing:Browser] Lost connection to sharingd      (error level)
   18:34:49.448/449/464/465 Finder  activating connection ... name=com.apple.sharingd  (开始重建)
   18:34:49.469 Finder  [0x7fc72144da30] invalidated after the last release of the connection object
   18:34:50.455 sharingd[20545] Starting Up...                                        (launchd 拉起新实例)
   ```
   同一次运行里 `/tmp/sharingd-sweep.err` 记录 pid 11302 的崩溃（mtime 18:34），18:36:34 又记录 pid 20545 的同一崩溃：
   ```
   [tramp] async 0x1001be678 returned with sp -16: no async area extra 16
   [host] aligned SSE operand at unaligned 0x1b3c80d08 ... completed unaligned
   FATAL: SIGSEGV
   a2x-stop: build a2x r27 lab negsweep macos 26B123 pid 20545
   a2x-stop: program /usr/local/libexec/sharingd
   a2x-stop: signal SIGSEGV fault 0x0
   [host] SIGSEGV at guest pc 0x0 ... rsp 0x1b3c80e78
   [host] stack[2] 0x7ff80867560c swift_job_runImpl+0x8c
   [host] faulting thread ...; the stage was published by ... A DIFFERENT THREAD
   ```
   `launchctl print gui/501/com.apple.sharingd` 在同一窗口里显示 `runs` 递增、`last exit code = 139`。`/tmp/sharingd-sweep.err` 里共有 6 条 `FATAL: SIGSEGV`（pids 10735/10743/11302/20545/…），都是同一类 guest async 返回栈错位。
   因此因果链是：**Finder 打开隔空投送 → 与 sharingd 建立 peer 连接并调用 BecomeTransferPresenter → sharingd 的 guest arm64e async continuation 在 a2x 蹦床上崩溃 → Finder 收到 `XPC_ERROR_CONNECTION_INTERRUPTED`（"Lost connection to sharingd"）→ `SFXPCResilientAsyncSequence` 首次 next 抛 XPC 连接错误 → shouldRetry=true → 重建时 sharingd 已死/正在重启，`SFXPCConnection` 重建/调用失败 → "Unable to recreate sequence. Throwing iterationError"。**

5. **`[com.apple.xpc] invalidated after the last release of the connection object` 的含义（重要，别再当根因）。**
   该字符串在 `/usr/lib/system/libxpc.dylib`（unslid `__TEXT` 0x7FF807ECF000，字符串 va 0x7FF807F19245），唯一代码引用是 `0x7FF807EDD8E1`（`leaq 0x3b958(%rip),%rcx`），所属函数是 **`-[OS_xpc_connection _xref_dispose]`（符号 `0x7FF807EDD86D`）**。反汇编开头 `cmpl $0,0x1c(%rdi); jne already_disposed`，随后走 `_os_log` 分支，日志格式参数就是这条字符串 + 连接对象指针。
   语义：**某个 `xpc_connection_t`（OS_xpc_connection 对象）在还有活动状态时被最后一次 `OS_object_release` 释放（没有先 `xpc_connection_cancel`），libxpc 于是自己把它 invalidate 并打这条 debug 日志。** 它说明"谁把这个连接对象的最后一个引用放掉了"，**不**说明对端拒绝、也不说明 a2x 的 ARC 有 bug。
   实测它不是 AirDrop 专属：18:34:48–57 的 5 秒里，`System Settings / appleeventsd / tccd / cloudd / contactsd / sharingd / a2xhost-*` 等都在刷同一条（`/tmp/a2xdsc/try.log` 数十条）。在 Finder 这次的具体位置，它出现在 `Lost connection to sharingd` 之后（18:34:49.448 → .449/.469），是**连接被对端死亡打断后旧 NSXPCConnection 被释放的拆栈动作**，即症状/后果，不是原因。

6. **最小修复方向：L1（a2x 解释器），不是 Finder/Sharing（L3 禁止）。**
   崩溃点是 guest `0x1001be678`（sharingd arm64e，已 strip；该函数 async 返回后 `sp` 相对进入值 **-16**），当前 `host.c` 在负 gdelta 分支只加一个全局 `A2X_ASYNC_NEG_AREA` 常量（sharingd 现在=16）：
   ```c
   /* liberator-devkit/src/interpreter/candidate/interp/host.c:1811-1822（a2x_cb_call 内） */
   } else {
       long long extra = 0;
   #if !A2X_SHIP
       const char *e = getenv("A2X_ASYNC_NEG_AREA");
       if (e) extra = strtoll(e, 0, 0);
   #endif
       if (extra) ss->__rsp += (unsigned long)extra;
   }
   ```
   实测 16 仍然让 rsp 8 字节错位（日志里 `aligned SSE operand at unaligned 0x...d08/d18/d28/d38`，全部 ≡8 mod 16），随后 `swift_job_runImpl` 返回到 0。
   最小改动建议（按优先级）：
   1) **先做 lab sweep（零改动）**：在 `A2X_ASYNC_NEG_AREA` 上试 **24**（= -gdelta 16 + async word 8）和 **40**（= 正 gdelta 分支对 `gpop=16` 的公式 `((16+16+8+15)&~15)-8`）。24/40 都未实测过；0/8/16/-8 已试且都失败（父代理记录）。**注意：这两个值只是候选，不是已证明的答案；如果 24 和 40 都失败，说明常量补偿这条路对该 site 不成立，直接走 (3)。**
   2) 代码化（备选）：负 gdelta 分支复用正分支的 `argb = gpop + 16` 形式，`gpop=(unsigned long)(-a2x_gdelta)`，得到 site 0x1001be678（gpop=16）→ area=40；但这必须和 (1) 的 sweep 一起验证，不能直接当成修复。
   3) 若 24 仍失败：在 `a2x_cb_call` 的 native→guest async 调用入口把**调用点实际预留的 area**（x86 caller 的 `sub $N,%rsp`/`retq $8` 布局）按调用点记录（per-site 或 shadow），返回时按记录值恢复，而不是猜常量。
   4) 不要动 Sharing/Finder 的 Swift 代码、不要加"重试次数"或改 `SFXPCResilientAsyncSequence`（L3）；`sharingd` 崩溃修好后，序列的重建会自然成功（或至少不再走到 iterationError）。
   5) 附带的 a2x 缺口（非本次阻塞）：`objc_bridge: guest protocol SDXPCInterface carries NO extended method types (size 96) — an NSXPCInterface over it will raise` 会反复出现，是 guest 协议元数据缺 method types 的独立问题，值得单独开线；本次它没有直接 abort。

7. **可直接复核的判据（命令）**
   ```bash
   # 1) 复现（不需要辅助功能权限；会打开 Finder 隔空投送窗口）
   ( log stream --level debug --style compact \
       --predicate 'subsystem == "com.apple.sharing" OR subsystem == "com.apple.xpc"' > /tmp/airdrop.log 2>&1 & echo $! > /tmp/ls.pid )
   sleep 1; open "nwnode://AirDrop"; sleep 8; kill $(cat /tmp/ls.pid)
   grep -E 'Lost connection to sharingd|XPCResilient|iterationError|Re-initialization successful' /tmp/airdrop.log
   # 2) sharingd 崩溃记录
   grep -a -E 'FATAL: SIGSEGV|returned with sp -16|a2x-stop: .*pid' /tmp/sharingd-sweep.err | tail
   launchctl print gui/501/com.apple.sharingd | grep -E 'pid =|runs =|last exit code'
   # 3) 切片/地址
   nm -arch arm64e -u <guest Finder> | grep -E 'SFXPCResilientAsyncSequence|registerTransfersMonitor'
   vmmap 9752 | grep 'Sharing.framework'
   # 4) libxpc 消息归属
   #    字符串 0x7FF807F19245 唯一 xref 0x7FF807EDD8E1，函数 -[OS_xpc_connection _xref_dispose]
   ```
   停止条件：`/tmp/sharingd-sweep.err` 不再新增 `returned with sp -16` + `FATAL: SIGSEGV`；Finder 日志不再出现 `Lost connection to sharingd`；`XPCResilientAsyncSequence` 日志应为 `START. Created initial sequence`（不再出现 `Unable to recreate`）。

---

## 1. 取证方法与产物

| 项 | 内容 |
|---|---|
| dyld cache 解析 | `/tmp/a2xdsc/probe.py`、`mkdis.py`（解析 `dyld_shared_cache_x86_64` 的 mapping/images/LC_SEGMENT_64，按 `__TEXT` 文件偏移抽取 thin Mach-O）；Sharing 抽成 `/tmp/a2xdsc/Sharing.x86_64.macho`（3.9 MB，vmaddr 保持原值） |
| 符号 | export trie + `LC_SYMTAB`（22182 条 local symbols）→ `/tmp/a2xdsc/symbols.json`；ObjC ivar 表从 `__DATA_CONST` 直接读 |
| 反汇编 | `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --no-show-raw-insn --start-address=... --stop-address=...` |
| 日志 | `log stream --level debug`（18:34:49 / 18:36:28 两次窗口）→ `/tmp/a2xdsc/try.log`、`now.log`；`log show --info --debug` 对 12h 内 `com.apple.sharing` 只有 1 条，说明这些 Info/Debug 记录不落持久库，必须实时抓 |
| 崩溃记录 | `/tmp/sharingd-sweep.err`（sharingd job 的 `stderr path`） |
| 进程状态 | `vmmap 9752`、`sample 9752`、`launchctl print gui/501/{com.apple.sharingd,com.apple.Finder}` |

**地址基准**：本文所有 Sharing 地址都是 **unslid**（cache 内）。运行中的 Finder 需要加 boot slide **0xC79000**：
`__TEXT 0x7FF8214B1000 → 0x7FF82212A000`，`makeIterator 0x7FF82171E250 → 0x7FF82239B250`，`next 0x7FF82171E800 → 0x7FF82239B800`。

---

## 2. 为什么是 native x86_64（完整证据链）

### 2.1 磁盘上没有 arm64e Sharing

```
$ lipo -info /Library/NullMoth/golden-gate/orig/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing
lipo: file not found
$ lipo -info /System/Volumes/Preboot/Cryptexes/OS/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing
lipo: file not found
$ lipo -info /System/Cryptexes/OS/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing
lipo: file not found
```

`/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/` 本身也只有 `Resources`、`_CodeSignature`，没有 `Sharing` 文件（`Sharing` 是 broken symlink）。运行中的镜像来自 dyld shared cache。

### 2.2 a2x 只在 dlopen 失败时 guest-load

`host.c` `scan_deps()`（`liberator-devkit/src/interpreter/candidate/interp/host.c:2947-2960` 一带）：

```c
void *dh_ = dlopen(nm, RTLD_LAZY | RTLD_GLOBAL);
...
if (!dh_ && a2x_sysdylib_guest_path(nm, gp_, sizeof gp_)) {
    /* no x86_64 slice anywhere: the file is guest code */
    ... load_guest(gp_, ...) ...
}
```

Sharing 的 x86_64 镜像在 `/System/Library/dyld/dyld_shared_cache_x86_64` 里，`dlopen("/System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing")` 会从 cache 命中成功（vmmap 已证明该镜像在进程里），所以**不会**走 guest 分支。Binding 阶段 `apply()` 里 "A GUEST EXPORT WINS OVER A NATIVE ONE"（`guest_lookup(f->symbol)`）也只有在 guest 镜像存在时才可能命中；Sharing 没有 guest 镜像。

### 2.3 Finder 侧符号是 import，且 native 镜像导出它们

```
$ nm -arch arm64e -u <guest Finder> | grep -i 'SFXPCResilient\|registerTransfersMonitor'
                 U _$s7Sharing15SFAirDropClientC24registerTransfersMonitorAA27SFXPCResilientAsyncSequenceVyAA0bC0O0F0VGyYaKF
                 U ...Tu
                 U _$s7Sharing27SFXPCResilientAsyncSequenceV04makeC8IteratorAC0cF0Cyx_GyF
                 U _$s7Sharing27SFXPCResilientAsyncSequenceV0C8IteratorCMn
                 U _$s7Sharing27SFXPCResilientAsyncSequenceV0C8IteratorCyx_GScIAAMc
```

在 native x86_64 Sharing 的 export trie 里能查到同一批符号（`symbols.json`，6941 条 exports）：

| 符号 | unslid 地址 |
|---|---|
| `$s7Sharing27SFXPCResilientAsyncSequenceV04makeC8IteratorAC0cF0Cyx_GyF` | 0x7FF82171E250 |
| `$s7Sharing27SFXPCResilientAsyncSequenceV0C8IteratorC4nextxSgyYaKF` | 0x7FF82171E800 |
| `$s7Sharing27SFXPCResilientAsyncSequenceV4name3log4body11shouldRetryACyxGSS_2os6LoggerVAA010SFXPCAsyncD0VyxGyYaYbKcSbs5Error_pYbcSgtcfC` | 0x7FF82171E630 |
| `$s7Sharing15SFAirDropClientC24registerTransfersMonitorAA27SFXPCResilientAsyncSequenceVyAA0bC0O0F0VGyYaKF` | 0x7FF82170CD80 |
| `$s7Sharing15SFAirDropClientC42registerTransfersMonitorAndBecomePresenterAA27SFXPCResilientAsyncSequenceVyAA0bC0O0F0VGyYaKF` | 0x7FF82170CF90 |
| `$s7Sharing15SFAirDropClientC24registerTransfersMonitorAA18SFXPCAsyncSequenceVyAA0bC0O0F0VGyYaKF`（非 resilient 重载） | 0x7FF82170D640 |
| `$s7Sharing18SFXPCAsyncSequenceV13AsyncIteratorV4nextxSgyYaKF`（内层迭代器） | 0x7FF8216388B0 |
| `$s7Sharing15SFXPCConnectionC11asyncInvoke...YaKF` | 0x7FF821669310 |
| `$s7Sharing15SFXPCConnectionC10connectionSo15NSXPCConnectionCvg` | 0x7FF821668C10 |

### 2.4 运行态

```
$ vmmap 9752 | grep 'Sharing.framework'
__TEXT  7ff82212a000-7ff8224ea000  ...  /System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing
__DATA_CONST 7ff843cf6fc0-...       ...  同上
```
`0x7ff82212a000 - 0xC79000 = 0x7FF8214B1000`，和 cache 里 x86_64 镜像的 `__TEXT` 完全一致。

### 2.5 为什么 stderr 不能当证据

`finder-source-v5.log` 里 `grep -c 'guest image'` = 0，但 `strings a2xhost-finder-source-v5` 里 `has no x86_64 slice`、`guest image`、`[stage]` 也全是 0 条——该 host 是 ship 构建，这些诊断被编译掉了，所以"日志里没有"不构成"没有发生"的证据。切片判定的强证据只有三条：dlopen 成功（vmmap 有 native 镜像）、a2x 的 guest-load 分支只在 dlopen 失败时走、以及全系统找不到 Sharing 的 arm64e 文件。

> **对原任务前提的修正**：`SFXPCResilientAsyncSequence` 的实现不在 guest arm64e Finding 里，而在 **native x86_64 Sharing**。Finder 只在 guest 里持有/调用它。后面所有反汇编都是 x86_64。

---

## 3. 代码分析

### 3.1 `makeIterator`：只构造 iterator

`0x7FF82171E250`（≈0x110 字节）做的事：
1. `0x7ff82186f36c` 取 `AsyncIterator` 的 metadata；`0x40(%metadata)` 是实例大小，`sub` 出栈上临时缓冲。
2. 调用 `0x7FF82171E360`（iterator 的 init/布局辅助）。
3. 从序列结构（`%r13`）按 field offset 读 `+0x10/+0x18`（`name` 的 16 字节 String）、`+0x30/+0x34` 字段（`body` 与 `shouldRetryBlock` 的两对 fn/context），分别 retain 后调 `0x7FF82171E750`（类初始化，写入 iterator ivar，`innerIterator` 清零）。
4. 返回 iterator。

ivar 表实证（`__IVARS__TtCV7Sharing27SFXPCResilientAsyncSequence13AsyncIterator` @ `0x7ff8430e3718`，entsize 0x20，count 6）：

```
$defaultActor(96)  name(16)  log  body(16)  shouldRetryBlock(16)  innerIterator(16)
```

所以序列 = `(name, log, body, shouldRetryBlock)`；**连接不在序列里，连接在 `body` 闭包的捕获上下文里**（见 §3.3）。

### 3.2 `next` 的重试状态机与 `iterationError`

`0x7FF82171E800`（async，Swift 状态机，`%r14` = async context）。与本次问题相关的分支：

- `0x7FF82171F103` 引用 `0x7ff821810dd0`（`START. Created initial sequence`）：**初次**创建内层序列并 `makeIterator()`；失败走 `0x7ff821810d70`（`Failed to create initial sequence`）。
- 内层 `next()` 调用（`callq *0x30(%rax)` 的协议 witness）之后，错误路径：
  - `0x7FF82171F424` 引用 `0x7ff821810f40`（`RETRY. Recreating sequence {error}`）→ 说明 `shouldRetryBlock` 判 true。
  - `0x7FF82171FB84` / `0x7FF82171FE1C` 引用 `0x7ff821810e60`（`Unable to recreate sequence. Throwing iterationError {error, iterationError}`）。
  - 两处日志后都构造 `_SFXPCError`（`swift_instantiateConcreteTypeFromMangledName` 用 mangled name `0x7ff82181a868`；class metadata `0x7FF844559270`）并 `throw`。`movl $0x2,%esi` 是 code/枚举实参。
- 成功重建的分支引用 `0x7ff821810ee0`（`CONTINUE. Recreated sequence after error`）。
- 内层正常结束引用 `0x7ff821810f90`（`END. Inner sequence finished`）。
- `shouldRetry` 的判定包含一个专门的 "Cocoa Error" 分类（字符串 `0x7ff821811030`：`isXPCConnectionError`），即 **XPC 连接类错误被设计成可重试**。

**结论：`iterationError` 的触发条件是"第一次失败可重试，但重建用的 `body` 或新序列的 `makeIterator` 再次抛错"。它的含义是"无法恢复"，不是"初次连接失败"。**

### 3.3 连接在哪里：`SFAirDropClient.connection` + `SFXPCConnection`

`__IVARS__TtC7Sharing15SFAirDropClient`（`0x7ff8430e2af0`，entsize 0x20，count 4）：

```
$defaultActor(96)  connection(8)  clientIdentifier  queue
```

`registerTransfersMonitor`（`0x7FF82170CD80`）的 async continuation 在构造序列时：
```
0x7ff82170ce60:  movq -0x30(%rbp),%rax     ; self (async context +0x18)
0x7ff82170ce64:  movq 0x70(%rax),%rax       ; 读 self+0x70
0x7ff82170ce68:  movq %rax,-0x30(%rbp)      ; 存为 body 闭包的 context
...
0x7ff82170ceb6:  movq %rcx,(%r13,%rax)      ; body.fn = 0x7ff821826f08（__const 里的 async 函数指针）
0x7ff82170cebf:  movq %rdi,0x8(%r13,%rax)   ; body.ctx = self+0x70 的对象
```
`0x70` 是 `SFAirDropClient.connection`（`SFXPCConnection`）的偏移——这是**从 ivar 表/disassembly 推断**，未用 lldb 验证（见 §6 未验证项）。`SFXPCConnection` 的 API 是 `serviceName` / `machServiceName` / `listenerEndpoint` + `asyncInvoke`（`0x7FF821669310`）；它持有 `NSXPCConnection`（`0x7FF821668C10`）。

### 3.4 `Lost connection to sharingd` 的归属

对 Sharing `__oslogstring` 里 `Lost connection to sharingd`（0x7FF8218049D0）、`Reconnecting to sharingd`（0x7FF821803F30）做 RIP-relative xref：

| 字符串 | xref 地址（unslid） | 所属符号 |
|---|---|---|
| Lost connection to sharingd | 0x7FF8214B963A | `____SFBrowserCreateConnection_block_invoke + 0x124` |
| Lost connection to sharingd | 0x7FF8214BDB35 | `____SFOperationCreateConnection_block_invoke + 0x12a` |
| Lost connection to sharingd | 0x7FF821791D68/0x7FF821791D9C/0x7FF821795BBE/0x7FF821795BF2 | 上述两个 block 的 `.cold.*` |
| Reconnecting to sharingd | 0x7FF8214C7A35 | `-[SFCompanionXPCManager init] block_invoke + 0x49` |
| Reconnecting to sharingd | 0x7FF8214C7C65 | `-[SFCompanionXPCManager onQueue_setupConnection] block_invoke + 0x3d` |

Finder 日志里 18:34:49.448 的 `Lost connection to sharingd` 就是 `SFBrowserCreateConnection_block_invoke` 在 NSXPC 的 invalidation/interruption handler 里打的（error 级）。**这条日志是 sharingd 死亡的直接证据**。

---

## 4. 复现与因果链（实测）

### 4.1 触发方法

不需要 System Events/辅助功能（实测 `osascript` 调用 System Events 返回 `-1719`），`open "nwnode://AirDrop"` 就能让 Finder 打开隔空投送浏览器：

```
18:34:49.448 Finder  [com.apple.sharing:Browser] SFBrowserSetMode
18:34:49.468 Finder  [com.apple.sharing:Browser] SFBrowserOpenNode
18:34:51.393 Finder  [com.apple.sharing:Browser] SFBrowserCallBack / SFBrowserGetRootNode
```

`airdrop://` 不是 Finder 注册的 scheme（`open "airdrop://"` → `kLSApplicationNotFoundErr -10814`）。

### 4.2 18:34 的完整时间线（节选，`/tmp/a2xdsc/try.log`）

```
18:34:49.436 Finder[9752]  asyncXPC [BecomeTransferPresenter] START -- Client
18:34:49.438 sharingd[11302] activating connection: peer name=com.apple.sharing.airdrop.service.peer[9752]
18:34:49.438 sharingd[11302] [AirDropNW] New AirDrop Client
18:34:49.439 sharingd[11302] Invocation [BecomeTransferPresenter:RD13622867.com.apple.finder:9752] START -- Daemon
18:34:49.442 sharingd[11302] [AccessReporting] ... is missing com.apple.private.airdrop.client ... serving anyway, reporting
18:34:49.444 sharingd[11302] [AirDropNW] Becoming presenter for connectionID
18:34:49.445 sharingd[11302] Invocation [BecomeTransferPresenter...] END -- Daemon
18:34:49.448 Finder[9752]  [com.apple.xpc:connection] Re-initialization successful; ... XPC_ERROR_CONNECTION_INTERRUPTED
18:34:49.448 Finder[9752]  [com.apple.sharing:Browser] Lost connection to sharingd        ← E
18:34:49.448 Finder[9752]  activating connection ... name=com.apple.sharingd
18:34:49.448 Finder[9752]  [com.apple.sharing:Framework] Lost connection to sharingd      ← E
18:34:49.448 Finder[9752]  [com.apple.sharing:Framework] SFOperationResume
18:34:49.449 Finder[9752]  [0x7fc723c15c00] invalidated after the last release of the connection object
18:34:49.464 Finder[9752]  [com.apple.sharing:Framework] SFOperationResume
18:34:49.469 Finder[9752]  [0x7fc72144da30] invalidated after the last release of the connection object
18:34:50.455 sharingd[20545] Starting Up...
18:34:50.559 sharingd[20545] activating connection: listener=true name=com.apple.sharingd.nsxpc / com.apple.sharingd
```

**sharingd 的崩溃记录**（`/tmp/sharingd-sweep.err`，pid 11302，紧接着 pid 20545 同一形状）：

```
[tramp] async 0x1001be678 returned with sp -16: no async area extra 16
[host] aligned SSE operand at unaligned 0x19f880d08 (native rip 0x7ff80414fa5b, map 1 op 7f) completed unaligned
[host] aligned SSE operand at unaligned 0x19f880d18 ... completed unaligned
[host] aligned SSE operand at unaligned 0x19f880d28 ... completed unaligned
[host] aligned SSE operand at unaligned 0x19f880d38 ... completed unaligned
FATAL: SIGSEGV
a2x-stop: build a2x r27 lab negsweep macos 26B123 pid 11302
a2x-stop: program /usr/local/libexec/sharingd
a2x-stop: signal SIGSEGV fault 0x0
[host] SIGSEGV at guest pc 0x0 ... | pid 11302 /usr/local/libexec/sharingd | pc in ?+0x0
[host]   native rip 0000000000000000  rsp 000000019f880e78
[host]   stack[2] 0x7ff80867560c swift_job_runImpl+0x8c
[host]   faulting thread ...; the stage was published by ... A DIFFERENT THREAD
```

`native rip=0`、`[rsp]=0`、`swift_job_runImpl+0x8c`、faulting thread 从未解释过 guest 代码——这就是 a2x 的 guest async 返回栈错位导致 job resume 返回到 0 的已知形状（与 2026-11-18 早先 sharingd ControlCenter 崩溃同族）。

### 4.3 与 `iterationError` 的关系

`XPCResilientAsyncSequence` 在 Finder 侧（native）为 `SFAirDropClient.registerTransfersMonitor` 建立 transfer monitor。它的 `body` 会对 `SFXPCConnection` 发 async invoke 并返回 `SFXPCAsyncSequence`。当 sharingd 死亡：

1. 已建立的 `NSXPCConnection` 收到 `XPC_ERROR_CONNECTION_INTERRUPTED`（日志 `Re-initialization successful; calling out ... INTERRUPTED`）。
2. `SFBrowserCreateConnection`/`SFOperationCreateConnection` 打 `Lost connection to sharingd`，并尝试重建连接（`activating ... name=com.apple.sharingd`）。
3. 正在 `for await` 的 `SFXPCResilientAsyncSequence.Iterator.next` 的内层迭代器抛 XPC 连接错误。
4. `shouldRetryBlock` 判 true（`isXPCConnectionError`），进入 `RETRY. Recreating sequence`。
5. 重建用的 `body` 再次 `asyncInvoke`；此时 sharingd 已死/正在重启，`SFXPCConnection` 无法建立有效连接 → 抛错 → 走 `0x7FF82171FB84`/`0x7FF82171FE1C`：`Unable to recreate sequence. Throwing iterationError`。

**这一步是推断**：本次 18:34 的 5 秒窗口里没有再抓到 `XPCResilientAsyncSequence` 日志（只在父代理更早的捕获里见到那条 `Unable to recreate`）。但链路的两端（sharingd 崩溃 + Finder 的 `Lost connection to sharingd` + 重建连接）已实测，且 `iterationError` 的代码条件与"重建失败"完全对应。**若要 100% 钉死，需在下次重现时把 `log stream` 谓词放宽到 Finder + sharingd 并保留 30 秒**（见 §7）。

**进程归属的保留意见**：`[com.apple.sharing:AirDropNWClient]` 这个分类字面量在 x86_64 dyld cache、Preboot arm64e cache、`/usr/local/libexec/sharingd`、guest Finder 里都搜不到（`strings`/字节搜索），说明它是运行时拼出来的 category/name，或父代理的捕获把 category 与消息合并显示了。`SFXPCResilientAsyncSequence` 在 Finder 和 sharingd 里都会用到（两者都链接 native x86_64 Sharing），所以"这条日志到底由 Finder 还是 sharingd 打出"不能从父代理的摘录单独确定；本报告的因果链对两者都成立（都是到 sharingd 或由 sharingd 发起的 XPC 连接中断），但"是 Finder 的 transfersMonitor"这一句应视为**最可能、未逐条证实**。

---

## 5. `[com.apple.xpc] invalidated after the last release of the connection object` 到底是什么意思

### 5.1 代码归属（实测）

- 字符串文件偏移：`/System/Library/dyld/dyld_shared_cache_x86_64` `0x7f19245`（va **0x7FF807F19245**）。
- 所在镜像：`/usr/lib/system/libxpc.dylib`（unslid `__TEXT` 0x7FF807ECF000–0x7FF807F21DF6）。
- 唯一 RIP-relative 引用：`0x7FF807EDD8E1: leaq 0x3b958(%rip),%rcx  ## 0x7FF807F19240`。
- 所属函数：`-[OS_xpc_connection _xref_dispose]`（本地符号表 `0x7FF807EDD86D`）。
- 入口判断：
  ```
  7ff807edd878: cmpl $0x0, 0x1c(%rdi)     ; 已经 disposed?
  7ff807edd87c: jne  0x7ff807edd934       ; 是 -> 走 "over-release" 报错分支
  7ff807edd8a3: testb $0x40, 0x109(%rbx)  ; 已 cancel/invalid?
  7ff807edd8aa: jne  0x7ff807edd8f8       ; 是 -> 不记
  ... 0x7ff807edd8f3: callq _os_log...    ; 否则记 "invalidated after the last release ..."
  ```

### 5.2 语义

**`OS_xpc_connection` 这个 ObjC 包装对象的最后一个引用被释放（`OS_object_release`/`-dealloc`）时，如果它还没有被 cancel/invalidate，libxpc 自己把它 invalidate 并打这条 debug 日志。** 它说的是"这个连接对象是被谁最后一次 release 掉的"，而不是"对端拒绝了连接"或"a2x 的 ARC 算错了"。

### 5.3 为什么不能把它当根因

- 实测系统范围内它极常见：18:34:48–57 的 5 秒里，`System Settings`、`appleeventsd`、`tccd`、`cloudd`、`contactsd`、`sharingd`、`a2xhost-*` 都在刷；正常情况下每个进程每秒都有。
- 在 Finder 这次的具体序列里，它出现在 `Lost connection to sharingd` **之后**（.448 中断 → .449/.469 旧连接被释放），是"对端死亡后旧 NSXPCConnection 被拆掉"的结果。
- 它也没有指向 `SFXPCConnection`/`SFXPCResilientAsyncSequence` 的任何对象：日志里的 `[0x...]` 是 `OS_xpc_connection` 地址，无法从用户态映射回 Swift 对象。

### 5.4 可验证判据

```bash
log stream --level debug --predicate 'subsystem == "com.apple.xpc"' | grep 'invalidated after the last release'
```
在不做任何 AirDrop 操作时也会持续出现（多进程）。若某进程在**没有** peer 死亡、也**没有**大量正常 teardown 的情况下单独刷这一条，才值得怀疑该进程的对象生命周期；对 a2x，真正的判据是 `sample`/`malloc_history`/`vmmap` 指向具体 Swift/ObjC 对象，而不是这条字符串。

---

## 6. 最小修复方向与层级

### 6.1 根因层级

| 候选 | 判定 |
|---|---|
| a2x objc_bridge/refcount 过早释放 | **否**。`invalidated after the last release` 是通用拆栈日志；没有证据指向 Finder 的 Swift 对象被提前释放。 |
| host 的 XPC 句柄保留 | **否**。连接是 native libxpc/NSXPCConnection；Finder 的 `SFBrowser`/`SFOperation` 在中断后确实重新 `activating`（日志可见）。 |
| **Finder guest 的 Swift 运行时适配（async 返回栈）** | **是（L1，a2x 解释器）**。sharingd（guest arm64e，同样由 a2x 解释）在 `0x1001be678` async 返回 `sp -16` 时，host 的负 gdelta 分支补偿错误，`swift_job_runImpl` 返回到 0 → SIGSEGV；Finder 的序列只是受害者。 |
| 只能报告边界 | 若把"Finder 侧序列重建失败"当独立问题，则是 Apple/Sharing 逻辑（L3，禁止改）；但它的触发条件（sharingd 死亡）是 L1 可修的。 |

### 6.2 具体改动建议（L1）

文件：`liberator-devkit/src/interpreter/candidate/interp/host.c`（运行中的 Finder host 源码在 `finder-malloc-r27/search-source-v5/source/src/interpreter/candidate/interp/host.c`，同一段逻辑）。函数：`a2x_cb_call`（native→guest 调用返回处理），行 ≈1735–1825。

当前负 gdelta 分支（≈1811–1822）：

```c
} else {
    /* the async word is inside the guest's own frame; the +8 above already popped the return address.
       The lab can sweep the extra amount: Sharing's 0x1001be678 returns -16 and a wrong area leaves
       SSE accesses misaligned (SIGBUS in swift_job_runImpl). */
    long long extra = 0;
#if !A2X_SHIP
    const char *e = getenv("A2X_ASYNC_NEG_AREA");
    if (e) extra = strtoll(e, 0, 0);
#endif
    if (extra) ss->__rsp += (unsigned long)extra;
    ...
}
```

建议：

1. **先做零改动的 lab sweep**：把 sharingd job 的 `A2X_ASYNC_NEG_AREA` 依次试 **24**（-gdelta 16 + async word 8）和 **40**（正分支公式对 `gpop=16` 的值），每次重启 job 并 `open "nwnode://AirDrop"`，看 `/tmp/sharingd-sweep.err` 是否还出现 `returned with sp -16` + `FATAL: SIGSEGV`。0/8/16/-8 已试且都失败；24/40 未试，但**只是候选**。若两者都失败，说明该 site 不能用常量补偿，直接走第 3 条。
2. **代码化**：负分支不要用全局常量，直接复用正分支公式：
   ```c
   unsigned long gpop = (unsigned long)(-a2x_gdelta);
   unsigned long argb = gpop ? gpop + 16 : 0;
   unsigned long area = ((argb + 8 + 15) & ~15UL) - 8;
   ss->__rsp += area;
   ```
   （按这个公式 gpop=16 → area=**40**，gpop=0 → area=8；40 未实测，必须和 sweep 一起验证。不要写成 24。）
3. **仍失败时**：在 native→guest async 调用入口按**调用点**记录 x86 caller 预留的 area（`sub $N,%rsp` / `retq $8` 布局），返回时按记录值恢复，而不是猜一个全局常量；这能覆盖 `0x1001be678` 之外其它负 delta 的 site。
4. **不要**改 Finder/Sharing 的 Swift 代码、不要加重试次数、不要替换 Sharing（L3）。sharingd 不崩溃后，`SFXPCConnection` 的重建会成功，`XPCResilientAsyncSequence` 会走 `CONTINUE. Recreated sequence after error`，不会到 `iterationError`。
5. 记录与回滚：每次 lab 值变更都写进 `/tmp/sharingd-sweep.err` 对应的启动参数和 `launchctl print` 的 environment；回滚就是把 `A2X_ASYNC_NEG_AREA` 改回 16（或删掉 env）并重启 job。

### 6.3 附带发现（不作为阻塞）

- sharingd 收到 Finder 的 `BecomeTransferPresenter` 时报告：`RD13622867.com.apple.finder:9752 is missing com.apple.private.airdrop.client`。但原始 Finder 的 entitlements 里也**没有** `com.apple.private.airdrop.client`（只有 `com.apple.private.airdrop.discovery`/`.settings`、`com.apple.sharing.airdrop.service`），且 sharingd 明确 "serving anyway, reporting" → **不是 a2x 身份问题，也不是本次阻塞**。
- `objc_bridge: guest protocol SDXPCInterface carries NO extended method types (size 96) — an NSXPCInterface over it will raise`：每次 sharingd 启动/连接都出现，是 a2x ObjC 协议元数据的独立缺口（guest protocol 的 method types 没被填进 native NSXPCInterface）。本次没有直接 abort，但值得单开一条线（如果 sharingd 的某条路径真的把该 protocol 包成 NSXPCInterface，会 raise）。
- 18:37 的 launchd 日志还有 `sharingd` 注册 `com.apple.private.alloy.nearby-idswake` 与 rapportd 冲突（`Operation not permitted`）、`com.apple.sharing.remote-text-editing` 失败，这是 sharingd 的 endpoint 权限/冲突问题，和本序列失败无直接关系，未深入。

---

## 7. 未验证项（必须列出）

1. **本次 18:34 的 5 秒窗口里没有直接抓到 Finder 的 `XPCResilientAsyncSequence ... Unable to recreate` 行**（父代理的捕获来自更早的运行）。因果链的"sharingd 崩溃 → Finder Lost connection → 重建失败 → iterationError"中，前两段实测，后一段由代码条件 + 时序推断。**复核方法**：下次用 30 秒窗口、谓词只筛 Finder 进程，并保留 `--info --debug`；或对 `0x7FF82171FB84`/`0x7FF82171FE1C` 下断点（当前无 lldb 权限/未尝试）。
2. `0x7FF82171FB84` 与 `0x7FF82171FE1C` 两处 `iterationError` 日志分别对应"body 抛错"还是"新序列 makeIterator 抛错"，静态上两者代码形状相同，未动态区分。
3. `SFAirDropClient+0x70 == connection` 是从 `registerTransfersMonitor` 的 `movq 0x70(%rax)` 与 ivar 表推断的，未用 lldb/objc runtime 实证偏移。
4. `A2X_ASYNC_NEG_AREA=24/40` 均未实测；per-site 记录 area 的方案未实现；因此 §6.2 的常量候选（24/40）只是待验证假设。
5. sharingd 的崩溃是否**每次**打开隔空投送都发生、以及是否只在 `BecomeTransferPresenter` 之后（而不是更晚的 AirDrop 网络/browse 回调）——目前只有两次同形状记录（pid 11302/20545，mtime 18:34/18:36），未做逐次关联。
6. `/tmp/sharingd-sweep.err` 的崩溃记录没有时间戳，时间只能靠文件 mtime 和 launchd 的 `runs`/重启时刻对齐。
7. 未在 Apple Silicon 真机上验证同一 `Failed to create / unable to recreate` 的日志路径；native x86_64 Sharing 是 Apple 的 Intel 切片，客户端逻辑应一致，但 sharingd 侧行为不同（真机是原生 arm64e）。
8. 未验证 `sharingd` 当前 job 的 `A2X_ASYNC_NEG_AREA=16` 是由哪个部署脚本写入的（`launchctl print` 只显示 environment）；回滚需同时改部署与 live job，本次未动。

---

## 8. 证据索引

| 证据 | 位置 |
|---|---|
| Finder 进程与 agent | `~/Library/LaunchAgents/com.apple.Finder.plist`；`ps` pid 9752 |
| sharingd job | `/System/Library/LaunchAgents/com.apple.sharingd.plist`（program `/usr/local/libexec/sharingd`）；`launchctl print gui/501/com.apple.sharingd` |
| Finder 日志窗口 | `/tmp/a2xdsc/try.log`（18:34:49）、`/tmp/a2xdsc/now.log`（18:36:28） |
| sharingd 崩溃记录 | `/tmp/sharingd-sweep.err`（6 条 `FATAL: SIGSEGV`；pids 10735/10743/11302/20545/…） |
| Sharing x86_64 抽取 | `/tmp/a2xdsc/Sharing.x86_64.macho`、`/tmp/a2xdsc/symbols.json`、`/tmp/a2xdsc/mkdis.py` |
| libxpc 抽取 | `/tmp/a2xdsc/libxpc.macho`、`/tmp/a2xdsc/extract_generic.py` |
| 关键地址 | `makeIterator 0x7FF82171E250`；`Iterator.next 0x7FF82171E800`；`init 0x7FF82171E630`；resilient `registerTransfersMonitor 0x7FF82170CD80`；日志字符串 0x7FF821810D70–0x7FF821811090；`Lost connection to sharingd` xref 0x7FF8214B963A（`____SFBrowserCreateConnection_block_invoke`）；libxpc 字符串 0x7FF807F19245 / xref 0x7FF807EDD8E1（`-[OS_xpc_connection _xref_dispose]`） |
| a2x 源码 | `liberator-devkit/src/interpreter/candidate/interp/host.c`（async 返回块 ≈1735–1825；`scan_deps` ≈2860–2960） |
| 复现命令 | `open "nwnode://AirDrop"` + `log stream --level debug --predicate 'subsystem == "com.apple.sharing" OR subsystem == "com.apple.xpc"'` |
