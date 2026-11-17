# airportd / CoreWiFi `[ASSOC]` 阻塞点取证报告

日期：2026-11-17 19:40（Asia/Shanghai）
系统：macOS 27.2（26B123 / Darwin 27.2.0，x86_64 Intel），BCM43602 + SimpleBCM（注入 IO80211FamilyLegacy + AirPort payload）
分析对象：`/usr/libexec/airportd`（arm64e slice，经 a2x 转译）、`CoreWiFi.framework`（x86_64，来自 dyld 共享缓存）
约束：全程只读。除 `/tmp` 下的提取物和脚本外，未修改任何系统文件、未改 launchd、未重启。

---

## 0. 结论摘要（先看这里）

1. **`[ASSOC]` 是 CoreWiFi XPC 请求层的请求名，不是驱动 ioctl。** 19:23:37.099 设置扩展（pid 3050，`com.apple.wifi-settings-extension`）通过 `com.apple.private.corewifi.internal-xpc` 发出 `BEGIN REQ [ASSOC] uuid=4054B`；19:23:38.086 又发了一次（`uuid=265C1`）。两条都在 **120 s** 后以 `err=60` 结束。
2. **请求确实进入了 airportd 的关联实现**，不是"根本没到 airportd"。它执行的是 `-[CWXPCSubsystem __associateToWiFiNetwork:tetherDevice:password:is8021X:passpointDomain:remember:addReason:possiblyHidden:updateUserKeychain:interface:processName:suspendAWDLToken:isAutoJoin:error:]`（该 selector 名字面量在 airportd `0x100115e1e`，被 `0x10000d7f0` 引用）。
3. **关联流程走到 private MAC 之后才停**：`Assoc: Router info doesn't match…` → `PRIVATE MAC: Did update device key/rotation key` → `PRIVATE MAC: Successfully created private MAC` → `Assoc: Will use private MAC address for association (mac=aa:8e:cf:ee:26:ec …)` → `PRIVATE MAC: Successfully set networkID`。**之后该线程（tid 0x4401）再无任何日志。**
4. **它没有停在扫描结果缺失上**：private MAC 阶段已经把目标 BSS 完整物化（`bssid=…, channel=2g13/20, rssi=-22, age=255734ms`），说明 scan result/RNR/BSS 字段足够。
5. **它也没有停在 private MAC / SDP 失败上**：`returned error ((null))`、`Successfully set networkID`，都成功。
6. **阻塞窗口在 airportd `0x10000d6bc`（`setNetworkIDForAssociationWithMACAddress:networkProfile:` 返回之后）到 `0x10000d804`（`setAssociatedNetwork:` 之前）之间**，即 `0x10000d804` 的 `setAssociatedNetwork:` 及后续 `0x10000d880` 的 `Will associate to [%@], hasPassword=%d` 日志**一次都没有发生**。窗口内的可直接阻塞的子调用已逐条解出（见 §4）。
7. **驱动侧确实一次 Set 关联都没收到**：日志里所有 `Apple80211SetWithIOCTL` 的 type 只有 `216/363/469/483/490/512/51/575`；ioreg `AssociationRequests=0`、`LastRequest=96`；提交 16 条请求历史里没有 20/254。
8. **错误码 60 不是驱动错误码**：同一条日志直接给出 `END REQ [ASSOC] took 120.028665510s … err=60 reply=(null)`。60 = 该 XPC 请求超时后回填的错误（数值与 POSIX `ETIMEDOUT=60` 一致，`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/errno.h:177`）。
9. **修正一个前提**：并不是"02:19 之后再也没有 private MAC + 254"。**19:23:38 这一轮 private MAC、networkID 全部成功**，与 02:19 的差异发生在**更后面**（Set 下发/等待链路事件），不在 private MAC 决策。
10. 属性 `CommandErrors / ReqCount ≈ 45%`（19:37 时 3919/8748），其中绝大多数是 `APPLE80211_IOC_EXTERNAL_POWER_STATE(483)` 每次都返回 `-3903`，与关联阻塞无直接因果，但属于同一批"27 新增 Set 未实现"缺口。

---

## 1. 取证方法与产物（可复现）

### 1.1 运行时日志（关键突破点）

`airportd` 的日志在 a2x 下**不会**出现在 `log show --predicate 'process == "airportd"'` 里：

- `log show --last 12h --info --debug --predicate 'process == "airportd"'` → 只有表头（0 条）。
- 实际进程名被记成 **`a2xhost-mac`**。用 `processID == 293` 才拿到全量（22 分钟 35797 行，其中 13928 行 `corewifi`）。

命令（写进脚本避免 `log` 工具在 a2x 下的谓词解析 bug）：

```bash
/usr/bin/log show --last 22m --info --debug --predicate 'processID == 293' --style compact
```

另外两份现场日志：

- `/var/log/wifi.log`（11 MB，airportd 自己的文件日志，带 `(file.m:line)`；但**不含** CoreWiFi/Assoc 模块，见 §6 的坑）。
- `/var/log/airportd-a2x.log`（airportd stderr，只有 `AssertMacros`）。

### 1.2 静态：CoreWiFi.framework（x86_64，共享缓存）

磁盘上 `/System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi` **不存在**（cache-only）。`dyld_info` 能读，`otool` 不能。自写提取器：

1. 解析 `dyld_shared_cache_x86_64` 头 + mapping 表（7 个 cache 文件 `.00…​.06`），建立 `vmaddr → (file, offset)`；
2. 从 `dyld_cache_image_info` 数组（主 cache 文件偏移 `0x1018`，1454 项）定位 image：CoreWiFi `vmaddr=0x7ff81ee32000`；
3. 按 `LC_SEGMENT_64` 重排段、修 `fileoff`/`section.offset`，清零 `LC_SYMTAB/LC_DYSYMTAB/LC_DYLD_CHAINED_FIXUPS` 等；
4. `llvm-objdump -d` 反汇编（952028 行）。

产物（`/tmp`，易失）：`/tmp/cw/CoreWiFi.x86_64`、`/tmp/cw/cw.dis`。

### 1.3 静态：airportd（arm64e）

`lipo -thin arm64e` → `otool -arch arm64e -tV`（229025 行）+ `otool -arch arm64e -ov`（ObjC 元数据/`__objc_selrefs` 名字表）。airportd 的 `__TEXT vmaddr=0x100000000`、`fileoff=0`，所以 **VA = 0x100000000 + 文件偏移**。

`__objc_stubs`（`0x1000e36c0…0x1000f39a0`）是"选择子特化 stub"，每个 stub 里 `adrp x1 / ldr x1,[x1,#imm]` 载入一个选择子字面量。把它解出来即可还原所有 `bl 0x1000eXXXX` 的选择子（脚本解出 2344 个 selref 槽）。本文 §4 的调用名都来自这个方法。

---

## 2. Q1：`[ASSOC]` 进来后第一个失败/阻塞点

### 2.1 请求确实被机场守护进程接收

```
19:23:37.099 [corewifi] BEGIN REQ [ASSOC] (pid=3050 proc=Wi-Fi bundleID=com.apple.wifi-settings-extension
              service=com.apple.private.corewifi.internal-xpc qos=25 intf=(null) uuid=4054B info=<redacted>)
19:23:38.086 [corewifi] BEGIN REQ [ASSOC] (… uuid=265C1 …)
19:25:37.127 [corewifi] REQ TIMEOUT [ASSOC] after 120.028503724s (… uuid=4054B)
19:25:37.127 [corewifi] END REQ [ASSOC] took 120.028665510s (… err=60 reply=(null)
19:25:38.126 [corewifi] REQ TIMEOUT [ASSOC] after 120.040112909s (… uuid=265C1)
19:25:38.127 [corewifi] END REQ [ASSOC] took 120.040235998s (… err=60 reply=(null)
```

同一个 120 s 周期内，airportd 仍在正常服务其它 XPC 请求（`GET SSID / GET POWER / SCAN / GET CURR SCAN RESULT` 等都有 `END REQ … err=0`），**所以不是进程级死锁，而是关联这条请求的 handler 卡住**。

### 2.2 关联实现走到了哪一步

tid `0x4401` 的完整序列（19:23:38.078 → .323）：

```
19:23:38.086 BEGIN REQ [ASSOC] uuid=265C1              ← 第二条 ASSOC 在本线程
19:23:38.088 airportdProcessDpsEvent: DPS event: 2 on interface en1 type:0
19:23:38.320 Assoc: Router info doesn't match, assignning colocated scope id (944C801D-…)
19:23:38.321 PRIVATE MAC: Did update device key (<redacted>)
19:23:38.322 PRIVATE MAC: Did update rotation key (<redacted>) (interval=86400s)
19:23:38.323 PRIVATE MAC: Successfully created private MAC (…) returned error ((null))
19:23:38.323 Assoc: Will use private MAC address for association
              (mac=aa:8e:cf:ee:26:ec, macData=aa8ecfee26ec, …, channel=2g13/20, rssi=-22, age=255734ms (0))
19:23:38.323 PRIVATE MAC: Successfully set networkID (<redacted>) for association (…)
            ← 此后 tid 0x4401 在本会话日志中再无输出
```

（`PRIVATE MAC: Forgetting IP configuration for updated networkID` 与 `ipconfig_forget_network(en1) succeeded` 由另一线程 `0x2af4` 在 .323/.324 完成，属异步分支。）

### 2.3 代码级定位：停在哪个窗口

airportd 中这四条日志的交叉引用（`adrp+add` 解出，各只有 1 处）：

| 字符串 VA | 引用点 | 文本 |
| --- | --- | --- |
| `0x1001164f4` | `0x10000d67c` | `<%s[%d]> Will %suse private MAC address for association (mac=%@, macData=%@, network=%@)` |
| `0x100116553` | `0x10000d7d0` | `<%s[%d]> [NWTRANSIT]: %s: Debounce the Link` |
| `0x100116581` | `0x10000dd6c` | `<%s[%d]> [DISASSOC] Will disassociate due to new association request` |
| `0x100116618` | `0x10000d878` | `<%s[%d]> Will associate to [%@], hasPassword=%d` |

四条都在同一个函数里 —— 即 `-[CWXPCSubsystem __associateToWiFiNetwork:…]`（函数名 `%s` 实参由 `0x10000d7f0` 从 `0x100115e1e` 载入）。

执行序列（arm64e，地址即真实 VA）：

```
0x10000d678  adrp x1, 0x100116000
0x10000d67c  add  x1, x1, #0x4f4          ; "Will %suse private MAC address…"
0x10000d684  bl   _IO8Log2                ;  ← 实际打印的最后一行为本行
0x10000d688  ldr  x0, [x19, #0x810]
0x10000d68c  bl   0x1000f1ba0             ; -[<obj> sharedXPCManager]
0x10000d690  bl   0x1000ec7e0             ; -[<mgr> privateMACManager]
0x10000d6a0  cbnz x8, 0x10000d6b0
0x10000d6a8  bl   0x1000ebca0             ; -[<net> networkProfile]
0x10000d6b4  mov  x2, x23
0x10000d6b8  bl   0x1000f0080             ; -[<pm> setNetworkIDForAssociationWithMACAddress:networkProfile:]
0x10000d6bc  str  x0, [sp, #0x40]         ; ← 已返回；"Successfully set networkID" 已打印
   …（构造 block：isa/flags/invoke/descriptor）…
0x10000d76c  add  x2, sp, #0x1e8
0x10000d770  bl   _CFRunLoopPerformBlock   ; (rl=*(0x100168a20), kCFRunLoopCommonModes, block)
0x10000d780  bl   _CFRunLoopWakeUp
0x10000d798  bl   0x1000ea2a0             ; -[<intf> interfaceMode]        → x21
0x10000d7a8  bl   0x1000e76a0             ; -[<intf> capabilities]
0x10000d7b4  bl   0x1000e7d00             ; -[capabilities containsObject:@(…)]
0x10000d7c8  tbnz w8, #0, 0x10000dd34     ; 分支
0x10000d7cc  … [NWTRANSIT]: Debounce the Link        ← 未出现
0x10000dd34  switch(interfaceMode) 1/2/3:            ← 未出现
             1 → "Will disassociate due to new association request"
             2 → __stopIBSSModeWithInterface:error:
             3 → __stopHostAPModeWithInterface:error:changeInterfaceRoleToSTA:
0x10000d804  bl   0x1000edee0             ; -[<intf> setAssociatedNetwork:]      ← 未到达
0x10000d820  bl   0x1000f0380             ; -[<intf> setPreferredNetworkID:]
0x10000d83c  bl   0x1000f3060             ; -[<intf> updateDynamicStoreWithEntries:removeKeys:]
0x10000d85c  bl   0x1000e4620             ; -[<self> __descriptionForNetwork:]
0x10000d880  bl   _IO8Log2                ; "Will associate to [%@], hasPassword=%d"  ← 未到达
```

**结论（可核对）**：`tbnz` 的**两条**分支（落空 → `0x10000d7cc` 的 `Debounce` 日志；命中 → `0x10000dd34` 的 `switch`）中，`switch` 的 case 2/3 与 default 都汇合到 `0x10000d804`，case 1 先打 `[DISASSOC] Will disassociate due to new association request`（其后还会打 `Disconnecting from auto hotpost…` 或跳 `0x10000e85c`）。**也就是说：只要执行到 `0x10000d7c8`，四条格式串里必然至少打印一条。** 而日志里 `Debounce`、`[DISASSOC]`、`stopIBSS`、`stopHostAP` 与 `Will associate to` **一条都没有** ⇒ **执行流在 `0x10000d6bc` 与 `0x10000d7c8` 之间就被卡住了**。

窗口内的调用（全部已解出选择子，见 §1.3 方法）：

| 地址 | 调用 | 是否可能同步等待 |
| --- | --- | --- |
| `0x10000d6b8` | `setNetworkIDForAssociationWithMACAddress:networkProfile:` | 已返回（内部日志已打印），但其内部触发的 IPConfiguration forget 走另一线程 |
| `0x10000d770` | `CFRunLoopPerformBlock(mainRL, commonModes, ^{…})` | 不阻塞；**但 block 是否被执行取决于该 run loop 是否有线程在跑** |
| `0x10000d780` | `CFRunLoopWakeUp(mainRL)` | 不阻塞 |
| `0x10000d7a0` | `interfaceMode` | 即时 |
| `0x10000d7b4` | `capabilities` + `containsObject:` | 即时 |
| （`0x10000d804` 之后） | `setAssociatedNetwork:` / `setPreferredNetworkID:` / `updateDynamicStoreWithEntries:removeKeys:` / `__descriptionForNetwork:` | 均未到达 |

> 说明：`CFRunLoopPerformBlock` 的目标 run loop 是全局 `*(0x100168a20)`（airportd 主 run loop，`dq:'com.apple.main-thread'`）。窗口内**唯一**可能无限期同步等待的外部子系统是 `setNetworkIDForAssociationWithMACAddress:` 内部对 IPConfiguration 的等待（`ipconfig_forget_network` 已成功，但完成信号是否回调到该线程未验证）。
> **未验证**：精确到某一条指令的阻塞点（需要 `sample`/`lldb` 附加 root 进程，本会话无 sudo，无法做）。

### 2.4 不是这些原因（逐条排除）

| 假设 | 判定 | 证据 |
| --- | --- | --- |
| 等 scan done 事件 | 否 | 19:23:38.315 已有 `AutoJoin: Successful cache-assisted scan request`；private MAC 已用到具体 BSS |
| 等扫描结果字段（RNR/BSS/IE） | 否 | `Will use private MAC address … bssid=…, channel=2g13/20, rssi=-22, rsn=[…]` 字段齐全 |
| private MAC / SDP 失败 | 否 | `Successfully created private MAC … returned error ((null))`、`Successfully set networkID` |
| 等 XPC 子请求 | 否（本段） | 窗口内无 `BEGIN SUBREQ`；子请求 `SUBREQ [SCAN]` 出现在 AUTO-JOIN 阶段且已完成 |
| 驱动可用性事件缺失 | 否（本段） | 该请求流未出现 driver-available 相关等待；`DriverAvailabilityReplays` 只影响 `MonitorStart` 快照 |
| 电源关闭 | 否 | 否则会打印 `Failed to associate … because power is OFF`（`0x1001166b5`），未出现 |
| 自动解锁中 | 否 | 否则会打印 `Association not permitted … auto-unlock is in progress`（`0x100116649`），未出现 |
| 进程崩溃/死锁 | 否 | airportd 全程存活并持续服务其它请求 |

---

## 3. Q2：02:19 与当前这轮的差异

**前提需要修正**：本轮（19:23:38）**同样走到了** private MAC 与 `set networkID`，与 02:19 的日志级别一致。因此"02:19 之后不再出现 private MAC"是观测偏差（此前会话没有按 `processID` 抓 CoreWiFi/airportd 日志，只看 `process == "airportd"` 会 0 条）。

真正差异在 private MAC **之后**：

| 项 | 2026-11-17 02:19（pid 41224） | 2026-11-17 19:23（pid 293） |
| --- | --- | --- |
| private MAC 创建 | 有（父代理记录） | **有**（`Successfully created private MAC`） |
| networkID 设置 | 有（父代理记录） | **有**（`Successfully set networkID`） |
| 驱动侧请求 254 | `LastRequest=254 / LastResult=0` | **无**（`AssociationRequests=0`、历史无 20/254） |
| XPC 请求超时 | 未见记录 | `REQ TIMEOUT [ASSOC] … err=60`（两条） |

即：02:19 那次至少把 **254 这条 Set 发到了驱动**；本轮没有。两者在 airportd 代码里的分界点就是 §2.3 的窗口。**（02:19 的 unified log 已不可回溯：`log show --start "2026-11-17 02:18:30" --end "2026-11-17 02:26:00" --predicate 'processID == 41224'` 返回 0 条；`/var/log/wifi.log` 对该模块不记录。因此 02:19 到底停在哪一步，本报告只能给出"它越过了 Set 下发"这一事实，**更细的对照未验证**。）**

可以确定的是：**airportd 启动时间、TCC、钥匙串、扫描缓存都不是这两轮的关键差异**——因为两轮都已经完成到同一阶段，差别在之后的 Set 下发/等待。

---

## 4. Q3：错误码 60 的来源（有直接证据）

同一条日志里由 CoreWiFi 的 XPC 请求框架回填：

```
19:25:37.127 [corewifi] END REQ [ASSOC] took 120.028665510s (pid=3050 proc=Wi-Fi … uuid=4054B err=60 reply=(null)
```

- 该行格式串 `[corewifi] END %{public}@ [%{public}@] took %0.9fs (… err=%ld)` 位于 CoreWiFi `VA 0x7ff81f2bdbd0`（`__TEXT` image off `0x48bbd0`）；超时那条 `[%@] FAILED to complete request before default timeout (%.6fs)` 位于 `VA 0x7ff81f2bdba0`，其唯一引用点是 `0x7ff81eedccbb`（`_os_log_impl(&__mh_execute_header, log, type, fmt, buf, 22)` 在 `0x7ff81eedcccb`，`%r9d=0x16` 为 format buffer 长度）。
- 数值 60 与 POSIX `ETIMEDOUT` 一致（SDK `usr/include/sys/errno.h:177`）。**它是请求超时的返回码，不是驱动/固件错误码**；驱动侧同期 `LastResult=0`、`AssociationRequests=0`，没有产生任何关联错误。
- 因此：**60 = "airportd 没能在这个请求的 default timeout（此处 120 s）内完成"**。UI 的"未能加入（60）"是这个超时值的直接外显，不是关联被拒。

---

## 5. Q4：修哪里，怎么验证

### 5.1 驱动侧（SimpleBCM）——对本问题**不是**最小改动点

证据：请求**根本没有走到** `Apple80211Set` 关联分支。

- 本轮全部 `Apple80211SetWithIOCTL` 的 type 集合：`{51, 216, 363, 469, 483, 490, 512, 575}`；无 20、无 254。
- `Apple80211Associate2` 在 458 条 Set 日志与 2445 条 Get 日志中**一次都没出现**（`grep -c Apple80211Associate` = 0）。
- ioreg：`AssociationRequests=0`、`LastRequest=96`、`Rejects=0`、`LastRejectKind=0`。

所以"补字段/补事件"不能解开这个阻塞；驱动侧当前的缺口（`483 EXTERNAL_POWER_STATE → -3903`、`103 CURRENT_NETWORK → -3903`、`363 USB_HOST_NOTIFICATION` 等 27-only Set 返回 `0x66`）是**并行的**问题。

### 5.2 用户态（airportd 内的 CoreWiFi 关联实现）——真正的修复面

阻塞点在 airportd（arm64e guest）里的 `-[CWXPCSubsystem __associateToWiFiNetwork:…]`，窗口 `0x10000d6bc–0x10000d7c8`。修复方向按优先级：

1. **先定位到具体语句**（诊断优先，不改行为）：在窗口内加 trace（计数器/日志），把 `CFRunLoopPerformBlock` 之后 block 是否执行、`setNetworkIDForAssociation…` 返回时刻、`interfaceMode`/`capabilities` 取值记下来。这属于 workspace 里的分析工具或 kext 侧 trace，不动系统文件。
2. **若确认是 `CFRunLoopPerformBlock(mainRL)` 之后等待主 run loop**：这是 a2x 转译下最可疑的一类 —— 主线程 run loop 被 CoreWiFi 的其它同步等待占用/未及时 `CFRunLoopRun`，则 block 永不执行。**已做的初步测量不足以判定**：`/var/log/wifi.log` 在 19:23–19:26 整个窗口只有 9 行（`dq` 分布为 `com.apple.airportd.server.timer.q` 8 行、`xpc-subsystem.internal` 1 行），`com.apple.main-thread` 0 行 —— 样本太少，无法据此断言主 run loop 停止运转。要判定需在窗口内统计主线程是否仍在消费 CFRunLoop 源（例如用 `sample`/`lldb`，本会话无 sudo）。
3. **若确认是 IPConfiguration forget 的完成信号未回到该线程**：属 CoreWiFi 与 `IPConfiguration.framework` 的交互，仍需用户态侧解决。

> 约束提醒：按工作区规则，系统文件（含 CoreWiFi.framework、airportd）**不得替换或二进制修补**。因此这里的"修复"只能是：定位根因 → 判断是否属于已被用户授权的**转译层（a2x）**范围；若属于 a2x 的 ObjC/runloop 桥接缺陷，则在 a2x 侧修；否则只能给出证据与技术边界，不能改系统组件。

### 5.3 验证方法（不依赖猜测）

- **判据 A（下发成功）**：`ioreg -rn SimpleBCM -l` 出现 `AssociationRequests >= 1`，且日志出现 `IOCTL type 20/254` 的 `Apple80211SetWithIOCTL`。
- **判据 B（阶段推进）**：`log show --predicate 'processID == <airportd pid>'` 中出现 `Will associate to [<bssid>], hasPassword=…`（`0x10000d880`）。
- **判据 C（不再超时）**：不再出现 `REQ TIMEOUT [ASSOC]`；`END REQ [ASSOC] … err=0`。
- **判据 D（真实行为）**：`/usr/libexec/airportd` + 设置里连接「401」后 `en1` 进入 associated（`GET SSID/BSSID/CURRENT_NETWORK` 返回 0），且能拿到 IPv4。
- 回归项：让上述四条与 `ScanRecords`/`ScanDoneRecords` 增长、`CommandErrors` 不恶化同时成立。

---

## 6. 取证过程中的坑（供后续复用）

1. `log show --predicate 'process == "airportd"'` 在 a2x 下**恒为空**；真实进程名是 `a2xhost-mac`，必须用 `processID ==`。
2. `log` 工具（也是 a2x guest）对含 `CONTAINS`/引号的谓词会抛 `NSInvalidArgumentException`（`predicateWithFormat` 变参被桥接破坏），只能用 `==` 形式。
3. `/var/log/wifi.log` 有 `(file.m:line)` 但**不含** `Assoc:`/`PRIVATE MAC`/`Will associate to` 这些模块（02:19 与 19:23 两轮都验证过）。
4. CoreWiFi 在磁盘上无文件（cache-only）；`otool` 打不开，`dyld_info` 能读；要反汇编必须自己按 mapping 表从 7 个 cache 文件里拼。
5. airportd **没有符号表**（`nm` 只有 831 条 undefined），但 `__objc_stubs` 的每个 stub 内嵌选择子字面量，可按 §1.3 的方法还原调用名 —— 这是本次能读懂 `0x10000d6xx` 这段代码的关键。
6. airportd 里确实含有 `-[CWXPCSubsystem …]`（132 处 `__FUNCTION__` 字面量），但 **XPC 请求追踪日志（BEGIN/END/TIMEOUT/`err=60`）来自 CoreWiFi.framework**（这些格式串在 airportd 里为 0 条，日志的 sender image 也是 `(CoreWiFi)`）。两处代码不要混为一谈。

---

## 7. 证据清单（关键行）

```
# 请求进入 / 超时 / err=60
19:23:37.099 BEGIN REQ [ASSOC] (pid=3050 … service=com.apple.private.corewifi.internal-xpc … uuid=4054B)
19:23:38.086 BEGIN REQ [ASSOC] (… uuid=265C1)
19:25:37.127 (CoreWiFi) [ASSOC] FAILED to complete request before default timeout (120.000000s)
19:25:37.127 REQ TIMEOUT [ASSOC] after 120.028503724s (… uuid=4054B)
19:25:37.127 END REQ [ASSOC] took 120.028665510s (… err=60 reply=(null)
19:25:38.126/127 同上（uuid=265C1, err=60）

# 阻塞前后（tid 0x4401）
19:23:38.320 Assoc: Router info doesn't match, assignning colocated scope id (944C801D-…)
19:23:38.323 PRIVATE MAC: Successfully created private MAC (…) returned error ((null))
19:23:38.323 Assoc: Will use private MAC address for association (mac=aa:8e:cf:ee:26:ec …)
19:23:38.323 PRIVATE MAC: Successfully set networkID (…) for association (…)
（之后 tid 0x4401 无输出）

# 驱动侧无关联 Set
grep "Apple80211SetWithIOCTL" → type 集合 {51,216,363,469,483,490,512,575}
grep -c "Apple80211Associate" → 0
ioreg SimpleBCM: AssociationRequests=0  LastRequest=96  Rejects=0  (19:37 ReqCount=8748 CommandErrors=3919)
```

---

## 8. 未验证 / 待补

1. **窗口内精确阻塞指令**：`0x10000d6bc` 与 `0x10000d7c8` 之间到底停在哪条调用（`setNetworkIDForAssociation…` 内部等待 IPConfiguration 完成？还是 `CFRunLoopPerformBlock` 的目标 run loop 未运行？）。需要 `sample`/`lldb` 附加 root 的 airportd，本会话无 sudo。
2. **02:19 那一轮的完整序列**：unified log 已滚出保留窗口，`wifi.log` 不记录该模块，无法逐行对照。
3. **254 的符号名**：本次运行没有发生 254，日志无法给出 `IOCTL type 254/'APPLE80211_IOC_…'` 的名字；20/254 的语义仍以父代理的 27 表解码为准（slot 20 空、254 有 handler）。
4. `CommandErrors` 45% 与关联阻塞**无因果**的判断基于"错误集中在 483 且返回值恒为 -3903"，未逐类统计全部 3919 次错误。
