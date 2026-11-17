# 27.2 扫描/关联 ABI 缺口复验：AssociateLengthMismatch、请求 86、扫描结果多记录

日期：2026-11-18（Asia/Shanghai）
系统：macOS 27.2（26B123，Darwin 27.2.0，x86_64，Mac15,14）
硬件：BCM43602（`pci14e4,43ba`），`en1`
仓库：`/Users/geek/Documents/Macintosh/simplebcm-r27`，分支 `wifi-assoc-probe`
取证对象：

| 对象 | 路径 / 地址基准 | 说明 |
| --- | --- | --- |
| SimpleBCM 源码 | 仓库 HEAD | 实际 HEAD 为 `b6dc085`（比任务描述的 `222ed98` 多一个 Docs-only 提交）；关联/扫描相关代码与 `222ed98` 相同 |
| 运行期 kext | `kextstat`：`cn.laobamac.SimpleBCM 1.2.1`，UUID `5E82D19F-E3B8-3DAA-8110-FC90C8A08050` | 与 workspace 里 84348ff 构建（`…81FB-F7A34A49B204`）只差 UUID 尾部；`C103Hits>0` 证明确实包含 84348ff 的 103 补丁 |
| 27 内核 IO80211Family | `/System/Library/KernelCollections/BootKernelExtensions.kc`，基址 `0xffffff8001e80000` | 只用 `Tools/kernel_collection.py` 只读读取 |
| payload0（IO80211FamilyLegacy） | `.research/extract/payload0.bin`，基址 0 | 当前注入的 legacy 栈 |
| 运行期 | `ioreg -rn SimpleBCM -l`、`system_profiler SPAirPortDataType`、`/usr/bin/log show` | 只读；扫描触发未修改系统 |

> 取证边界：本会话无 `sudo`，未修改 `/System`、`/Library`、EFI，未重启、未部署；实验全部在 `/tmp`。
> 运行期 kext 的确切文件在 EFI 分区内，无法在无 root 的情况下读取，因此不能对 live 二进制做哈希对齐；但 `AssociateLengthMismatch` 的递增代码自 `aedf7d1` 起未变，HEAD 与 `222ed98` 在该区域相同。
> `/usr/bin/log` 在本机走 a2x 翻译，带 `--predicate` 会 NSException；本文的日志证据来自无 predicate 的 45 分钟窗口 dump（200 MB，已删除）。日志只作辅助，结论以 ioreg 计数器 + 反汇编为准。

---

## 0. 结论摘要

1. **`AssociateLengthMismatch = 4` 就是 4 次 27 的 `0x290` 关联，不是 4 次失败。** 4 次全部经过 `-sbcmggassoc` 的 golden gate，全部到达驱动并成功（`AssociationAccepted=4`、`DriverAssociateRequests=4`、`LastAssociationResult=0`）。
2. **只要 27 发 `0x290`，这个计数器就必然增长**，因为它的条件是 `header->length != abi.associateSize`（`0x290 != 0x38C`），在 golden gate 之前、且不区分 gate 是否成功。它是“布局差异计数器”，不是“拒绝计数器”。
3. **27 自身的 ASSOCIATE ABI 明确是 `0x290`**：27 新 handler `setASSOCIATE` 把 `0x290` 传给 `routeIoctlToWcl`；27 legacy handler `setAssociateRequest` 分配 `0x290` 栈缓冲、按 `0x290` clamp copyIn，并在同一偏移上校验 ssid/rsn/pmk/bssidCount/scope。实际运行期 `LastAssociateLength=656=0x290`。
4. **请求 86 在 27 里是死代码**：`gSetHandlerTable` / `gSetHandlerTableLegacy` / `gInternalSetHandlerTable` 的 type 86 槽位全部为 NULL；`apple80211setSCAN_REQ_MULTIPLE` 和 get 版本都是 11 字节 stub（返回 `0xE082280E`），整个 KC 中没有直接 call 或数据表引用。27 实际扫描走 **type 10，长度 `0x1598`**（运行期 `LastSetType=10`、`LastSetLength=5528`、`LastSetResult=0`）。
5. **SimpleBCM 的 86 直通只在客户端发 `0x14E8` 时安全**；字段布局与 27 的 `fastScanMultiple` 完全一致，只有总长度差 8 字节（`0x14E8` vs `0x14E0`），且字段访问最高只到 `0x14D8`。若 27/第三方客户端发 legacy 的 `0x14E0`，当前本地门槛会直接拒绝——这是 86 路径唯一的实际缺口。
6. **27 的 get 11 是“一次一条 0x8E8 记录”**：新 handler 硬门禁 `cmpl $0x8e8, 0x18(%rcx)`，随后走 WCL 或 `apple80211getSCAN_RESULT`；两者都只填一个 `apple80211_scan_result`。payload0 的 `getScanResult` 也是一次弹一条记录、返回 5 表示队列空。`ScanRecords` = 成功 get 11 的次数 = 已交付记录数；`ScanDoneRecords` 名字有误导，它其实是 scan-done 事件写入客户端 ring 的次数（≈客户端数 × `ScanDoneEvents`）。
7. **额外发现（比 86 更值得记录）**：27 的 type 10 扫描缓冲是 `0x1598`，legacy payload0 的 `setScanRequest` 只分配/拷贝 `0x1550`。当前扫描成功，因为 payload0 用 `min(req->length, 0x1550)` 截断，且关键字段都在前缀内；但 27 请求尾部 `0x48` 字节被静默丢弃。这是独立的 ABI 差异，需要单独取证，不要和 86 混在一起。

---

## 1. `AssociateLengthMismatch = 4` 的来源

### 1.1 代码路径（SimpleBCM）

`SimpleBCM/UserClient.cpp`：

| 行 | 代码 / 行为 |
| --- | --- |
| 287 | `const bool associate = set && request == bcm::AssociateRequest;`（set type 20） |
| 288-289 | `const bool goldenGateAssociate = associate && abi.kernel == 27 && header->length == bcm::GoldenGateAssociateSize;` |
| 350-355 | `associationRequests++`、`lastAssociateLength = header->length`、`if (goldenGateAssociate) goldenGateAssociateRequests++`、`if (header->length != abi.associateSize) associateLengthMismatch++` |
| 368 | 拒绝门禁：`(associate && !goldenGateAssociate && header->length != abi.associateSize) → goto done` |
| 407-410 | `if (associate && goldenGateAssociate && !prepareAssociateGoldenGate(..., goldenGateAssociateEnabled())) goto done` |

`SimpleBCM/WirelessABI.hpp`：

| 行 | 常量 / 行为 |
| --- | --- |
| 64-72 | `GoldenGateAssociateSize=0x290`、`Native=0x38C`、gap `0x1FC`、ssid `0x10`、rsn `0xD0`、pmk `0x1D8`、bssidCount `0x202`、scope `0x240` |
| 381-413 | `prepareAssociateGoldenGate()`：校验 0x290 字段 → 0x290 插入 4 字节 gap 变成 0x38C → 复用 `prepareAssociate()` → 最终 `request.length=0x224`（legacy 驱动结构） |
| 141 | `static_assert(GoldenGateABI.associateSize == GoldenGateNativeAssociateSize)`，即 `abi.associateSize == 0x38C` |

关键点：**`associateLengthMismatch` 在 `prepareAssociateGoldenGate()` 之前递增**，且条件只有 `header->length != abi.associateSize`。27 的 `0x290` 与 `0x38C` 永远不相等，所以 golden gate 成功与否都会 +1。这不是代码 bug，而是计数器语义把“27 布局”和“拒绝”混在一起了（`Bridge.hpp:86-89` 的注释也写明它统计“包括 27 的 0x290 布局”）。

### 1.2 运行期证据（2026-11-18 05:19–05:31，boot-args 含 `-sbcmggassoc -sbcm103`）

```
ioreg -rn SimpleBCM -l
  ActiveABI                       = "GoldenGate"
  AssociationRequests             = 4
  GoldenGateAssociateRequests     = 4
  AssociateLengthMismatch         = 4
  LastAssociateLength             = 656          (= 0x290)
  AssociationAccepted             = 4
  LastAssociationResult           = 0
  DriverAssociateRequests         = 4
  DriverAssociateHookReady        = 1
  LastDriverAssociateWord         = 1
  AssociationEvents               = 4
  AssociationEventsClassic        = 4
  AssociationEventsSkywalk        = 0
  AssocSsidLength                 = 3
  LastGoldenGateBssidCount        = 0
  LastGoldenGateScope             = 36
  GoldenGateWord0                 = 32           (0x1D8 pmkLength = 32)
  GoldenGateWord10                = 60454        (0x200..0x203 = 26 EC 00 00 → 0x202 bssidCount = 0)
  GoldenGateWord26                = 36           (0x240 scope = 36)
  CurrentNetworkValid             = 1
  C103Hits                        = 4111
```

推导链：

1. `GoldenGateAssociateRequests=4` 只在 `goldenGateAssociate` 为真时递增，而它要求 `header->length == 0x290`。所以 **4 次请求全是 0x290**；没有任何一次是 0x38C 或其它长度。
2. `AssociationRequests=4` → 全部 4 次都到了 `runCommand` 的 set+20 分支（没有走 ifnet ioctl 绕过）。
3. `LastAssociateLength=656` 是最近一次 `header->length`，与 4 次全为 0x290 的结论一致。
4. `LastGoldenGateScope=36` 是从 `shadow+0x240` 读出的；`LastGoldenGateBssidCount=0` 是从 `shadow+0x202` 读出的；`GoldenGateWord0=32` 是 `shadow+0x1D8` 的 pmkLength。这三项只在 `goldenGateAssociate` 分支执行，直接证明 0x290 布局被按 27 的偏移读取（`0x1D8/0x202/0x240`），而不是 0x38C 布局（`0x1DC/0x206/0x244`）。
5. `AssociationAccepted=4` 在 `UserClient.cpp:555-557` 只在 `associate && result == kIOReturnSuccess` 时递增；`LastAssociationResult=0`。因此 4 次全部成功返回，golden gate 的转换与 `prepareAssociate()` 都成功。
6. `DriverAssociateRequests=4` 来自 `Bridge.cpp:161-168` 对 `AirPort_BrcmNIC::setASSOCIATE` 的 hook：4 次都实际到达驱动；`DriverAssociateHookReady=1` 说明 hook 已安装。`LastDriverAssociateWord=1` 是驱动侧 `apple80211_assoc_data` 的首字（version=1）。
7. 统一日志（pid 217 = `a2xhost-mac`，即 airportd）在 45 分钟窗口内抓到 2 次 `Will use private MAC address for association`（04:45:37.985、04:45:48.642）和 2 次 `Successfully updated Wi-Fi configuration following association`（04:45:44.116、04:46:09.437）；窗口内没有 `unable to join` / `failed to join`。计数器的 4 次包含 04:36–04:41 启动窗口的另外 2 次。日志里的 WPA3-transition、`channel=2g13/20` 只说明关联对象；`LastGoldenGateScope=36` 是 associate 请求里的 scope 字段（+0x240），不是信道，两者不冲突。

### 1.3 27 侧反汇编：ASSOCIATE 请求就是 0x290

**(a) 27 新表 handler `setASSOCIATE` @ `0xffffff8001f8a1fa`**（`__ZL12setASSOCIATEP17IO80211ControllerP23IO80211SkywalkInterfaceP20IO80211APIUserClientP13apple80211req`）：

```
ffffff8001f8a295:  cmpl   $0x0, 0x18(%r13)        ; req->length != 0
ffffff8001f8a2a0:  cmpq   $0x0, 0x20(%r13)        ; req->data != 0
ffffff8001f8a2f8:  movl   $0x290, %r8d            ; ★ 传给 WCL 的长度 = 0x290
ffffff8001f8a301:  movl   $0x802869c8, %esi       ; SetCommand
ffffff8001f8a306:  movl   $0x14, %edx             ; type 20
ffffff8001f8a30b:  movq   %rbx, %rcx              ; req->data
ffffff8001f8a30e:  callq  routeIoctlToWcl
```

**(b) 27 legacy 表 handler `setAssociateRequest` @ `0xffffff800205e8bd`**：

```
ffffff800205e8f6:  movl   $0x290, %esi            ; stack buffer = 0x290
ffffff800205e920:  movl   $0x290, %ecx            ; copyIn clamp = 0x290
ffffff800205e925:  cmpl   %ecx, %eax
ffffff800205e927:  cmovbl %eax, %ecx              ; min(req->length, 0x290)
ffffff800205e941:  movl   -0x2a8(%rbp), %r10d     ; buf+0x10 ssidLength
ffffff800205e948:  cmpl   $0x21, %r10d            ; < 33
ffffff800205e966:  movzwl -0x1e8(%rbp), %r10d     ; buf+0xD0 rsnLength
ffffff800205e96e:  cmpl   $0x102, %r10d           ; < 258
ffffff800205e97b:  movl   -0xe0(%rbp), %r10d      ; buf+0x1D8 pmkLength
ffffff800205e982:  cmpl   $0x21, %r10d            ; < 33
ffffff800205e98c:  movzbl -0xb6(%rbp), %r10d      ; buf+0x202 bssidCount
ffffff800205e994:  cmpl   $0xb, %r10d             ; < 11
ffffff800205e99e:  cmpl   $0x26, -0x78(%rbp)      ; buf+0x240 scope < 38
ffffff800205e9fb:  movl   $0x290, %r8d            ; ★ routeIoctlToWcl 长度 = 0x290
ffffff800205ea24:  callq  apple80211setASSOCIATE   ; WCL 缺失时的 fallback
```

字段偏移与 SimpleBCM 的 `GoldenGateAssociate*Offset` 常量逐项一致（`0x10/0xD0/0x1D8/0x202/0x240`）；27 的界限是 `≤32 / ≤257 / ≤32 / ≤10 / <38`，其中 ssid/rsn/pmk/scope 与 SimpleBCM 一致，bssidCount 则更宽（SimpleBCM 只允许 ≤3，见 §1.5/§5）。**因此 27 的用户态 associate 缓冲不可能是 0x38C**；0x38C 是 Tahoe 时代 native `apple80211_assoc_data`，27 在框架内部完成 0x290→native 的转换。

**(c) 离线验证**（`/tmp/abitest.cpp`，包含 `SimpleBCM/WirelessABI.hpp`）：

```
associate 0x290: request.length=0x224 == abi.associateSize(0x38c)? 0 ; mismatch-counter condition=1
gate(convert=true)=1 -> driver request.length=0x224 (legacy 0x224)
gate(convert=false)=0 -> request.length=0x290 (unchanged, would goto done)
```

这直接说明：`0x290` 永远满足 `header->length != abi.associateSize`，所以计数器必然增长；gate 成功时 driver 收到的是 `0x224`（payload0 的 legacy 结构）。

### 1.4 为什么 `-sbcmggassoc` 已启用仍然出现 mismatch

因为 `-sbcmggassoc` 只影响 `prepareAssociateGoldenGate()` 的 `convert` 参数，不影响计数器：

- gate 开：`goldenGateAssociate=true` → 0x290 被转换成 0x38C → 再转成 0x224 → 驱动成功；同时 `header->length != 0x38C` 仍为真 → mismatch +1。
- gate 关：`goldenGateAssociate=true` → `prepareAssociateGoldenGate(..., false)` 返回 false → `goto done`，默认 `result=kIOReturnBadArgument`（`UserClient.cpp:257`）→ mismatch 也 +1，但 `AssociationAccepted` 不会增长，`LastAssociationResult=0xE00002C2`。

也就是说，**mismatch=4 不能区分“gate 成功”与“gate 关闭/转换失败”**；必须结合 `AssociationAccepted`、`LastAssociationResult`、`DriverAssociateRequests`。当前三者是 4/0/4，结论是成功。

### 1.5 影响

- 功能上：无影响。4 次关联全部成功，当前网络有效（`CurrentNetworkValid=1`、`C103Hits` 持续增长）。
- 诊断上：任何看到 `AssociateLengthMismatch` 非零的人都会误以为关联失败；这是本次任务被提出的直接原因。若将来默认关闭 golden gate 或转换失败，计数器仍是 4，无法从 ioreg 一眼区分，容易误判。
- 边界上：27 legacy handler 允许 `bssidCount < 11`，SimpleBCM 的 `prepareAssociate()`（0x38C→0x224）检查 `buffer[0x206] > 3` 就拒绝；如果 27 发 4–10 个候选 BSSID，SimpleBCM 会比 27 的 framework 更严格。本次 4 个样本的 `LastGoldenGateBssidCount=0`，未触发。该差异的实机影响未验证，标记为残余缺口（§5）。

### 1.6 最小适配建议（仅描述，未改代码）

**不建议改 golden gate 的功能路径**；只改诊断语义。推荐方案 1：

1. **保留 `AssociateLengthMismatch` 作为“27 0x290 布局样本数”**（它现在就是这个含义），并在文档/属性名上明确；新增：
   - `GoldenGateAssociateFailures`：`goldenGateAssociate && prepareAssociateGoldenGate(...) == false` 时 +1。它同时覆盖 gate 关（`convert=false`）和 gate 开但字段非法两种情况；
   - `GoldenGateAssociateEnabled`：把 `Bridge::goldenGateAssociateEnabled()` 发布成 ioreg 布尔。
   这样当前基线读作“4 个 0x290 布局样本，0 个转换失败”，而不是“4 次失败”。
2. 若一定要让 `AssociateLengthMismatch` 表示“未被转换的布局”，条件必须是：
   ```cpp
   if (header->length != abi.associateSize &&
       !(goldenGateAssociate && Bridge::goldenGateAssociateEnabled()))
       associateLengthMismatch++;
   ```
   这样 gate 开且合法时 mismatch=0；gate 关时 0x290 仍 +1。**注意不要只写 `!goldenGateAssociate`**：gate 关时 `goldenGateAssociate` 仍为 true（它只看长度），只写 `!goldenGateAssociate` 会让 gate 关的 0x290 也不计数，反而丢掉诊断。即使采用方案 2，gate 开但字段非法导致 `prepareAssociateGoldenGate` 返回 false 的情况仍不会被这个条件捕获，所以仍建议保留 `GoldenGateAssociateFailures`。

另建议把 `LastAssociateLength` 保留（已有），它能直接回答“这次到底是 0x290 还是 0x38C”。

### 1.7 验证方法

```sh
ioreg -rn SimpleBCM -l | grep -E \
 'AssociationRequests|GoldenGateAssociateRequests|AssociateLengthMismatch|LastAssociateLength|AssociationAccepted|LastAssociationResult|DriverAssociateRequests|LastDriverAssociateWord|AssocSsidLength|LastGoldenGateScope|LastGoldenGateBssidCount'
```

当前基线（gate 开，未改代码）：

```
AssociationRequests=4, GoldenGateAssociateRequests=4, AssociateLengthMismatch=4,
LastAssociateLength=656, AssociationAccepted=4, LastAssociationResult=0,
DriverAssociateRequests=4, LastDriverAssociateWord=1
```

改诊断语义后的验收（按推荐方案 1）：

- 一次成功关联：`AssociationRequests`、`GoldenGateAssociateRequests`、`DriverAssociateRequests` 同步 +1；`AssociationAccepted` +1；`LastAssociationResult=0`；`AssociateLengthMismatch` 与 `GoldenGateAssociateRequests` 同步（表示“看到了 0x290 布局”）；`GoldenGateAssociateFailures` 不增；`GoldenGateAssociateEnabled=1`。
- 负向对照（需要另一次重启，本次未做）：去掉 `-sbcmggassoc` 后，`AssociationRequests`/`GoldenGateAssociateRequests`/`AssociateLengthMismatch` 仍会 +1（后两者都是 0x290 布局），但 `GoldenGateAssociateFailures` +1、`GoldenGateAssociateEnabled=0`、`AssociationAccepted` 不增、`LastAssociationResult=0xE00002C2`。这条负向对照能把“布局计数”和“功能失败”彻底分开；也说明为什么只看 `AssociateLengthMismatch` 会误判。

---

## 2. 请求 86（多通道扫描）

### 2.1 payload0 的 `setScanRequestMultiple` @ `0x86f4c`

```
86f57:  movl $0x14f0, %eax            ; 0x14E0 + 0x10 栈帧
86f85:  movl $0x14e0, %esi            ; memset 0x14E0
86fb5:  cmpl $0x14e0, 0x18(%r12)      ; ★ 入参 req->length 必须恰好 0x14E0
86fc0:  movq 0x20(%r12), %rsi         ; req->data
86fd1:  movl $0x14e0, %ecx
86fd9:  callq IO80211Controller::copyIn ; copyIn(req->data, buf, 0x14E0)
86fe7:  cmpl $0x3, -0x1308(%rbp)      ; buf+0x200 != 3（一个模式/标志）
87015:  callq getPrimaryInterfaceScanManager
87029:  callq IO80211ScanManager::startScanMultiple(buf)
```

即：payload0 只接受 **`0x14E0`**，其它长度直接返回 `0x16`（`86fb0: movl $0x16,%ebx`）。`startScanMultiple` @ `0xacb0e` 再校验：

```
acbc5:  cmpl $0xa, 0x8(%r13)         ; 通道/SSID 项数 ≤ 10
acbd0:  cmpl $0x10, 0x19c(%r13)      ; 通道数 ≤ 16
acce1:  movl 0x210(%r13), %eax       ; 漫游/候选列表数
acd26:  testb $0x20, 0x14d8(%r13)    ; 尾部位标志，最高访问 0x14DB
```

`fastScanMultiple`（payload0 @ `0xac8cc`）读取的字段：

| 偏移 | 含义 | 证据 |
| --- | --- | --- |
| +0x4 | u32 标志/版本 | `ac940` |
| +0x8 | 项数 | `ac984`/`ac9f5` |
| +0x10 + i*0x28 | 每项长度（≤32） | `ac99d`/`ac9a2` |
| +0x14 + i*0x28 | 每项 32 字节 SSID | `ac9ac`/`ac9be` |
| +0x19C | 通道数（≤16） | `ac9c6` |
| +0x1A0 | 每项 6 字节（通道/band） | `aca19`/`aca59` |
| +0x200 | u32（27/payload0 的 `startScanMultiple` 都会看） | `ac979`/`acb56` |
| +0x204 | u32 | `ac96a` |
| +0x210 | 候选/结果数 | `ac944` |
| +0x214 | 0x12C0 字节块 | `ac95d` |

有效字段最高到 `0x14D8`，**没有超过 0x14E0**。

### 2.2 27 侧：type 86 是死代码

**表项**（`Tools/kernel_collection.py` 读 `com.apple.iokit.IO80211Family`）：

| 27 表 | type 86（1-based，slot 85） |
| --- | --- |
| `__ZL16gSetHandlerTable` @ `0xffffff800218d590` | `0`（NULL） |
| `_gSetHandlerTableLegacy` @ `0xffffff80021a6b10` | `0`（NULL） |
| `__ZL24gInternalSetHandlerTable` @ `0xffffff80021abf90` | `0`（NULL） |

**函数**：

```
ffffff8001f6c7da  apple80211setSCAN_REQ_MULTIPLE:
  55                    push rbp
  48 89 e5              mov rbp, rsp
  b8 0e 28 82 e0        mov eax, 0xE082280E
  5d                    pop rbp
  c3                    ret
（get 版本 @0xffffff8001f6783f 完全相同，11 字节）
```

- 全 KC 扫描：没有任何 `call rel32` 指向 `0xffffff8001f6c7da`，也没有数据段引用该地址（chained-fixup 编码扫描）。
- 结论：27 的内核**不实现** type 86；即使某个客户端发 86，27 自己的分派器也不会调用上述 stub（slot 为 NULL）。
- 补充：27 仍有 `IO80211ScanManager::fastScanMultiple` @ `0xffffff8001fe4cde` 的实体（多扫描字段处理逻辑），但本次没有找到它的直接 call、表项或数据指针引用；“有内部函数、没有可达的 86 入口”是本节的准确表述，不影响 §2.4 用它的字段布局做对照。

### 2.3 27 实际扫描路径：type 10，长度 `0x1598`

运行期实测（触发一次 `system_profiler SPAirPortDataType` 扫描，以 50 ms 间隔轮询 `SetHist`/`SetLen` 80 次）：

```
SetHist/SetLen pairs: [(10, 5528), (483, 1)]      # 5528 = 0x1598
LastSetType=10, LastSetLength=5528, LastSetResult=0
Req types seen: [1,2,4,8,9,10,11,12,15,16,19,27,28,43,44,48,51,57,69,70,96,103,207,483]
```

**只有 type 10 和 483；没有 86。** 扫描完成、有结果（`ScanRecords` 增长，`system_profiler` 列出 2.4G/5G 网络）。

27 静态侧也明确把 type 10 的长度写死为 `0x1598`：

```
ffffff8001f8a0e9  setSCAN_REQ:
  ...  cmpl $0x0, 0x18(%rcx)          ; 只要 req->length != 0
  ffffff8001f8a125  movl $0x1598, %r8d ; ★ routeIoctlToWcl 长度 = 0x1598
  ffffff8001f8a13b  callq routeIoctlToWcl
  ...  fallback: apple80211setSCAN_REQ
```

27 legacy 表 `setScanRequest` @ `0xffffff800205e6a2` 同样：

```
205e6ee:  movl $0x1598, %ecx
205e6f3:  cmpl %ecx, %eax
205e6f5:  cmovbl %eax, %ecx          ; min(req->length, 0x1598)
205e71d:  callq IO80211ScanManager::startScan
```

即 27 用户态扫描请求缓冲的上限是 **0x1598**（实测请求长度正好 0x1598），不是 legacy payload0 的 **0x1550**（payload0 `setScanRequest` @ `0x8402d`：`movl $0x1550,%ecx` + `min`）。当前 SimpleBCM 对 type 10 不做任何转换，直接把 `0x1598` 转发；payload0 用 `min(0x1598, 0x1550)` 截断到 `0x1550`。这是内存安全的（payload0 只 copyIn 0x1550 到 0x1550 的堆缓冲），但 27 请求尾部 `0x48` 字节被丢弃。

### 2.4 SimpleBCM 直接透传 86 是否安全

| 场景 | 行为 | 安全性 |
| --- | --- | --- |
| 客户端发 `0x14E8`（当前 `abi.scanMultipleSize`） | 本地门槛通过 → `prepareScanMultiple` 校验字段 → 尾部 8 字节清零 → `request.length=0x14E0` → payload0 接受 | **安全**；字段偏移与 payload0/27 的 `fastScanMultiple` 一致，最高访问 0x14D8 |
| 客户端发 `0x14E0`（payload0 唯一原生长度） | `UserClient.cpp:369` 的 `header->length != abi.scanMultipleSize` 直接 `goto done`，默认 `kIOReturnBadArgument` | **不安全（误拒）**：payload0 本来可以处理，却被本地门槛挡掉 |
| 客户端发 27 type 10 的 `0x1598` 到 type 86 | 本地门槛拒绝（长度不等于 0x14E8） | 类型/语义都不对；但 27 不会这样做 |
| 客户端发其它长度 | 拒绝 | 安全 |

**字段布局对比**：27 `fastScanMultiple` @ `0xffffff8001fe4cde` 读取的偏移与 payload0 `fastScanMultiple` @ `0xac8cc` 完全相同：

```
27:  movl 0x4(%r12),%eax          payload0: movl 0x4(%r13),%ebx
27:  movl 0x210(%r12),%eax        payload0: movl 0x210(%r13),%eax
27:  leaq 0x214(%r12),%rsi        payload0: leaq 0x214(%r13),%rsi
27:  movl $0x12c0,%edx            payload0: movl $0x12c0,%edx
27:  movl 0x204(%r12),%eax        payload0: movl 0x204(%r13),%eax
27:  movl 0x200(%r12),%eax        payload0: movl 0x200(%r13),%eax
27:  0x8 count, 0x10/0x14+0x28 items, 0x19C, 0x1A0
```

**结论**：86 的结构布局在 27 与 legacy 之间没有字段漂移；只有总长度 `0x14E8` vs `0x14E0` 的 8 字节尾部差异，且 27 的 `fastScanMultiple` 没有任何长度门禁，最高访问 `0x14D8`。因此“0x14E8 → 0x14E0”的转换是安全的；真正的缺口是 **0x14E0 被本地拒绝**，而不是直通会写坏。

### 2.5 影响

- 27 自身不扫描 86，所以当前 27 的扫描/菜单功能不受 86 路径影响；这是“死代码 + 本地严格门禁”的组合，不是当前故障。
- 若第三方工具或旧客户端用 `Apple80211ScanMultiple`（legacy 0x14E0）走 SimpleBCM，会被本地拒绝，表现为 `kIOReturnBadArgument`，而 payload0 本来可以执行。这是兼容性缺口，不是内存安全缺口。
- 若 27 将来把 86 重新接回（例如 WCL 路径），它最可能仍使用 0x14E0/0x14E8 之一；当前本地只接受 0x14E8，风险是单边。

### 2.6 最小适配建议（仅描述）

1. **同时接受两种长度**：把 `prepareScanMultiple` 改成“校验字段 + 按长度收尾”：
   ```cpp
   if (request.length != NativeScanMultipleSize && request.length != LegacyScanMultipleSize)
       return false;
   /* 两种长度的字段偏移完全相同，先做现有 0/8/0x19C/0x210/0x10+i*0x28 校验 */
   if (request.length == NativeScanMultipleSize)
       for (off = LegacyScanMultipleSize; off < NativeScanMultipleSize; ++off) buffer[off] = 0;
   request.length = LegacyScanMultipleSize;
   ```
   对 `0x14E0` 输入不需要清零/搬移，直接 `request.length=0x14E0` 透传。
2. **记录观测长度**：在 ioreg 增加 `LastScanMultipleLength`（或复用 `LastSetLength`，但它会被 483 覆盖），这样下次有客户端发 86 时能直接看到是 0x14E0 还是 0x14E8。当前 27 不发 86，运行时永远看不到。
3. **不要**把 27 的 type 10 `0x1598` 映射到 86：两者语义不同（scan_data vs scan_multiple_data），而且 27 的 86 本来就是死代码。

### 2.7 验证方法

- 27 真实扫描：`system_profiler SPAirPortDataType` 期间轮询
  ```sh
  ioreg -rn SimpleBCM -l | grep -E '"Set(Hist|Len)[0-9]+"'
  ```
  期望只看到 `(10, 5528)` 和 `(483, 1)`，没有 `(86, …)`；`LastSetResult=0`，`ScanRecords` 增长。这就是“27 不走 86”的运行期判据。
- 86 正向测试（需要合成客户端，当前 27 不会发）：发 `0x14E8`，期望 `prepareScanMultiple` 返回 1、payload0 `setScanRequestMultiple` 返回 0、`ScanDoneEvents`/`ScanRecords` 增长；发 `0x14E0`，修复前应看到 `kIOReturnBadArgument`，修复后应与 0x14E8 同样成功。
- 反汇编复核：
  ```sh
  nm -arch x86_64 .research/extract/payload0.bin | grep -E 'setScanRequestMultiple|startScanMultiple|fastScanMultiple'
  llvm-objdump -d --arch=x86_64 --start-address=0x86f4c --stop-address=0x87224 --no-show-raw-insn .research/extract/payload0.bin
  ```

---

## 3. 扫描结果：27 是否一次 get 11 返回多条记录

### 3.1 27 的 get 11：一次一条 0x8E8

27 新表 `getSCAN_RESULT` @ `0xffffff8001f7e61d`：

```
ffffff8001f7e629:  cmpl $0x8e8, 0x18(%rcx)     ; ★ req->length 必须恰好 0x8E8
ffffff8001f7e643:  movl $0x8e8, %r8d           ; routeIoctlToWcl 长度 = 0x8E8
ffffff8001f7e659:  callq routeIoctlToWcl
ffffff8001f7e65e:  cmpl $0xe082280f, %eax      ; WCL 不可用
ffffff8001f7e66f:  jmp  apple80211getSCAN_RESULT ; fallback
```

`apple80211getSCAN_RESULT` @ `0xffffff8001f66bfd`：

```
ffffff8001f66c35:  movq (%r14),%rax
ffffff8001f66c38:  movq 0x1b8(%rax),%rax        ; 接口 vtable +0x1b8（单结果方法）
ffffff8001f66c48:  jmpq *%rax
```

`0x8E8` 是单个 `apple80211_scan_result` 的大小（见 `Docs/Reverse-ScanResult-Layout-20261118.md` §1）。WCL 路径 `WCLScanRequest::getNextScanResult(apple80211_scan_result&)` @ `0xffffff80020033e4` 也是“填一条、返回 bool”；legacy 兼容 handler `getScanResult` @ `0xffffff800202c48b` 使用 `0x8CC`（`202c495: cmpl $0x8cc,0x18(%rdx)`），但它在 27 里实际是“查 scan manager 后返回 `0xE00002BC`”的路径，不是 27 用户态 get 11 的路径。**27 的 0x8E8 请求没有“记录数组/计数”字段，结构上不可能一次返回多条。**

### 3.2 payload0 的 get 11：一次弹一条，长度门禁 0x48C

payload0 `getScanResult` @ `0x78a33`：

```
78a7c:  cmpl $0x48c, 0x18(%rbx)      ; ★ 只接受 0x48C
78a89:  cmpq $0, 0x20(%rbx)          ; req->data
78aaf:  callq IO80211ScanManager::getScanResult(&result) ; 弹一条
78b05:  callq copyIn(req->data, buf, 0x48C)
78c2c:  ... 逐字段拷贝
78c38:  movzwl buf+0x8A,%eax ; 客户端 IE 长度
78c3f:  movzwl cached+0x8A,%ecx
78c46:  cmpw %cx,%ax
78c49:  cmovbl %eax,%ecx
78c4c:  movw %cx, buf+0x8A         ; min(client, cached)
78c62:  movl $0x400,%ecx           ; 上限 0x400
78c7d:  callq copyOut(buf, req->data, 0x48C)
```

`IO80211ScanManager::getScanResult` @ `0xae808`：从链表摘一个节点（`ae8cc`–`ae8d7`），没有结果时返回 5（`ae9c7`）。所以 payload0 也是**一次一条**。

SimpleBCM 的处理（`WirelessABI.hpp:240-266`）：

- `prepareScanResult`：把 `0x8E8` 请求改成 payload0 的 `0x48C`，并把 `+0x8A` 写成 `0x400`（修复 IE 被 `min()` 压成 0 的根因）。
- `expandScanResult`：把 0x48C 扩展回 0x8E8，清零 `0x48C..0x8E7`，SSID 非空时清 `+0x88` 的 hidden 位。
- `runCommand` 返回时 `produced = legacy.request.length = 0x8E8`，与 27 的请求长度一致。

### 3.3 在 27 的 0x8E8 下长度/返回值是否成立

| 检查 | 直接转发 0x8E8 到 payload0 | SimpleBCM 当前处理 |
| --- | --- | --- |
| payload0 `req->length == 0x48C` | **不成立**，返回 `0x16` | `prepareScanResult` 改成 0x48C，成立 |
| IE 长度 `+0x8A` | 客户端值（27 常为 0）→ `min()` 把 IE 清零 | 写入 `0x400`，IE 不再被压掉 |
| 输出长度 | 0x48C | `expandScanResult` 恢复 0x8E8 |
| 单条记录 | payload0 一次一条 | 27 每次 get 11 一条，匹配 |
| 队列空 | payload0 返回 5（非 0） | 原样返回；27 停止循环 |

结论：**在 0x8E8 下，payload0 的 0x48C 长度校验本身不成立，必须由 `prepareScanResult` 改写；SimpleBCM 已经这样做了，返回值/长度链路成立。** 27 是一条一条请求，不是一次多条；如果 `ScanRecords` 很大，那是“成功 get 11 的次数/记录数”累积，不是单次返回多记录。

### 3.4 `ScanRecords` / `ScanDoneRecords` 的准确含义

| 计数器 | 递增点 | 语义 | 实测 |
| --- | --- | --- | --- |
| `ScanRecords` | `UserClient.cpp:505`，`scanResult && result==success` 后 | 成功 get 11 的次数；每次一条记录 → **已交付记录数** | 4069 → 4128 → 4260（随扫描增长） |
| `ScanDoneEvents` | `Bridge.cpp:566-567`，`message == ScanDoneEvent` | 驱动 scan-done 消息数（一次扫描一条） | 150 → 154 → 161 |
| `ScanDoneRecords` | `UserClient.cpp:656-657`，每个客户端 ring 成功 append 一次 | **scan-done 事件投递次数**，不是记录数；≈ `ScanDoneEvents × 已订阅客户端数` | 609/150≈4.06，625/154≈4.06，653/161≈4.06 |

`ScanDoneRecords` 的命名容易让人以为它统计“扫描到的记录数”，实际是事件 ring 的写入次数；本次 4.06 的比值正是 4 个左右已订阅客户端的签名。若要统计“每条记录”，应使用 `ScanRecords`（每次 get 11 成功 +1），或从 scan-done 事件 payload 里读真正的 count（如果 payload 有的话；当前代码没有这样做）。

### 3.5 影响与最小适配

- 功能：无缺口；单记录 ABI 与 27 的 0x8E8 一致。
- 诊断：`ScanDoneRecords` 名字误导；建议改名为 `ScanDoneDeliveries`，或新增 `LastScanResultLength`（get 11 返回 0x8E8）和 `ScanRecords` 并列展示。
- 如果未来要在一次 get 11 里塞多条记录：**不要做**；27 的 `req->length == 0x8E8` 硬门禁和单结构 `apple80211_scan_result` 都不支持。
- 最小改动（仅命名/诊断）：
  ```cpp
  // 仅属性名变更；语义不变
  {"ScanDoneDeliveries", &counters.scanDoneRecords}
  ```
  或保留属性名但在 Docs 中明确“每次 ring append 一次”。

### 3.6 验证方法

```sh
# 扫描前后读计数；每成功 get 11 一次，ScanRecords +1
ioreg -rn SimpleBCM -l | grep -E 'ScanRecords|ScanDoneEvents|ScanDoneRecords|LastResult|Last103OutputSize'
```

- 期望：`ScanRecords` 随扫描/读取持续增长；`ScanDoneRecords ≈ ScanDoneEvents × 4`（当前 4 个订阅客户端）；`LastResult` 在 get 11 成功时为 0。
- 若要确认单次 get 返回 0x8E8：在 `runCommand` 的 `scanResult` 成功分支临时记录 `legacy.request.length`（当前为 0x8E8），或直接读 `produced`；不要用 `ScanDoneRecords` 推断记录数。

---

## 4. 额外发现：type 10 的 `0x1598` vs legacy `0x1550`

这是本次复验中新出现的、比请求 86 更实际的 ABI 差异：

| 层 | 扫描请求长度 | 证据 |
| --- | --- | --- |
| 27 用户态（实测） | `0x1598`（5528） | 扫描期间 `LastSetLength=5528`，`SetHist/SetLen` 对 `(10, 5528)` 稳定出现 27 次 |
| 27 新 `setSCAN_REQ` | `0x1598` | `0xffffff8001f8a125: movl $0x1598,%r8d` |
| 27 legacy `setScanRequest` | `0x1598` | `0x205e6ee: movl $0x1598,%ecx`，`min(req->length,0x1598)` |
| payload0 `setScanRequest` | `0x1550` | `0x8402d: movl $0x1550,%ecx`，`min(req->length,0x1550)` |
| SimpleBCM | 不转换，直接转发 `header->length` | `UserClient.cpp` 无 type 10 的 prepare；payload0 负责 clamp |

影响：

- **内存安全**：payload0 分配 0x1550、copyIn 最多 0x1550，不会越界读 27 的 0x1598 缓冲。
- **语义**：27 请求尾部 `[0x1550,0x1598)` 的 0x48 字节不会进入 legacy 栈。当前扫描成功（`LastSetResult=0`，2.4G/5G 结果都出现），说明关键字段都在前缀；但如果 27 在这个尾部放了新字段（例如 6GHz/新 scan flag），legacy 栈不会理解。
- **不要**简单把 payload0 的缓冲/拷贝上限改成 0x1598：payload0 的 `apple80211_scan_data` 是 0x1550，驱动只认识这个结构；盲目放大不会让驱动读取新字段，反而可能改变栈布局。
- **建议**：先加观测，不急着转换——在 `runCommand` 对 type 10 记录 `LastScanRequestLength=header->length`，并把 `shadow[0x1550..0x1598)` 的 18 个 word 发布成 ioreg（类似 `ScanW*`），下次扫描时确认尾部是否非零、是否有 27 语义。若尾部全 0 或与 legacy 无关，则当前截断是可接受的兼容策略。

验证判据：

```sh
# 扫描期间轮询，确认 type 10 的长度固定为 5528
ioreg -rn SimpleBCM -l | grep -E '"Set(Hist|Len)[0-9]+"'
```

当前实测只有 `(10, 5528)` 和 `(483, 1)`；`LastSetResult=0`，扫描结果非空。

---

## 5. 残余缺口 / 未验证

1. **live kext 二进制无法哈希对齐**：EFI 分区需要 root 才能读；本会话无 `sudo`。`kextstat` UUID 与 workspace 84348ff 构建只差尾部，`C103Hits>0` 证明 ≥84348ff；但无法排除后续小改动。本文的代码引用均按 HEAD/`222ed98` 的源码，源码在 mismatch 区域未变。
2. **27 type 10 尾部 `[0x1550,0x1598)` 的语义未验证**：没有请求快照；当前扫描成功只能证明前缀足够。需要新增 ioreg 快照后再判断。
3. **`bssidCount` 上限差异**：27 framework 允许 `<11`，SimpleBCM golden gate 只允许 `≤3`（`prepareAssociate` 检查 0x206）。本次 4 个样本 `LastGoldenGateBssidCount=0`，未触发；4–10 个候选 BSSID 的实机行为未验证。若未来出现关联被拒且 `LastGoldenGateBssidCount>3`，这是第一嫌疑。
4. **请求 86 无法在 27 上自然触发**：27 的 86 是死代码；要验证 SimpleBCM 的 86 路径，需要一个合成客户端直接发 0x14E8/0x14E0。本次未做（不修改系统、不部署）。
5. **27 legacy get 11 的 0x8CC 路径**：`0xffffff800202c48b` 校验 0x8CC 后实际返回 `0xE00002BC`（不支持），不是 27 用户态 get 11 的真实路径；为什么保留 0x8CC 这个尺寸未进一步追。它不影响 0x8E8 新路径的结论。
6. **统一日志受 a2x 影响**：`/usr/bin/log --predicate` 在本机 NSException；45 分钟无 predicate dump 只覆盖了 04:41 之后，启动窗口的 2 次关联未在日志中逐条列出。4 次关联的完整性由 ioreg 计数器（`AssociationRequests`/`DriverAssociateRequests`）保证，不依赖日志。

---

## 6. 复现命令（只读）

```sh
# 运行期计数
ioreg -rn SimpleBCM -l | grep -E \
 'AssociationRequests|GoldenGateAssociateRequests|AssociateLengthMismatch|LastAssociateLength|AssociationAccepted|LastAssociationResult|DriverAssociateRequests|LastDriverAssociateWord|ScanRecords|ScanDoneEvents|ScanDoneRecords|LastSetType|LastSetLength|LastSetResult|LastGoldenGateScope|LastGoldenGateBssidCount|GoldenGateWord(0|10|26)'

# 触发一次扫描并观察 SetHist/SetLen（不会修改系统）
(for i in $(seq 1 80); do ioreg -rn SimpleBCM -l | grep -oE '"Set(Hist|Len)[0-9]+" = [0-9]+' | tr '\n' ' '; echo; sleep 0.05; done) &
system_profiler SPAirPortDataType > /tmp/spairport.txt 2>&1
wait

# payload0 反汇编
nm -arch x86_64 .research/extract/payload0.bin | grep -E 'setScanRequestMultiple|startScanMultiple|fastScanMultiple|getScanResult'
llvm-objdump -d --arch=x86_64 --start-address=0x86f4c --stop-address=0x87224 --no-show-raw-insn .research/extract/payload0.bin
llvm-objdump -d --arch=x86_64 --start-address=0x78a33 --stop-address=0x78cb7 --no-show-raw-insn .research/extract/payload0.bin

# 27 KC 表项（需要 Tools/kernel_collection.py + DSH python）
/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3 - <<'EOF'
import sys; sys.path.insert(0,'Tools')
from kernel_collection import KernelCollection
kc=KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
im=kc.images['com.apple.iokit.IO80211Family']
for tab in ('__ZL16gSetHandlerTable','_gSetHandlerTableLegacy','__ZL24gInternalSetHandlerTable'):
    base=im.symbols[tab]; raw=int.from_bytes(im.read(base+85*8,8),'little')
    print(tab, 'type86 raw', hex(raw), 'ptr', hex(kc.pointer(base+85*8)) if raw else 'NULL')
EOF

# 离线 ABI 验证
clang++ -std=c++17 -I SimpleBCM /tmp/abitest.cpp -o /tmp/abitest && /tmp/abitest
```

---

## 7. 证据文件

- `SimpleBCM/UserClient.cpp`：287-289、350-355、368-370、392-393、407-410、505、555-557、656-657
- `SimpleBCM/WirelessABI.hpp`：64-72、240-266、290-302、381-413
- `SimpleBCM/Bridge.cpp`：153-168、566-567、885-886
- `.research/extract/payload0.bin`：`setScanRequestMultiple` @0x86f4c、`fastScanMultiple` @0xac8cc、`startScanMultiple` @0xacb0e、`getScanResult` @0x78a33、`IO80211ScanManager::getScanResult` @0xae808
- `/System/Library/KernelCollections/BootKernelExtensions.kc`：`setASSOCIATE` @0xffffff8001f8a1fa、`setAssociateRequest` @0xffffff800205e8bd、`setSCAN_REQ` @0xffffff8001f8a0e9、`setScanRequest` @0xffffff800205e6a2、`getSCAN_RESULT` @0xffffff8001f7e61d、`apple80211getSCAN_RESULT` @0xffffff8001f66bfd、`fastScanMultiple` @0xffffff8001fe4cde、`apple80211setSCAN_REQ_MULTIPLE` @0xffffff8001f6c7da
- `/tmp/abitest.cpp`（本次离线测试源码）、`/tmp/spairport.txt`（扫描结果样本）
- 统一日志片段：pid 217 `a2xhost-mac`，04:45:37/04:45:48 关联请求，04:45:44/04:46:09 关联成功；无 `unable to join`。
