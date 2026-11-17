# SimpleBCM 关联代码路径审计（macOS 27.2 / Golden Gate）

日期：2026-11-17（Asia/Shanghai）
机器：macOS 27.2（26B123 / Darwin 27.2.0，x86_64 Intel），BCM43602（`pci14e4,43ba`）
代码：`simplebcm-r27`，分支 `wifi-assoc-probe`，HEAD `93df845`（工作区另有未跟踪的 `Docs/Reverse-Payload-SetTable-20261117.md`）
系统侧：`com.apple.iokit.IO80211Family 1200.13.1`（UUID `FCFF2E2C-C353-3ED2-9010-D88CC8A08050`）+ `cn.laobamac.SimpleBCM 1.2.1`

> 取证边界：本会话只做只读检查与工作区文档编辑。**没有**加载/卸载 kext、没有构建、没有重启、没有改 `/System`、`/Library`、EFI。
> 当前启动没有 `SimpleBCM: probe/iouc` 统一日志（`DBGLOG` 只在 DEBUG 编译；部署产物为 Release，见 `SimpleBCM/Patcher.hpp:19-23`），
> 因此运行期证据以 IORegistry 持久计数器为准；二进制证据取自 `.research/extract/payload0.bin`、`payload1.bin`
> 与本机 `/System/Library/KernelCollections/BootKernelExtensions.kc`（只读）。

---

## 0. 结论摘要（先看这里）

1. **27 的关联请求号仍然是 20，不是 254。** 27 系统 IO80211Family 的 set/get 表（新 set、legacy set、internal set，以及两张 get）里，
   `type 20`（下标 19）都映射到 ASSOCIATE 系 handler；`type 254` 在**所有 set 表里都是空槽**，255 才是
   `setBTCOEX_PROFILE`/`setUCMCoexProfile`。父报告里“slot 20 为空、slot 254 有 handler”是**把 0-based 表下标当成了 1-based type 号**。
   详见 §3 与 `Docs/Reverse-Payload-SetTable-20261117.md` §0/§5（本会话独立复核了同样的表项）。
2. **即使 27 真把 254 作为 Set 发下来，SimpleBCM 也不会把它当关联。** `UserClient.cpp:287` 的判定是
   `set && request == bcm::AssociateRequest`（20）；254 会走原样转发。Classic 端点落到内嵌驱动的未知类型路径
   （同类 483 的实测返回是 0x66；254 未逐指令验证），Virtual/Skywalk 端点落到 payload0 417 表的下标 253（空槽），
   返回 `0x66` 并打 `not recognized: 254 out of 417`（`payload0.bin @0x91ede`，见 §4）。**因此“补 254→20 映射”是错误方向。**
3. **27 kext 消费/校验的 associate 数据长度是 0x290（656），不是 `GoldenGateABI.associateSize` 的 0x38C（908）。**
   （wifid 实际填进 `header->length` 的值仍待实测，见 §9.1；但 27 自身两条 handler 都只按 0x290 消费。）
   证据：27 `setASSOCIATE` 把 `req->data` 以长度 `0x290` 直接交给
   `IO80211SkywalkInterface::routeIoctlToWcl`（`0xffffff8001f8a1fa`，`movl $0x290,%r8d`）；
   27 legacy `setAssociateRequest` 也是 `bzero 0x290` + `copyIn(min(req->length, 0x290))` + 按 0x290 布局校验后
   `routeIoctlToWcl(..., 0x290)`（`0xffffff800205e8bd`）。这比 `Docs/Control-Codecs.json` 的 Tahoe native 布局
   （0x38C）小 0xFC，而且 bssid/scope 两处偏移比 Tahoe 各小 4（0x202/0x240 对 0x206/0x244）。
4. **如果 27 用 0x290 发 type 20，当前代码会在两处拒绝，且不会调用转换：**
   ①`UserClient.cpp:320` 的 `header->length != abi.associateSize` → `goto done`（默认 `kIOReturnBadArgument`）；
   ②即便绕过①，`WirelessABI.hpp:286-314` 的 `prepareAssociate` 要求 `request.length == 0x38C`，0x290 直接返回 false。
   这两处都在 `Bridge::command` 之前，所以驱动不会收到请求，也不会产生 AssociationDone。
5. **`AssociationRequests=0` 只能证明“没有任何 type 20 set 到达被包装的命令用户客户端”，不能证明“27 用户态从未发过关联”。**
   `AssociationRequests` 在 `UserClient.cpp:313-314` 递增，位置在 interface-name/长度门禁之前；只要请求进了任意一个
   `BCM80211UserClient::runCommand`，计数就会 ≥1。当前 `Commands` 在 19:30–19:45 之间从 4196 涨到 10338、
   `AssociationRequests=0`；同类计数 `IO80211APIUserClient=10` 与 `BCM80211UserClient=10`（所有原生 API 客户端都被包装），
   所以走用户客户端这条路的 type 20 确实一次都没有。
   但 **legacy ifnet ioctl（airportd 的 `SIOCSA80211` 路径）可以绕过用户客户端直接进 `apple80211RequestIoctl`**，本会话无法用现有计数器排除它（§6）。
6. **`AssociationEvents=0` 是“驱动没产生事件 9”，不是 filter 拒绝、也不是 ring 没读。**
   `AssociationEvents` 在 `Bridge.cpp:469-472` 递增，位置在 `queueEvent` 的客户端/过滤器/队列之前；`receive()` 里的
   `filter.accepts`（`UserClient.cpp:502`）只影响后续 ring append。`ScanDoneEvents=20` 证明同一 hook 链对事件 10 正常工作；
   `DroppedEvents=0` 排除队列丢弃。默认 `filter.all=1`（`UserClient.cpp:69`）也排除“过滤器一开始就拒绝”。
7. **事件转换存在 27 特有风险（即使关联成功）：** `captureJoinEvent` 只在
   `message==9 && !length && kind==Classic` 时合成 0x1D4 的 join status（`Bridge.cpp:483-486`）；
   它还把 endpoint 硬编码为 `InterfaceKind::Classic`（`Bridge.cpp:357`），`PendingEvent` 里根本没有 kind 字段。
   若 27/内嵌驱动通过 Virtual/Skywalk 投递事件 9，或事件 9 带非空 payload，就不会走转换，用户态收到的是 legacy 原始负载；
   27 的 `apple80211_join_status` 是否仍是 0x1D4 **未验证**（`WirelessABI.hpp:86-88` 直接沿用 Tahoe）。
8. **当前最该做的不是改关联转换，而是先把“关联请求到底有没有到驱动”变成可判定的持久计数。**
   现有 `ReqHist` 只有 16 项，而本会话三次读取 `Commands` 从 4196 涨到 10338（约 4–5 条/秒），16 项只覆盖约 3–4 秒；
   单次关联尝试很容易被 WoW/查询流量挤出历史。建议先加 §PatchDraft 的 A1（用户客户端持久计数/Set 历史）和
   A2（在内嵌 `AirPort_BrcmNIC::setASSOCIATE` 上挂钩计数）。A2 能同时覆盖用户客户端路径与 ifnet ioctl 路径，是决定性实验；
   前提是把该符号加入 `Tools/profiles.py` 的 `ROUTE_SYMBOLS["AirPort"]` 并重新生成 payload（现有 route 表只有
   HARDWARE_VERSION/getLOCALE，见 §PatchDraft A2 的前提说明；未重新生成前 A2 的 route 会失败且 HookReady=0）。
9. **“先修哪一侧”的判断：当前阻塞在 airportd 内部、驱动 Set 之前，所以驱动侧关联补丁不是这次超时的根因修复。**
   同会话 airportd 取证（`Docs/Reverse-Assoc-20261117.md` §2.2/§2.3）把 19:23:38 的 `[ASSOC]` 定位到
   airportd `__associateToWiFiNetwork:` 内、`setAssociatedNetwork:` 之前；驱动侧的 set 20 在这之后。
   因此：先修用户态/airportd 的阻塞（系统组件，受“不改系统文件”约束，只能定位并报告，不能改），
   驱动侧只做两件事：①A1/A2 证明驱动没有参与；②把 0x290 转换准备好，等用户态走到 Set 时不再以 BadArgument 失败。
   0x290 转换是**迟早会触发的真 bug**，但不是本次 120 秒超时的根因。
10. **不要做 254 映射、不要动系统文件、不要用用户态临时绕过。** 关联号、结果号（set 20 / get 21）、
    事件号（9）在可核对的范围内都没有变；变的是结构尺寸/布局和 27 的前置请求集合。

---

## 1. 本会话实测状态（只读）

### 1.1 SimpleBCM 持久计数器

`ioreg -rn SimpleBCM -l`（本会话 19:30–19:45 多次读取；计数器单调，故列出快照）：

| 属性 | 值 | 含义 |
| --- | --- | --- |
| `Commands` | 4196 → 8160 → 10338 | `runCommand` 总调用数（三次快照） |
| `AssociationRequests` | **0** | `set && type==20` 的次数（在门禁之前） |
| `AssociationAccepted` | 0 | type 20 成功返回的次数 |
| `LastAssociationResult` | 0 | 从未被 type 20 写过（`UserClient.cpp:414-418` 只在 associate 时写） |
| `AssociationEvents` | **0** | 驱动 postMessage(9) 的次数（`Bridge.cpp:469-472`） |
| `LastAssociationEventLength` | 0 | 同上 |
| `AssociationEventReadErrors` | 0 | 同上（没有事件可读） |
| `ScanRecords` | 218 | request 11 成功次数 |
| `ScanDoneEvents` | 20 | 驱动 postMessage(10) 次数 |
| `DroppedEvents` | 0 | 事件队列/长度/识别丢弃 |
| `Rejects` | 0 | `Bridge::command` ENXIO 次数 |
| `LastRequest` / `LastRequestSet` / `LastRequestKind` | 96 / 0 / 1 | 最后一次是 Virtual 端点上的 get 96 |
| `LastResult` | 0 | 最后一次成功 |

`ReqHist`（19:30 快照的最后 16 条）：`70, 69, 483, 96, 96, 48, ...`，**没有 20，也没有 254**。
但如 §0.8 所述，这个窗口只有约 3–4 秒，不能作为“从未发过”的主证据；主证据是 `AssociationRequests=0`（对 20）
和“没有持久 254 计数”（对 254，靠 §3 的表结构排除）。

### 1.2 用户客户端的包装覆盖

`ioreg -l` 的 IOKitDiagnostics 类计数：

```
"IO80211APIUserClient"=10
"BCM80211UserClient"=10
"IO80211AsyncEventUserClient"=0
"SB80211AsyncEventUserClient"=0
```

`wrapNativeUserClient()`（`NativeUserClient.cpp:156-200`）为每个原生前端创建一个 `BCM80211UserClient` 实现
（profile 0），因此 10/10 说明当前所有 `IO80211APIUserClient` 实例都被 SimpleBCM 包装。没有“未包装的原生命令客户端”
可以让 wifid 绕过 `runCommand` 的计数器（但 ifnet ioctl 路径仍不受此保护，见 §6）。

### 1.3 27 分派表（本会话复核）

用 `Tools/kernel_collection.py` 读 27 KC，按 `table[type-1]` 解码 chained fixup；
下标含义由已知项校验：下标 9 = `setSCAN_REQ`（type 10）、下标 19 = `setASSOCIATE`（type 20）、
下标 253 = `getHW_SUPPORTED_CHANNELS`（type 254）。结果：

| 表（27 KC） | 地址 | type 20（下标 19） | type 254（下标 253） | type 255（下标 254） |
| --- | --- | --- | --- | --- |
| `gSetHandlerTable`（新表/IOUC 路径） | `0xffffff800218d590` | `setASSOCIATE` `0xffffff8001f8a1fa` | **0** | `setBTCOEX_PROFILE` `0xffffff8001f8c7d1` |
| `_gSetHandlerTableLegacy`（BSD ioctl 路径） | `0xffffff80021a6b10` | `setAssociateRequest` `0xffffff800205e8bd` | **0** | `setUCMCoexProfile` `0xffffff8002060df9` |
| `gInternalSetHandlerTable`（internal） | `0xffffff80021abf90` | `apple80211setASSOCIATE` `0xffffff8001f6c055` | **0** | `apple80211setBTCOEX_PROFILE` `0xffffff8001f6dd66` |
| `gGetHandlerTable`（新表 get） | `0xffffff800218c150` | **0**（关联是 set） | `getHW_SUPPORTED_CHANNELS` `0xffffff8001f812af` | `getBTCOEX_PROFILE` |
| `_gGetHandlerTableLegacy`（legacy get） | `0xffffff800219e6e0` | **0** | `getHwSupportedChannels` `0xffffff800202f36f` | `getUCMCoexProfile` |

`type 20` 在 payload0 的 417 表里同样是 `setAssociateRequest @0x84430`（`Tools/audit_codecs.py:61-65`；
`Docs/Reverse-Payload-SetTable-20261117.md` §2/§5 有逐项表）。所以“27 把关联改成 254”没有任何表结构支持。

> 关于“slot 20 为空、slot 254 有 handler”的两种来源：
> - 0-based 下标 20 = type 21（`getASSOCIATE_RESULT` 在 get 表，set 表为空）；0-based 下标 254 = type 255（BTCOEX/UCM）。
> - 1-based type 看 get 表：type 20 在 get 表为空（正常，关联是 set）；type 254 是 `getHW_SUPPORTED_CHANNELS`，返回 0。
>
> 历史 `LastRequest=254 / LastResult=0` 与“一次成功的 GET_HW_SUPPORTED_CHANNELS”完全吻合；若它是 **set** 254，
> payload0 的 `apple80211_ioctl_set` 会在空槽处返回 `0x66`，不会是 0（`payload0.bin @0x91ede`，见 §4.2）。

---

## 2. `UserClient.cpp:runCommand` 的关联路径逐行

### 2.1 包布局与请求解码

- 包大小：`sizeof(CommandHeader) + capacity + sizeof(Request)` = `8 + 0x3C00 + 0x28 = 0x3C30`
  （`UserClient.cpp:245`；`WirelessABI.hpp:431` 的 static_assert）。
- `CommandHeader` = `{command(uint32), length(uint32)}`（`WirelessABI.hpp:142-145`）。
- `shadow = packet + 8`，`Request` 位于 `shadow + capacity`；`legacy.pointerSize = 8`（`UserClient.cpp:274-278`）。
- `Request`：`interfaceName[16]`、`type@0x10`、`value@0x14`、`length@0x18`、`reserved@0x1C`、`data@0x20`
  （`WirelessABI.hpp:127-134`；`sizeof=0x28`）。
- `SetCommand=0x802869C8`、`GetCommand=0xC02869C9`（`WirelessABI.hpp:17-18`）。
  27 的 `setASSOCIATE` 调 `routeIoctlToWcl` 时也使用 `0x802869C8`（§3），号段一致。

### 2.2 `associate` 判定与计数

```cpp
// UserClient.cpp:279-288
const auto request = legacy.request.type;
const bool set = header->command == bcm::SetCommand;
const bool get = header->command == bcm::GetCommand;
...
const bool associate = set && request == bcm::AssociateRequest;   // 20
```

```cpp
// UserClient.cpp:304-314
__atomic_fetch_add(&bcm::counters.commands, 1ULL, ...);
__atomic_store_n(&bcm::counters.lastRequest, request, ...);
... // lastRequestKind / lastRequestSet
const uint32_t historySlot = __atomic_fetch_add(&bcm::counters.requestHistoryNext, 1u, ...) & 15u;
... // requestHistory / requestHistoryFlags
__atomic_fetch_add(&bcm::counters.requestHistoryCount, 1ULL, ...);
if (associate)
    __atomic_fetch_add(&bcm::counters.associationRequests, 1ULL, ...);   // 先计数
```

要点：`AssociationRequests` 在**所有**后续门禁（接口名、长度、scalar、prepare）之前递增。
所以“type 20 到了 `runCommand` 但被长度门禁拒绝”会表现为 `AssociationRequests≥1` + `LastAssociationResult=0xE00002C2`，
而不是 0。当前 0 说明没有 type 20 进入任何被包装客户端。`probeRequest`（`UserClient.cpp:290-296`）包含 20 和 254，
但它只在 DEBUG 下用 `DBGLOG` 打印（`Patcher.hpp:21-23`），当前 Release 产物没有落到统一日志（本会话 `log show --last 90m`
过滤 `SimpleBCM` 为空）。

### 2.3 尺寸门禁（拒绝 0x290 的第一处）

```cpp
// UserClient.cpp:315-323
if ((!set && !get) || header->length > capacity ||
    strncmp(legacy.request.interfaceName, endpoint.name, sizeof(endpoint.name)))
    goto done;
if ((get && request == bcm::ScanResultRequest && !scanResult) ||
    (get && request == bcm::CardCapabilitiesRequest && !capabilities) ||
    (associate && header->length != abi.associateSize) ||          // <-- 0x290 != 0x38C -> goto done
    (set && request == bcm::ScanMultipleRequest && header->length != abi.scanMultipleSize) ||
    (request == bcm::RoamProfileRequest && (get ? outputSize : header->length) != abi.roamProfileSize))
    goto done;
```

`result` 在 `UserClient.cpp:257` 初始化为 `kIOReturnBadArgument`，`goto done` 后：
`LastAssociationResult=0xE00002C2`，`AssociationAccepted` 不增，`Bridge::command` 不会被调用。

### 2.4 `prepareAssociate` 的结构转换（拒绝 0x290 的第二处）

```cpp
// UserClient.cpp:340-348
legacy.request.data = reinterpret_cast<uintptr_t>(shadow);
legacy.request.length = static_cast<uint32_t>(get ? outputSize : header->length);
if (scanResult && !bcm::prepareScanResult(...)) goto done;
if (set && request == bcm::ScanMultipleRequest && !bcm::prepareScanMultiple(...)) goto done;
if (associate && !bcm::prepareAssociate(legacy.request, shadow, capacity, abi)) goto done;
```

```cpp
// WirelessABI.hpp:286-314
inline bool prepareAssociate(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.associateSize || request.length != abi.associateSize)
        return false;                                              // 0x290 != 0x38C -> false
    if (abi.associateLayout == AssociateLayout::Legacy) { ... }
    const auto lower = readUInt32(buffer + 8);                     // 27: auth lower 8..11
    const auto upper = readUInt32(buffer + 12);                    // 27: auth upper 12..15
    if (lower > UINT16_MAX || upper > UINT16_MAX || buffer[0x206] > 3)
        return false;                                              // 假定 native bssidCount 在 0x206
    for (size_t offset = 0xC; offset < 0x215; ++offset)
        buffer[offset] = buffer[offset + 4];                       // 0x10..0x218 -> 0xC..0x214
    buffer[6] = lower & 0xFF; buffer[7] = lower >> 8;              // -> legacy 6..7
    buffer[8] = upper & 0xFF; buffer[9] = upper >> 8;              // -> legacy 8..9
    buffer[10] = buffer[11] = 0;
    for (size_t offset = 0x215; offset < 0x218; ++offset) buffer[offset] = 0;
    for (size_t offset = 0x218; offset < LegacyAssociateSize; ++offset)
        buffer[offset] = buffer[offset + 0x2C];                    // native 0x244 -> legacy 0x218
    for (size_t offset = LegacyAssociateSize; offset < abi.associateSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyAssociateSize;                          // 0x224
    return true;
}
```

对 **Tahoe native 0x38C** 布局，这个转换与 `Docs/Control-Codecs.json` 的字段表一致：
auth 8/12→6/8、ssid 0x10→0xC、key 0x3C→0x38、rsn 0xD0→0xCC、pmk 0x1D8→0x1D4、
bssid 0x206→0x202、scope 0x244→0x218（`Tools/audit_codecs.py:69-79`）。

但对 **27 的 0x290** 布局：
- 27 legacy handler 的校验点是 `0x10`（ssidLength<33）、`0xD0`（rsnLength<258）、`0x1D8`（pmkLength<33）、
  `0x202`（bssidCount<11，byte）、`0x240`（scope<38），见 §3.2；
- 0x202/0x240 比 Tahoe 的 0x206/0x244 各小 4，说明 27 的布局在 pmk 之后有一处 4 字节的差异；
- 直接拿 0x290 缓冲跑上面的 0x38C 转换，`buffer[0x206]` 读到的是 27 结构里别的字段，
  `0x244` 的 scope 也会读错，最终给驱动一个字段错位的 0x224 结构。
  这不是“只放宽长度门禁”能解决的。

### 2.5 结果/计数收尾

- `AssociationAccepted`：`UserClient.cpp:414-418`，只在 `associate && result==kIOReturnSuccess` 时递增。
- `LastAssociationResult`：同上，写入本次 IOReturn。
- `LastResult`/`ReqRes*`：`UserClient.cpp:425-426`，所有命令都写。
- `AssociationRequests` 的语义是“进入了 runCommand 的 type 20 set”，不是“驱动接受了关联”，也不是“用户态发了关联”。

---

## 3. 27 侧真实号码与结构

### 3.1 号码

见 §1.3 的表。结论：

- **associate set = 20**（四张表一致；payload0 也是 20）。
- **associate result get = 21**（27 `gGetHandlerTable[20]` = `getASSOCIATE_RESULT`；payload0 get[20] = `getAssociateResult`，
  标量写 `req->value`；SimpleBCM 的 `ScalarGetRequests` 已包含 21，`Tools/profiles.py:35`）。
- **254 是 set 方向的洞**；get 方向是 `getHW_SUPPORTED_CHANNELS`。不要映射。

### 3.2 27 的 associate 数据长度 = 0x290

27 新/IOUC handler（`0xffffff8001f8a1fa`，`setASSOCIATE`）：

```asm
; rcx = apple80211req*
ffffff8001f8a21a: movq 0x20(%rcx),%rbx        ; req->data
...
ffffff8001f8a2f8: movl $0x290,%r8d           ; data size = 656
ffffff8001f8a2fe: movq %r15,%rdi             ; IO80211SkywalkInterface*
ffffff8001f8a301: movl $0x802869c8,%esi      ; SetCommand
ffffff8001f8a306: movl $0x14,%edx            ; type 20
ffffff8001f8a30b: movq %rbx,%rcx             ; req->data
ffffff8001f8a30e: callq routeIoctlToWcl      ; 0xffffff8001ffe712
```

它**不检查 `req->length`**（只检查非零/data 非空，见 `0xffffff8001f8a295-0xffffff8001f8a2a5`）。
27 legacy handler（`0xffffff800205e8bd`，`setAssociateRequest`）：

```asm
ffffff800205e8f6: movl $0x290,%esi           ; bzero(buf, 0x290)
ffffff800205e900: movl 0x18(%r12),%eax       ; req->length
ffffff800205e920: movl $0x290,%ecx
ffffff800205e925: cmpl %ecx,%eax
ffffff800205e927: cmovbl %eax,%ecx           ; copyLen = min(req->length, 0x290)
ffffff800205e934: callq IO80211Controller::copyIn
ffffff800205e941: movl -0x2a8(%rbp),%r10d    ; buf+0x10  ssidLength
ffffff800205e948: cmpl $0x21,%r10d           ; < 33
ffffff800205e96e: movzwl -0x1e8(%rbp),%r10d  ; buf+0xD0  rsnLength
ffffff800205e975: cmpl $0x102,%r10d          ; < 258
ffffff800205e982: movl -0xe0(%rbp),%r10d     ; buf+0x1D8 pmkLength
ffffff800205e98c: movzbl -0xb6(%rbp),%r10d   ; buf+0x202 bssidCount (byte)
ffffff800205e994: cmpl $0xb,%r10d            ; < 11
ffffff800205e99e: cmpl $0x26,-0x78(%rbp)     ; buf+0x240 scope < 38
...
ffffff800205e9fb: movl $0x290,%r8d
ffffff800205ea04: movl $0x802869c8,%esi
ffffff800205ea09: movl $0x14,%edx
ffffff800205ea0e: callq routeIoctlToWcl      ; (0x802869c8, 20, buf, 0x290)
```

同一 27 kext 的 internal handler（`0xffffff8001f6c055`，`apple80211setASSOCIATE`）只把
`apple80211_assoc_data*` 原样交给 skywalk 控制器虚函数，无长度校验。也就是说 **27 的 driver-facing assoc 结构在两条路径上都是 0x290**；
`Docs/Control-Codecs.json` 的 Tahoe native 0x38C 不再适用。

**尚未实测的是 wifid 实际填进 `header->length` 的值**：27 的 handler 不校验它，`IO80211APIUserClient::validateBufferLength`
（`0xffffff800205d3aa`）只检查输入缓冲总长（`req+4` vs `0x3C00`），没有 per-type 尺寸表。因此：
`0x290` 是 27 自己消费的长度；wifid 是否也按 0x290 填 `header->length`，需要运行期样本确认（§PatchDraft A1/A2）。

### 3.3 payload0（内嵌 Tahoe）的目标格式是 0x224

- payload0 `setAssociateRequest @0x84430`：`bzero(buf, 0x224)`；`copyIn(min(req->length,0x224))`；
  之后按 legacy 0x224 解析，并把 0x224 传给驱动（`Tools/audit_codecs.py:63-65`；本会话复核同址）。
- 内嵌驱动 `AirPort_BrcmNIC::setASSOCIATE`（`payload1.bin @0x42b8e`）的签名是
  `(OSObject*, apple80211_assoc_data*)`，也就是 legacy 0x224 布局。
- 27 的 0x290 与 payload0 的 0x224 之间**没有现成的转换器**；`prepareAssociate` 只做 0x38C→0x224。
  这是关联一旦下发就会踩到的真缺口。

---

## 4. `Bridge::command` 的 Set 路径

### 4.1 两条转发路径

```cpp
// Bridge.cpp:556-560
const auto result = endpoint.kind == InterfaceKind::Classic ?
    classicCommand(endpoint.interface, endpoint.controller, set ? SetCommand : GetCommand, nullptr, &request.request) :
    (set ? setRequest : getRequest)(endpoint.controller, nullptr,
        endpoint.kind == InterfaceKind::Virtual ? endpoint.interface : nullptr,
        endpoint.kind == InterfaceKind::Skywalk ? endpoint.interface : nullptr, &request);
```

- Classic：`classicCommand` = `IO80211Interface::performCommand`（`Bridge.cpp:696`）→
  `apple80211RequestIoctl`（payload0 `@0x8ee5c`）→ 驱动虚函数 → `AirPort_BrcmNIC::apple80211_ioctl`（payload1 `@0x387e2`）
  → `wlIocCommon`（payload1 `@0x384c8`）→ `wlIoctl`（`@0x38394`）→ `wlc_ioctl`。
  这条路径**不查 payload0 的 417 表**。
- Virtual/Skywalk：`setRequest` = `IO80211Controller::apple80211_ioctl_set`（`Bridge.cpp:690`）→
  payload0 的 417 表 `table[type-1]`。

因此同一个 type 在两个端点上的失败方式不同。

### 4.2 如果 27 用 Set 254（假设，已被表结构否定）

`associate = set && request == 20` 为 false，254 不会被计数、不会进 `prepareAssociate`，会原样转发：

- **Classic**：`performCommand(0x802869C8, type=254)` → `apple80211RequestIoctl` → 驱动 `wlIoctl(254)` →
  `wlc_ioctl(254)`。内嵌驱动没有 254 的 assoc handler；未知类型返回 `0x66`（19:30 快照 `Req2=483` 的 `ReqRes2=102`
  就是同类未知类型的实测返回，`483` 走的是同一条 Classic 路径）。
- **Virtual/Skywalk**：`apple80211_ioctl_set(type=254)`：
  ```asm
  ; payload0 @0x91ede
  91ef8: movl 0x10(%rbx),%eax       ; type
  91efb: leal -0x1a2(%rax),%esi     ; type - 418
  91f01: cmpl $0xfffffe5f,%esi      ; 合法 1..417
  91f07: jb   0x91fd5               ; 越界 -> 0x66
  91f0d: decl %eax                  ; index = type-1
  91f0f: leaq _gSetHandlerTable
  91f16: movq (%rsi,%rax,8),%r15
  91f1a: testq %r15,%r15
  91f1d: je   0x91fb4               ; 空槽 -> log + 0x66
  ...
  91ff6: movl $0x66,%eax
  ```
  254 ≤ 417，但 `table[253] == 0`，走 `0x91fb4` 的 `logDebug("IOCTL (from pid %d) not recognized: %d out of %d")`，
  返回 **0x66**。**不会**是 `LastResult=0`，也**不会**产生 AssociationDone。
  所以“254 且有 result 0”只能解释为 get 254（`getHwSupportedChannels`），或用户客户端结构版本读错（未验证）。

### 4.3 如果 27 用 Set 20 + 0x290（当前最可能的真实情况）

- 请求在 `UserClient.cpp:320` 被拒（`AssociationRequests` 会 +1，`LastAssociationResult=BadArgument`），
  `Bridge::command` 根本不会执行；驱动、事件、用户态都看不到这次关联。
- 如果只放宽 320 但保留 `prepareAssociate`，在 `WirelessABI.hpp:287` 被拒（同样 `goto done`）。
- 如果两处都放宽但转换仍按 0x38C，驱动会收到字段错位的 0x224；最坏情况是把 SSID/key/PMK/BSSID 的偏移读错，
  关联失败或连到错误参数，且不会有明确的错误码告诉你“布局错了”。

### 4.4 ENXIO 与 `Rejects`

`Bridge::command` 在 `endpoint.interface->isInactive()` 或 `controller->isInactive()` 时返回 `ENXIO`
（`Bridge.cpp:538-550`），只更新 `Rejects/RejectInterfaceInactive/RejectControllerInactive/LastRejectType/LastRejectKind`。
注意：`LastRequest`、`ReqHist` 在 `runCommand` 里、调用 `Bridge::command` **之前**写入（`UserClient.cpp:304-312`），
所以 ENXIO **不会**让请求从历史/`LastRequest` 消失；当前 `Rejects=0`，可以排除这条早退。

> 更正：`Docs/Reverse-Payload-SetTable-20261117.md` §0.8/§7.6 说“ENXIO 不更新 LastRequest/ReqHist”，
> 与 `UserClient.cpp:304-312` 的顺序不符；准确说法是 ENXIO 不影响 `LastRequest/ReqHist`（它们在 Bridge 之前写），
> 只影响 `LastAssociationResult`（若 type 20 已进 runCommand）和 `Rejects` 系列。

### 4.5 绕过用户客户端的可能路径

内嵌驱动的 `apple80211RequestIoctl` 是**控制器级**入口：`IO80211Interface` 的 legacy ifnet ioctl
（`SIOCSA80211`，airportd）可以直接走到它，不经过 `BCM80211UserClient::runCommand`。
这类请求不会增加 `AssociationRequests`、不会出现在 `ReqHist`，也不会被 `prepareAssociate` 转换。
如果 27 的关联是 airportd 通过 ifnet ioctl 发的，那么：
- 内嵌驱动会直接收到 27 的 0x290 结构（被当成 0x224 解析），
- 现有计数器全部看不到，
- 用户态等 120 秒超时，与实测现象也相容。

**本会话无法用现有材料排除这条路径**。§PatchDraft 的 A2（在 `AirPort_BrcmNIC::setASSOCIATE` 入口挂钩计数）
是唯一能同时覆盖用户客户端与 ifnet ioctl 的决定性实验。

---

## 5. 事件路径

### 5.1 关联完成事件 9 的投递链

- 常量：`AssociationDoneEvent = 9`（`WirelessABI.hpp:35`）。
- Hook：`postClassic`/`postVirtual`/`postInfra` 分别路由
  `IO80211Interface::IO80211InterfacePostMessage`、`IO80211VirtualInterface::IO80211InterfacePostMessage`、
  `IO80211InfraInterface::postMessageInternal`（`Bridge.cpp:706-708`），都调用
  `queueEvent(self, kind, message, payload, length)`（`Bridge.cpp:523-536`）。
- 内嵌驱动确实导入这三个 postMessage 入口（`nm -u payload1.bin`：
  `IO80211Interface::postMessage`、`IO80211VirtualInterface::postMessage`、`IO80211InfraInterface::postMessage`），
  所以驱动侧的事件会落到 hook（前提是它们最终调用被路由的 `*PostMessage`/`postMessageInternal`，之前的分析已核对调用链）。
- `queueEvent` 在 `Bridge.cpp:469-472` 先给 `AssociationEvents` 计数，再走 pending 队列、`drainEvents`、
  `receive()` 的 filter 和 ring。**计数与 filter/ring 无关**。

### 5.2 `AssociationEvents=0` 的判定

- 不是 filter：`receive()` 的 `filter.accepts` 在 `UserClient.cpp:502`，位于 `queueEvent` 之后；
  默认 `filter.all=1`（`UserClient.cpp:69`），且即便 wifid 设了 filter，`AssociationEvents` 已经先加过了。
- 不是 ring 未读/丢弃：`DroppedEvents=0`，`receive()` 的 append 失败会加 `Dropped`（`UserClient.cpp:509-511`）；
  事件 9 从未进过 `receive`，因为 `queueEvent` 没被调用。
- 不是 hook 没装上：同一组 hook 收到并计数了 20 次 ScanDone 事件 10（`ScanDoneEvents=20`），
  `ScanDoneRecords` 也在增长，说明 `postMessage` 路由对事件 10 有效。
- 结论：**内嵌驱动没有 post 事件 9**（或 27 用了一条本桥未覆盖的事件通道，见 §5.3）。
  最直接的解释是没有关联完成（不管是因为没发关联，还是关联失败）。

### 5.3 事件 9 的转换风险（即使将来产生）

`captureJoinEvent`（`Bridge.cpp:355-377`）：

```cpp
Endpoint endpoint {event->interface, event->controller, InterfaceKind::Classic, {}};  // 357：硬编码 Classic
...
auto error = readEventValue(endpoint, 50, buffer, sizeof(uint32_t), &status);   // get ASSOCIATION_STATUS
if (!error) error = readEventValue(endpoint, 21, buffer, sizeof(uint32_t), &result); // get ASSOCIATE_RESULT
if (!error && result == 1) error = readEventValue(endpoint, 9, buffer, sizeof(buffer)); // get BSSID
...
if (encodeJoinStatus(status, result, ..., Bridge::abi())) { event->length = abi.joinStatusSize; ... }
```

触发条件（`Bridge.cpp:483-486`）：

```cpp
entry.interface = abi.joinEventPolicy != JoinEventPolicy::Passthrough &&
    message == AssociationDoneEvent && !length && kind == InterfaceKind::Classic ? self : nullptr;
```

因此：

1. **只有 Classic 且 payload 为空**的事件 9 才会被转成 0x1D4 的 join status；非空 payload 直接原样进 ring。
2. `PendingEvent` 没有 `kind` 字段（`Bridge.cpp:50-60`），`captureJoinEvent` 永远用 `InterfaceKind::Classic`；
   如果 27 的关联完成事件是从 Virtual/Skywalk 接口投递的，转换路径根本不会执行，用户态会收到 legacy 原始事件。
3. `encodeJoinStatus` 的 0x1D4 布局（status@+0x1B8/+0x1BC、result@+0x1C4、1@+0x1C8、BSSID@+0x1CC）
   是 Tahoe 的（`WirelessABI.hpp:267-284`）。27 的 `apple80211_join_status` 是否仍是 0x1D4 **未验证**；
   `GoldenGateABI.joinStatusSize` 只是沿用 Tahoe（`WirelessABI.hpp:86-88`）。
4. 即使事件 9 产生，`captureJoinEvent` 的 50/21/9 读取也可能失败；失败会加 `AssociationEventReadErrors`，
   但 `queueEvent` 已经把原始事件排进 ring，所以用户态仍会收到 legacy 负载（可能不是 27 期望的布局）。

**结论：** 当前 `AssociationEvents=0` 是“驱动没产生”；但事件路径本身还有一个 27 特有的“产生后可能转换错”的缺口，
需要在关联真正发生时验证，不能把 0 归因于 filter/ring。

---

## 6. 为什么 27 现在没有发 type 20（候选，全部未验证）

1. **用户态在关联之前就中止了。** 27 的 Settings/airportd 可能在 join 前检查 scan result、
   `getCURRENT_NETWORK`(103)、`setINFRA_ENUMERATED`(512)、`setOS_FEATURE_FLAGS`(469) 等；
   其中 103 在 payload0 里是 `mov $0x66; ret` 的三指令 stub（`Docs/Analysis-20261117-driver-side.md` §2.4），
   469/483/490/512/575 也返回 0x66（19:30 快照 `Req2=483` 的 `ReqRes2=102` 是实测）。
   这些失败是否会让 wifid 在 join 前放弃，**没有代码/日志证据**。
2. **关联走 ifnet ioctl（airportd），绕过被包装的用户客户端。** 见 §4.5；现有计数器无法排除。
   若成立，内嵌驱动已经收到 27 的 0x290 结构并被当成 0x224 解析，用户态超时；这会是比“用户客户端长度门禁”更早的失败点。
   同会话的 airportd 取证（`Docs/Reverse-Assoc-20261117.md` §2.4）记录本轮 `Apple80211SetWithIOCTL` 的 type 集合为
   `{51,216,363,469,483,490,512,575}`，**不含 20/254**；若该日志覆盖完整，则 ifnet 路径本轮也没有关联。
   但该日志是 airportd 自己的调用点，不能排除其它调用路径，所以 A2 仍值得做。
3. **27 用了一个新的 selector/命令描述符。** 27 的 `IO80211APIUserClient` external method 表
   （`0xffffff80021a6980`）只有 **9 项**（0..8），与 `Selector` 枚举一一对应；当前 `Selector6 (LargeCommand)=0`、
   `Selector8 (MapUserBuffer)=0`，没有第 10 个 selector 的迹象。`IO80211DriverCommandDescriptor`/`routeIoctlToWcl`
   是新 WCL 内部路径，但 SimpleBCM 包装的是同一个用户客户端，selector 0 仍应到达。**未验证。**
4. **用户点击的网络没有通过 wifid 的候选筛选**（SSID/安全类型/扫描结果内容不匹配），因此没有发出 join。
   扫描计数器增长只能证明 request 11 成功读回结构，不能证明 27 用户态解析出的 SSID/IE 正确。
   `expandScanResult` 只把 legacy 0x48C 零扩展到 0x8E8，没有重排字段；27 的 scan_result 是否仍是同一前缀布局**未验证**。
5. **02:19 的 `LastRequest=254` 只是一次 getHW_SUPPORTED_CHANNELS**（§3），与关联无关；
   当前 boot 的 `LastRequest=96` 也说明系统在 idle 轮询，不是 join 卡在驱动。
6. **同会话的 airportd 取证给出了更强的“阻塞在用户态”证据。** `Docs/Reverse-Assoc-20261117.md` §2.2/§2.3：
   19:23:38 的 `[ASSOC]` 请求已经进入 airportd 的 `__associateToWiFiNetwork:`，完成 private MAC 和
   `setNetworkIDForAssociationWithMACAddress:` 后，停在 `0x10000d6bc` 与 `0x10000d7c8` 之间；
   其后的 `setAssociatedNetwork:`、`Will associate to [%@]`、`Debounce the Link`、`[DISASSOC]` 一条都没有出现。
   驱动侧的关联 Set 在这条路径的更后面，所以**本次 120 秒超时发生在驱动关联之前**；
   `AssociationRequests=0` 与这个用户态阻塞完全一致，不能据此推断“驱动关联代码是当前根因”。
   （该报告的 §3 把 02:19 的 `LastRequest=254/LastResult=0` 解释为“至少把 Set 254 发到了驱动”，
   这个推断与 §3 的表结构矛盾：set 254 是空槽、会返回 0x66；按现有证据更可能是 **get 254**，
   或 V1/V2 请求头读错。不要把 254 作为关联号或补丁依据。）

---

## 7. 判断：先修哪一侧

### 7.0 现状判断（结合 airportd 取证）

`Docs/Reverse-Assoc-20261117.md` §2.2/§2.3 的证据比本报告的驱动侧计数更靠近现场：
19:23:38 的 `[ASSOC]` 已经进入 airportd 的 `__associateToWiFiNetwork:`，完成 private MAC 和
`setNetworkIDForAssociationWithMACAddress:` 后停在 `0x10000d6bc`–`0x10000d7c8` 之间；
`setAssociatedNetwork:`、`Will associate to [%@]`、`Debounce the Link`、`[DISASSOC]` 一条都没有出现。
驱动侧的关联 Set 在这条路径的更后面。因此：

- **本次 120 秒超时的最近阻塞点是 airportd/CoreWiFi，不是 SimpleBCM 的关联转换。**
  这与 `AssociationRequests=0`、`LastRequest=96`、`Rejects=0` 全部一致。
- **驱动侧 0x290 转换补丁对本次超时没有修复作用**；它是“用户态走到 Set 之后”的下一道门。
- 受“不允许修改系统文件/用户态组件”的约束，airportd 的阻塞只能定位、记录、报告，不能在 EFI/kext 里修。
  驱动侧能做的只有：证明驱动未参与（A1/A2）、保证未来关联下发时不因 0x290 失败（B）、
  以及保证前置响应（scan/capability/事件）不成为更早的阻塞因素。

### 7.1 顺序

1. **先加驱动侧可观测性（A1 + A2）。** 这是唯一能在不修改用户态的前提下区分
   “用户态没发 / 用户客户端拒了 / ifnet 路径进了驱动 / 驱动收了但没完成”的手段；
   即使 airportd 报告已经指向用户态，A1/A2 也是把“驱动未参与”钉死的证据，并为下一轮提供判据。
2. **若 A2（驱动 `setASSOCIATE` 调用数）> 0：** 关联确实到了驱动。
   - 若 A1（`AssociationRequests`）也 > 0 且 `LastAssociateLength=0x290`、`LastAssociationResult=BadArgument`：
     根因就是 §2.3/§2.4 的长度/布局门禁，按 B 修 0x290 转换。
   - 若 A1=0 而 A2>0：请求走的是 ifnet ioctl（或其它绕过 runCommand 的路径），
     问题在“驱动直接收到 0x290 当 0x224 解析”；需要在控制器/驱动边界做转换，而不是只改用户客户端。
   - 若 A2>0 且 `AssociationEvents=0`：驱动已收关联但没完成（或事件走了未覆盖的通道）；
     查驱动返回码/事件 9 的 kind/length，再决定 B3。
3. **若 A1=0 且 A2=0：** 关联根本没有到驱动。此时补关联转换**没有意义**；
   应转向 §6.1/§6.4 的前置请求（scan result 内容、103、27-only Set、availability 事件）以及
   Settings/wifid 侧的证据。注意这已经超出 EFI/kext 能单方面修复的范围，需要明确说明技术边界。
4. **无论 A2 结果如何，0x290 转换都是迟早要补的真 bug。** 它不是当前超时的“根因修复”，
   但一旦用户态走到关联，就会以 `BadArgument` 或字段错位失败。

### 7.2 “驱动侧补丁还有没有意义”

有，但分两层：

- **关联转换补丁（B）**：只在“27 已下发 type 20 且长度 0x290”时生效；当前没有证据表明已下发，
  所以它**不能单独解释/修复当前的 120 秒超时**。把它当作“下一道门”的修复，而不是根因修复。
- **前置响应/可观测性补丁（A）**：现在就有意义。A1 把“最后 16 条”升级为持久计数/Set 历史；
  A2 把“驱动是否收到关联”变成可判定。没有 A，任何关联补丁都无法验收。
- **不要**为了让“看到 20”而伪造请求、不要在用户态重试/重启服务、不要改系统文件。
  验收以真实 Settings 连接 attempt + A2 计数 + 事件/关联结果为准。

---

## 8. 验证矩阵（本会话不执行构建/部署/重启）

### 8.1 构建/CI（维护者执行）

```sh
python3 -B Tools/check.py
python3 -B Tools/build.py build --configuration Debug
python3 -B Tools/build.py build --configuration Release
python3 -B Tools/build.py analyze --configuration Release
```

CI（`.github/workflows/build.yml`）在 `macos-26-intel` 上跑同样四步；Debug/Release 都过才算构建通过。
若新增 0x290 转换器，必须在 `Tools/verify.py` 增加向量（0x290→0x224 的字段级断言 + 越界/错误路径），
否则 ASan/UBSan 不会覆盖新分支。

### 8.2 运行期（重启后，由维护者决定）

```sh
ioreg -rn SimpleBCM -l | grep -E 'AssociationRequests|LastAssociateLength|AssociateLengthMismatch|DriverAssociateRequests|DriverAssociateHookReady|AssociationAccepted|LastAssociationResult|AssociationEvents|LastAssociationEventLength|DroppedEvents|Rejects|LastRequest|LastResult'
```

判定表（一次真实的“连接 Wi-Fi”attempt 后）：

| A2 `DriverAssociateRequests` | A1 `AssociationRequests` | `LastAssociateLength` | 判定 | 下一步 |
| --- | --- | --- | --- | --- |
| 0 | 0 | — | 关联未到驱动 | §6 前置/用户态；不要先改 0x290 |
| ≥1 | 0 | — | 走了 ifnet/绕过路径 | 在驱动/控制器边界计数并转换 |
| ≥1 | ≥1 | 0x290 | 用户客户端收到 0x290，长度门禁拒绝 | 启用 B（0x290 转换） |
| ≥1 | ≥1 | 0x38C | 长度对但布局可能不是 0x38C | 用 A2 的样本核对 0x202/0x206、0x240/0x244 |
| ≥1 | ≥1 | 其它 | 第三种长度 | 先记录样本，不要猜 |
| ≥1 | ≥1 | 0x290，且 `AssociationEvents>0` | 转换/事件已推进 | 看 `LastAssociationEventLength` 是否 0x1D4、用户态是否接受 |
| 任意 | 任意 | `Rejects>0` | ENXIO 早退 | 查 inactiveness/endpoint |

补充：

- `LastAssociationResult == 0xE00002C2` 表示 type 20 进了 runCommand 但被门禁/转换拒绝；
- `LastAssociationResult == 6`（`ENXIO`，`Bridge::command` 的 plain errno）表示 Bridge 层拒绝；
  `kIOReturnNotOpen` 等 dispatch 层错误走的是另一条路径，不会写成 ENXIO。
- `AssociationEvents>0 && LastAssociationEventLength != 0` 表示事件 9 带非空 payload，未走 join-status 合成；
- `DroppedEvents>0` 才考虑 ring/队列。

### 8.3 回归

- 扫描：`ScanRecords`/`ScanDoneRecords` 继续增长，`bcmprobe --scan` 返回非空（用户态工具，只读）。
- Capability/scanResult：`LastResult=0`，`CommandErrors` 不再随 Opens 同步增长。
- 事件：`ScanDoneEvents` 继续增长，`Notifications`/`NotificationErrors` 正常。
- 睡眠唤醒/AWDL：本补丁不应触碰，但需在关联验证后复跑一次既有清单。

---

## 9. 未验证清单

1. **wifid 实际 `header->length`**：0x290（27 kext 自身消费的长度）还是 0x38C（沿用 Tahoe）——必须用 A1/A2 样本确认。
2. **27 的 0x290 布局全貌**：目前只确认 `0x10/0xD0/0x1D8/0x202/0x240` 五个校验点；
   auth/SSID/key/PMK/BSSID 数组/scope 的完整偏移没有逐字段验证；`0x202 vs 0x206`、`0x240 vs 0x244` 的 4 字节差异从何而来未知。
3. **关联是否走 ifnet ioctl（airportd）而非用户客户端**：A2 才能排除。
4. **27 的 join status 尺寸/布局**：`GoldenGateABI.joinStatusSize=0x1D4` 只是沿用 Tahoe；27 KC 未给出直接证据。
5. **27 事件 9 的 payload 长度与 endpoint kind**：`AssociationEvents=0`，没有样本。
6. **27 的 V1/V2 `apple80211IOUCReq` 选择**：`validateBufferLengthV2` 存在，但本会话没有逐指令核对触发条件；
   若某些 selector 用 V2，SimpleBCM 的 V1 解析可能读错 type/length（这也是“254 set 成功”唯一还能自洽的解释）。
7. **02:19 `LastRequest=254` 的 `LastRequestSet`/kind**：当时快照未给出；按表结构最可能是 get。
8. **27-only Set（469/483/490/512/575/363）失败是否阻塞 join**：无代码/日志证据。
9. **scan result 内容是否被 27 用户态接受**：`ScanRecords` 只证明读取成功，不证明字段布局/IE 正确。

---

## 10. 证据索引

- 代码：`SimpleBCM/UserClient.cpp`（244-430, 497-517）、`SimpleBCM/WirelessABI.hpp`（39-40, 86-88, 267-314, 347-355）、
  `SimpleBCM/Bridge.cpp`（355-377, 413-499, 538-577, 696-708, 815-858）、`SimpleBCM/Bridge.hpp`（36-82）、
  `SimpleBCM/NativeUserClient.cpp`（124-200）、`SimpleBCM/Patcher.hpp`（19-23）。
- 工具/字段表：`Tools/profiles.py`（35, 103）、`Tools/audit_codecs.py`（61-79）、`Tools/kernel_collection.py`。
- 兄弟报告（未跟踪）：`Docs/Reverse-Payload-SetTable-20261117.md` §0/§2/§5/§6/§7（表结构、0x290 证据、四张表对照）。
- 27 KC：`/System/Library/KernelCollections/BootKernelExtensions.kc`（只读；`com.apple.iokit.IO80211Family`，
  版本 1200.13.1，UUID `FCFF2E2C-C353-3ED2-9010-D88CC8A08050`）。
- 内嵌 payload：`.research/extract/payload0.bin`（IO80211FamilyLegacy，417 表）、
  `.research/extract/payload1.bin`（AirPortBrcmNIC-Tahoe，驱动 `setASSOCIATE`）。
- 运行期：`ioreg -rn SimpleBCM -l`（§1.1）、`ioreg -l` 类计数（§1.2）、`kmutil showloaded`（§0 系统/kext 版本）。

> 本报告没有 commit/push，没有修改源码，没有构建/部署/重启。补丁草稿见
> `Docs/PatchDraft-Assoc-20261117.md`。


---

## 11. 实施状态（2026-11-17，工作区）

按本报告与 `Docs/PatchDraft-Assoc-20261117.md` 已写入源码（**未 commit/push、未构建、未部署、未重启**）：

- `SimpleBCM/Bridge.hpp` / `Bridge.cpp` / `UserClient.cpp`：A1 持久计数 + 16 条 Set 历史 + 0x290 样本记录；
  A2 `countSetAssociate` 可选 route（失败不 disable bridge，当前部署产物上 `DriverAssociateHookReady=0`）；
  A3 事件 9 的 kind 计数；新增 ioreg 属性。
- `SimpleBCM/WirelessABI.hpp`：`GoldenGateAssociateSize=0x290`、`GoldenGateAssociateGap=0x1FC`、
  `prepareAssociateGoldenGate`；默认拒绝 0x290，只有 `-sbcmggassoc` 才转换。
- `Tools/profiles.py`：把 `AirPort_BrcmNIC::setASSOCIATE` 加入 `ROUTE_SYMBOLS["AirPort"]`，供下次 payload 生成使用。
- 语法检查（clang `-fsyntax-only` + py_compile）通过；**不是完整构建**。构建/部署/重启验证仍未做。

本报告第 0–10 节的审计结论不因这些加法改动而改变；当前 120 秒超时的最近阻塞点仍是 airportd（§7.0）。
