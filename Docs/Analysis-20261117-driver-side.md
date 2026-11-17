# SimpleBCM 驱动侧分析：request 分发、417 表、可用性事件与未提交 diff

日期：2026-11-17（America/Los_Angeles）
系统：macOS 27.2（26B123 / Darwin 27.2.0，x86_64），BCM43602（`pci14e4,43ba`）
代码基线：`main` @ `71dd72c` + 工作区未提交改动（= 远程 e2fa373 内容，见 §5）
产物：`simplebcm-artifacts/artifact-e2fa373/debug/.../SimpleBCM-v1.2.1-DEBUG-alpha-e2fa373`

> 取证边界：本会话**没有 sudo**，`dmesg` 被拒（`Unable to read kernel buffer: Operation not permitted`）。
> 内核侧实时证据取自统一日志（`log show`，IOLog 会以 `(Embedded)` 标记出现）与 IORegistry；
> 静态证据取自部署产物里的内嵌 payload（从 SimpleBCM 二进制提取，见 §1.1）与 BootKernelExtensions.kc。
> 父代理提供的 dmesg 摘录在文中标为「父代理 dmesg」，本会话未复读原始 dmesg。

---

## 0. 结论摘要（先看这里）

1. **417 不是 "BrcmTahoe payload" 的表，而是内嵌 `IO80211FamilyLegacy`（payloads[0]，UUID `4C07538B-…`）的 Get/Set 分发表容量**。`_gGetHandlerTable`/`_gSetHandlerTable` 各 417 项，Get 211 项非空、Set 187 项非空；`AirPortBrcmNIC-Tahoe`（payloads[2]，SHA `0b6cf936…`）里没有这张表。`Docs/First-Run-macOS27.md:81` 的归属说法需要更正。
2. 越界判定在 `IO80211Controller::apple80211_ioctl_get/set`：`type` 只接受 `1..417`，否则直接返回 **0x66**；日志 `IOCTL (from pid %d) not recognized: %d out of %d` 在 **Set** 路径里以字面量 417 打印。Get 越界**不打印**这条日志。
3. 关键坑：**Set 分派器在"表内 handler 返回 0x66"时也打同一条日志**。因此 `363 out of 417` 不代表 363 越界；363 在表内，handler 是 `setUSBHostNotification`（非 stub），按代码路径可推断是下游返回 0x66（`0x91f8b-0x91f8e`）。只有 `469/483/490/512/575` 是真正 `>417`。
4. 六个类型**全部是 Set**（27 的 `gInternalSetHandlerTable` 对应 `setUSB_HOST_NOTIFICATION` / `setOS_FEATURE_FLAGS` / `setEXTERNAL_POWER_STATE` / `setPRODUCT_INFO` / `setINFRA_ENUMERATED` / `setOS_ELIGIBILITY`）。扫描/关联/结果读取用的是 `10/86/20/11/12/19`（全部 ≤417 且有实现），事件过滤 `0x234` 在 kext 内本地消费（不查表），**都不经过这六个类型**。
5. 27 的 `IO80211Family`（系统 KC，UUID `FCFF2E2C-…`）自身 legacy 表是 **590（Get）/ 457（Set）**，比注入的 Tahoe 时代 417 大；六个 Set 的 handler 在 27 的 internal 表里都有实现（其中 469/483/490/512/575 超出 legacy Set 表，363 在 legacy 表里也有）。**对这六个请求而言，根因是注入的 legacy 分派层停留在 Tahoe 时代**，不是 `runCommand` 的边界判断写错；也就不存在"一个小改动让 27 命令全部工作"的修法。
6. `DriverAvailabilityEvents=0` **不是事件丢失**，而是内嵌 AirPortBrcmNIC **从未 post 0x37**（`DroppedEvents=0`，hook 链已核对）；bridge 用 `GET_POWER(19)` 合成可用性快照，在每次 `MonitorStart` 重放（实测 `PowerAvailabilityEvents=3`、`LastAvailabilityReadResult=0`、`DriverAvailabilityReplays=631`）。合成负载长度 0xF8 与 27 系统 `setDriverAvailable` 要求的 0xF8 一致；**字段语义未验证**。
7. 没有证据表明"0 个真实事件"会让 airportd/wifid 认为硬件不可用：用户态仍持续 Open/Subscribe/MonitorStart（1707/846/846），通知 1500 次、失败 1 次。菜单为空与"扫描从未发起"（probe 从未见到 `req=10/86`）一致；airportd 崩溃循环是父代理归因，本会话未抓到 crash report（未验证）。
8. **当前这一轮启动的 SimpleBCM 基本可以确定不是 DEBUG 构建**：`log show --last 2m | grep -c 'SimpleBCM:'` = 0，近 20 分钟过滤 `iouc/probe/loader/bridge` 也为空，而内嵌镜像的 `(Embedded)` IOLog 行正常；`DBGLOG` 在 Release 构建里被编译掉（`Patcher.hpp:19-23`），Debug 构建里 `simpleBCMDebug` 恒为 true（`SimpleBCM.cpp:143-147`）。因此**当前启动没有 probe/iouc 证据**，之前的 dmesg 证据来自更早的 DEBUG 启动。
9. 未提交 diff（回滚 103 映射 + probe + 文档）与 e2fa373 产物源码一致（Docs 逐字节相同、产物含两条 probe 格式串）；**不应**在本地 `71dd72c` 之上再 commit 一次，建议先 `git fetch` 对齐 `origin/main`，并用 tag 保留 103 实验。
10. 小改动只能做**诊断**（trace 计数器/尺寸属性）；行为层面的真修复（103 CURRENT_NETWORK、27-only Set 转发）不是小改，且需要 27 结构布局，当前证据不足。

---

## 1. Request 分发链与 417 表的位置

### 1.1 代码路径

| 阶段 | 位置 | 说明 |
| --- | --- | --- |
| 用户客户端 selector 检查 | `SimpleBCM/UserClient.cpp:147-153` | `selector >= abi.selectorCount` → bad arg；selector 0/6 进入命令 |
| selector → 容量 | `SimpleBCM/UserClient.cpp:160-170` | `Command`=0x3C00，`LargeCommand`=0x3C000 |
| 包布局 | `SimpleBCM/UserClient.cpp:245-278` | `CommandHeader{command,length}` + shadow(capacity) + `LegacyRequest`(0x30) |
| 请求解码/分类 | `SimpleBCM/UserClient.cpp:279-288` | `GetCommand=0xC02869C9`、`SetCommand=0x802869C8`；scanResult/capabilities/associate/roam |
| 尺寸门禁 | `SimpleBCM/UserClient.cpp:303-311` | scanResult 要求 `outputSize == abi.scanResultSize`；capability 同理 |
| 预处理/下发 | `SimpleBCM/UserClient.cpp:328-348` | `prepareScanResult`/`prepareScanMultiple`/`prepareAssociate` → `Bridge::command` |
| 事件过滤本地拦截 | `SimpleBCM/UserClient.cpp:337-343` | `set && request == abi.filterMonitorEvents(0x234)` 在 kext 内消化，不转发 |
| 结果展开/拷贝 | `SimpleBCM/UserClient.cpp:349-386` | `expandCapabilities`/`expandScanResult`，produced 长度校验 |
| 计数 | `SimpleBCM/UserClient.cpp:400-413` | `ScanRecords` 只在 scanResult 成功时 +1；失败走 `iouc` 日志 |
| Bridge 路由 | `SimpleBCM/Bridge.cpp:538-567` | Classic → `performCommand`；Virtual/Skywalk → `apple80211_ioctl_get/set` |
| 符号来源 | `SimpleBCM/Bridge.cpp:679-687` | `getRequest`/`setRequest`/`classicCommand` 全部从 **index 0 = 内嵌 Legacy** 解析 |
| 路由安装 | `SimpleBCM/Bridge.cpp:693-700` | 拦截 `newUserClient`、`IO80211InterfacePostMessage`、`postMessageInternal` 等 |

### 1.2 417 表确实在内嵌 IO80211FamilyLegacy 里

仓库工具本身就把这张表算在 `Legacy` 镜像上：

- `Tools/profiles.py:103`：`table = struct.unpack("<417Q", image.read(image.symbols["_gGetHandlerTable"], 417 * 8))`，其中 `IMAGES["Legacy"]` 指向 `IO80211FamilyLegacy.kext`（`Tools/profiles.py:21`）。
- `Tools/audit_codecs.py:21` 同样按 417 项读 `Legacy` 镜像。

我把部署产物 `artifact-e2fa373/.../SimpleBCM` 的三个内嵌 payload 按 `Payload` 数组地址（`nm`: `_bcmPayload0/1/2`）提取出来（`.research/extract/`，`.research/` 已被 `.gitignore` 忽略）：

| 提取物 | 大小 | UUID | 对应 |
| --- | --- | --- | --- |
| `payload0.bin` | 2,306,048 | `4C07538B-62EB-3D6D-AEF993BC-DCF45FAB` | `Docs/ABI.json` 的 `Legacy` = IO80211FamilyLegacy v1.0.0 |
| `payload1.bin` | 9,179,136 | `E4678FEB-1DC135CC-93064802-1083D04A` | `AirPortOriginal` = AirPortBrcmNIC（Tahoe 的 base） |
| `payload2` | —（delta 流） | — | `AirPort`（Tahoe，SHA `0b6cf936…`），运行时由 payload1 + delta 还原 |

选择规则：`Tools/native_payload.py:348` `'airPortPayloadIndex': 2 if kernel >= 25 else 1`，`Loader.cpp:166/185` 对 index 1 取 `payloads[airPortPayloadIndex]`；`Loader.cpp:193` 调 `restorePayload()`（`Relocate.cpp:18-52`）先 copy base 再打 delta。因此 Darwin 27 实际加载的是 `Legacy` + `AirPortBrcmNIC-Tahoe`。

在 `payload0.bin` 里：

```
_gGetHandlerTable      0x14a140     _gGetHandlerTableCount  0xf7cd0 = 417
_gSetHandlerTable      0x14ae50     _gSetHandlerTableCount  0xf8b00 = 417
非空项：Get 211 / Set 187
```

`payload1.bin`（AirPortBrcmNIC）**没有** `_gGetHandlerTable`/`_gSetHandlerTable`（`nm payload1.bin | grep HandlerTable` 为空）。

### 1.3 分派实现（反汇编）

`payload0.bin` 的 `IO80211Controller::apple80211_ioctl_get` @ `0x91e1a`：

```asm
91e27  movl 0x10(%r8), %eax        ; eax = apple80211req->type
91e2b  leal -0x1a2(%rax), %edi     ; type - 418
91e31  movl $0x66, %r15d           ; 默认返回值 ENOTSUP(0x66)
91e37  cmpl $0xfffffe5f, %edi      ; (uint32)(type-418) < (uint32)-417 ?
91e3d  jb   0x91e93                ; 是 → 直接返回 0x66（不查表、不打日志）
91e3f  decl %eax
91e41  leaq _gGetHandlerTable, %rdi
91e48  movq (%rdi,%rax,8), %rax    ; table[type-1]
91e4c  testq %rax,%rax             ; 空项 → 0x66
91e4f  je   0x91e93
```

等价于：**只有 `type ∈ [1, 417]` 才可能被处理**。Set 版 @ `0x91ede` 同构，并额外在：

- `0x91fbc`、`0x91fdd` 两处引用消息串 `0x12783c`：`"IOCTL (from pid %d) not recognized: %d out of %d"`（按 RIP-relative LEA 扫描只有这两处引用，都在 `apple80211_ioctl_set` 内；未覆盖所有指令编码）。
- `0x91fc8`/`0x91fe9`：`movl $0x1a1, %r8d`，即第三个参数硬编码 **417**。

Set 的关键分支：

```asm
91f16  movq (%rsi,%rax,8), %r15    ; handler = setTable[type-1]
91f1a  testq %r15,%r15
91f1d  je    0x91fb4               ; 表内空项 → 打日志 + 0x66
...
91f88  callq *%r15                 ; 调 handler
91f8b  cmpl $0x66, %eax
91f8e  je    0x91fd5               ; handler 返回 0x66 → 打同一条日志 + 0x66
```

**因此日志文案会误导**：`N out of 417` 既可能是 `N>417`（真越界），也可能是 `N≤417` 但 handler/下游返回 0x66。

### 1.4 27 的 legacy 表更大，但我们的注入层只有 417

从 `BootKernelExtensions.kc`（Darwin 27.2.0）读 `com.apple.iokit.IO80211Family`（UUID `FCFF2E2C-C353-3ED2-90CA-A7776A68E892`）：

```
_gGetHandlerTableLegacyCount  = 590
_gSetHandlerTableLegacyCount  = 457
__ZL16gGetHandlerTable / gSetHandlerTable / __ZL24gInternalGetHandlerTable / gInternalSetHandlerTable
```

即 27 的 legacy 分发表规模是 590/457（按符号 `…Count` 读取；其精确语义未逐项验证，但至少说明 **417 不是 27 的协议上限**）。27 还有独立的 internal 表，六个 27-only Set 的 handler 就在 internal 表里（见 §2.1）。**注入的是 Tahoe 时代的 IO80211FamilyLegacy，只有 417**，这是能力缺口，不是本次 `runCommand` 改坏的。

### 1.5 实测日志（本会话直接抓到）

`log show --last 15m` 过滤 `not recognized`（2026-11-17 01:21 local）：

```
2026-11-17 01:21:11.810 Df kernel[0:12726] (Embedded)  IOCTL (from pid 12316) not recognized: 512 out of 417
2026-11-17 01:21:12.325 Df kernel[0:12726] (Embedded)  IOCTL (from pid 12316) not recognized: 469 out of 417
2026-11-17 01:21:12.330 Df kernel[0:12726] (Embedded)  IOCTL (from pid 12316) not recognized: 575 out of 417
2026-11-17 01:21:12.517 Df kernel[0:1274f] (Embedded)  ... 483 ...
2026-11-17 01:21:12.520 Df kernel[0:12726] (Embedded)  ... 363 ...
2026-11-17 01:21:13.480 Df kernel[0:12748] (Embedded)  ... 490 ...
（约每 10 秒重复一组，pid 每轮不同：12316/12350/12366/12445/12489）
```

`(Embedded)` 前缀与静态分析一致：消息由**内嵌镜像**打印，不是系统 27 的 IO80211Family。
频率并不低：`log show --last 2m | grep -c 'not recognized'` = **146 行/2 分钟**（≈1.2 行/秒），说明 airportd/wifid 在持续轮询这些 27-only 请求，而不是偶发。

同一时期 `log show` 里**没有任何** `SimpleBCM: probe/iouc` 行（见 §5.1），说明当前加载构建没有 DBGLOG。

---

## 2. 469/483/490/512/575/363 是否影响扫描、关联、菜单

### 2.1 六个请求的身份（来自 27 的 internal set 表）

用 `Tools/kernel_collection.py` 读 27 `IO80211Family` 的 `__ZL24gInternalSetHandlerTable`（KC chained-fixup 解码规则：取低 36 位 + `0x100000` 基址偏移；该规则先用已知项校验过：type 11 → `getSCAN_RESULT`、type 103 → `getCURRENT_NETWORK`、type 20 → `setASSOCIATE`）：

| type | 27 internal set handler | 性质 |
| --- | --- | --- |
| 363 | `apple80211setUSB_HOST_NOTIFICATION` | Set 配置（USB 主机通知） |
| 469 | `apple80211setOS_FEATURE_FLAGS` | Set 配置（OS 特性开关） |
| 483 | `apple80211setEXTERNAL_POWER_STATE` | Set 配置（外部电源状态） |
| 490 | `apple80211setPRODUCT_INFO` | Set 配置（产品信息） |
| 512 | `apple80211setINFRA_ENUMERATED` | Set 配置（infra 接口枚举状态） |
| 575 | `apple80211setOS_ELIGIBILITY` | Set 配置（OS eligibility） |

六个都是 **Set**；且 469/483/490/512/575 > 27 自己的 legacy Set 上限 457，只出现在 27 的 internal 表里。一种与全部观测一致的解释是：SimpleBCM 的用户客户端沿用 legacy ABI，而 airportd 发的是 27 的 modern 请求号；27 内部表与 legacy 表之间的实际调用关系本会话未验证。

### 2.2 方向证据（为什么能确定是 Set）

- 消息串 `0x12783c` 的全部 xref 只在 `apple80211_ioctl_set` 内（`0x91fbc`/`0x91fdd`）；`apple80211_ioctl_get` 的越界路径直接返回 0x66，不打这条日志。
- `Bridge.cpp:546-550` 只在 `Virtual`/`Skywalk` 端点调用 `apple80211_ioctl_set`；`Classic` 走 `performCommand` → `apple80211RequestIoctl`（`payload0.bin` @ `0x8ee5c`，直接跳到 driver 虚函数，不查 417 表）。
- 27 internal 表里六个条目名全部是 `apple80211set…`。

### 2.3 与"必需路径"的对照表

| type | 方向 | OCLP Legacy 表项（payload0） | 用途 | 受六个失败影响？ |
| --- | --- | --- | --- | --- |
| 10 | Set | `setScanRequest` @0x83fbd | 发起扫描 | 否（不同 type） |
| 86 | Set | `setScanRequestMultiple` @0x86f4c | 多通道扫描 | 否 |
| 11 | Get | `getScanResult` @0x78a33 | 读扫描结果（0x8E8） | 否 |
| 12 | Get | `getCardCapabilities` @0x78cb7 | 能力位图（23B） | 否 |
| 19 | Get | `getPower` @0x7928b | 电源/可用性来源 | 否 |
| 20 | Set | `setAssociateRequest` @0x84430 | 关联 | 否 |
| 0x234(564) | Set | 无（kext 本地拦截，`UserClient.cpp:337-343`） | 事件过滤；27 internal = `setFILTER_MONITOR_EVENTS` | 否 |
| 103 | Get | `getCurrentNetwork` @0x7c80f **是三指令 stub**：`mov $0x66,%eax; ret` | 当前网络 | 否（独立缺口，见 2.4） |

六个类型都不在扫描/关联/结果读取链上；必需请求的类型号都 ≤ 417 且表项非空。

### 2.4 两个容易误判的点

1. **363 不是越界**。`setUSBHostNotification` @`0x8d1c7` 是完整函数（不是 stub），表项 `set[362]=0x8d1c7` 非空；而 Set 分派器只有在越界或 handler 返回 0x66 时才打这条日志（`0x91f1d`/`0x91f8e`），所以可推断 363 的 handler/下游返回了 0x66（未逐指令定位返回点）。判定"363 超界"是错的。
2. **103 的 0x66 不是"27 新增扫描请求号"**。`getCurrentNetwork` 在 OCLP Legacy 里直接返回 0x66（`0x7c80f-0x7c819`），无论长度；27 的 internal 实现是 `apple80211getCURRENT_NETWORK(..., apple80211_scan_result*)`，即 27 用 0x8E8 的 scan_result 承载"当前网络"。当初把 103 映射到 11 会返回"最后一次扫描记录"而不是"当前关联的 BSS"，语义错误，**回滚是对的**；但 0x66 的根因是 legacy 层未实现，不是长度门禁。

### 2.5 「驱动侧必需」与「用户态可选」的结论

- **驱动侧必需（当前目标）**：10、86、11、12、19、20、0x234（本地）。全部可用；证据：OCLP 表项地址非零 + 之前的 `ScanRecords`/`LastResult=0` 实测 + 27 internal 同名 handler。
- **用户态可选（可忽略）**：363（PCIe 网卡无 USB host notification 语义）、469（feature flags）、483（外部电源）、490（产品信息）、575（OS eligibility）。失败只回 0x66，不改变扫描/关联路径。
- **需留意、未验证**：512 `setINFRA_ENUMERATED`。它是唯一可能与"接口枚举/菜单状态"有关的 Set；如果 27 airportd 把它当初始化前置条件，失败可能导致后续不发起扫描。当前**没有代码或日志证据**证明这一点，标为未验证。
- **未验证**：airportd 是否因这六个 Set 返回 0x66 而中止后续流程。probe 观察"从未出现 req=10/86"与两种解释都相容（a2x 崩溃 vs 前置失败），见 §6 的 trace 补丁如何区分。

---

## 3. `DriverAvailabilityEvents=0` / `DriverAvailabilityReplays` 的含义

### 3.1 计数器语义（代码）

| 计数器 | 递增位置 | 含义 |
| --- | --- | --- |
| `DriverAvailabilityEvents` | `Bridge.cpp:466`（`powerSnapshot == false`） | 驱动通过 postMessage 真正投递的 0x37 事件数 |
| `PowerAvailabilityEvents` | `Bridge.cpp:466`（`powerSnapshot == true`） | 由 `GET_POWER(19)` 合成并写入快照的次数（按 available 位图去重） |
| `DriverAvailabilityReplays` | `UserClient.cpp:443` | `startMonitor` 时把快照作为 0x37 重放进 ring 的次数 |
| `DroppedEvents` | `Bridge.cpp:419/476/497` | 负载/识别/队列导致的丢弃 |

发布位置：`Bridge.cpp:813-818`。

### 3.2 为什么 `DriverAvailabilityEvents=0` 不是"事件丢失"

- `WirelessABI.hpp:30` `DriverAvailableEvent = 0x37`；真实事件应由驱动 `postMessage` → `Bridge.cpp:696-698` 路由 → `queueEvent` 计数。
- 实测 `DroppedEvents=0`：没有因 `length > MaximumEventPayload`、`identify` 失败或队列满而丢弃；所以是**从未 post**。
- hook 链已核对，不是 hook 漏：
  - 内嵌驱动 import：`IO80211Interface::postMessage`、`IO80211VirtualInterface::postMessage`、`IO80211InfraInterface::postMessage`（`nm -u payload1.bin`）。
  - 这三者分别调用被路由的 `IO80211InterfacePostMessage`（`0x971ad`）、`IO80211VirtualInterface::IO80211InterfacePostMessage`（`0xb4b3c`）、`postMessageInternal`（`0xd2e2a`）。即驱动侧调用会落到我们的 hook。
- 正常产生 0x37 的入口 `IO80211ControllerMonitor::setDriverAvailable(payload,len)` 在 OCLP Legacy 里要求 **len == 0xB8**（`payload0.bin` @`0xf58d8`：`cmpq $0xb8,%rdx`）；内嵌 AirPortBrcmNIC **不引用** `setDriverAvailable`（`nm -u payload1.bin | grep -i driveravail` 为空）。这一条链路也不会触发。

### 3.3 replay 机制如何工作

1. `startMonitor`（`UserClient.cpp:419-451`）先 `Bridge::refreshAvailability(endpoint)`；
2. `Bridge::refreshAvailability`（`Bridge.cpp:501-506`）对 **Classic** 端点读 `type 19`；
3. 读到成功且 `length == PowerDataSize(0x18)` 时，`Bridge::command`（`Bridge.cpp:559-565`）调 `encodePowerAvailability()`（`WirelessABI.hpp:245-265`）合成 0xF8 负载，`queueEvent(..., powerSnapshot=true)`；
4. `queueEvent`（`Bridge.cpp:429-468`）把快照存进 `availability[16]`（同 controller+name 去重），`PowerAvailabilityEvents++`；
5. 之后每次 `MonitorStart`，`copyAvailability()`（`Bridge.cpp:508-521`）取快照，`UserClient::startMonitor` 把它作为 0x37 追加到事件 ring，`DriverAvailabilityReplays++` 并 `notifyAvailable()`。

尺寸链：legacy 内部 0xB8（`WirelessABI.hpp:31`）→ 用户态 0xF8（`WirelessABI.hpp:32`、`eventPayloadSize`/`copyEventPayload` `WirelessABI.hpp:95-112` 零填充）。27 系统 `IO80211Family` 的 `IO80211ControllerMonitor::setDriverAvailable`（KC 地址 `0xffffff80020abf1e`）在 `+0x1a` 用 `cmp rdx, 0xf8` 校验长度 —— **0xF8 与 27 一致**，这是一个正向证据。

### 3.4 实测（2026-11-17T09:41:02Z，`ioreg -rn SimpleBCM -l`）

```
DriverAvailabilityEvents   = 0
DriverAvailabilityReplays  = 631        （父报告 383 是更早快照；该值随 MonitorStart 单调增长）
PowerAvailabilityEvents    = 3
LastAvailabilityReadResult = 0          （GET_POWER 读取成功）
DroppedEvents              = 0
Events                     = 223
Notifications              = 1500
NotificationErrors         = 1
Opens                      = 1707
Selector2(Subscribe)       = 846
Selector3(MonitorStart)    = 846
Selector5(UseEventPipe)    = 846
Selector0(Command)         = 65641
CommandErrors              = 31541
ScanRecords                = 0
LastRequest                = 12
LastResult                 = 0
```

（任务给的是更早一轮快照：`DriverAvailabilityReplays=383`、`CommandErrors=19222`、`Opens=1044`；`LastRequest=12`、`ScanRecords=0` 与当前一致。计数器随启动/重载清零。）

### 3.5 结论：是否会让 airportd/wifid 认为硬件不可用

- **不是"事件未送达"**：每轮 `MonitorStart` 都会拿到一次合成的 0x37（631 次），通知通道正常（1500 成功 / 1 失败）。
- **也不是"replay 完全替代"**：真实事件从未产生；replay 只是缓存快照的重放。若某轮 `MonitorStart` 早于任何 `GET_POWER`（快照不存在），该轮就没有 0x37。
- **没有证据表明用户态因此判定硬件不可用**：airportd 持续 Open/Subscribe/MonitorStart；`LastAvailabilityReadResult=0` 说明电源读取成功；`Selector3=846` 说明监控请求持续到达。
- **未验证**：合成 0xF8 负载的字段布局是否符合 27 语义（`encodePowerAvailability` 只写 `+8` available 位图、`+0x10` reason `0xE0821803`，其余清零）；`EventFilter` 结构（本地拦截 0x234，`sizeof=0x20`）是否与 27 的 `apple80211EventFilter` 一致。二者都可能影响用户态对"可用性/事件"的解释，但当前没有观测到故障证据。

---

## 4. 未提交 diff：内容、一致性与提交建议

### 4.1 现状

```
$ git status -sb
## main...origin/main [ahead 1]
 M Docs/First-Run-macOS27.md
 M SimpleBCM/UserClient.cpp
 M SimpleBCM/WirelessABI.hpp

$ git log --oneline -2
71dd72c (HEAD -> main) Map Golden Gate scan result request 103 to 11
e8ad08b (origin/main) Fix Golden Gate scan result size to 0x8E8
```

- 本地 `origin/main` ref 停在 `e8ad08b`（未 fetch 到远程后来用 GitHub API 创建的 `b232a43`/`e2fa373`）。
- 工作区 diff（`git diff`，sha256 `aa40507d9ebe0c8a…`）：
  1. `WirelessABI.hpp`：删除 `GoldenGateScanResultRequest = 103` 及注释（回滚 `71dd72c`）；
  2. `UserClient.cpp`：去掉 103 映射分支，新增 probe 日志（`UserClient.cpp:290-298`、`388-394`）；
  3. `Docs/First-Run-macOS27.md`：新增「修复 3 回滚 / 修复 4 / 修复 5」三节。
- 无残留引用：`grep -rn GoldenGateScanResultRequest SimpleBCM/` 为空；`103` 只出现在 probe 条件里。

### 4.2 与当前基线是否一致

- 工作区 `Docs/First-Run-macOS27.md` 与 `artifact-e2fa373/.../Docs/First-Run-macOS27.md` **逐字节相同**（`diff` 无输出）。
- 部署产物二进制里含两条 probe 格式串（`strings` 证据）：
  `"SimpleBCM: probe %s req=%u cmd=0x%08x ..."` 与 `"... req=%u result=0x%08x ..."`，即至少是「修复 5（10/86 + result）」那一版的源码。
- 结论：**工作区 = e2fa373 的源码快照**（就 Docs 与 probe 串而言），diff 是有效的回滚 + 取证改动。

### 4.3 是否应该提交

**不要**在当前本地历史（`71dd72c`）之上直接 commit：

- 远程已在 `b232a43`/`e2fa373` 里包含同样内容（DEPLOY 记录 + 产物），本地再提交会产生重复提交/冲突。
- 本地 `71dd72c`（103 映射实验）只在本地存在，值得保留但不应成为主线。

建议（未执行）：

```sh
git fetch origin
git log --oneline origin/main -5           # 确认 origin/main 是否已到 b232a43/e2fa373
git tag -f local-103-experiment 71dd72c    # 保留 103 实验，避免 reset 后丢失
git diff --stat origin/main                # 期望为空（工作区与远程一致）
# 若为空：
git reset --hard origin/main               # 本地历史对齐，不产生重复提交
# 若 fetch 不可用：保持工作区不提交，等网络恢复后再对齐
```

如果必须在离线下提交，提交信息建议：`Revert 103 mapping; add GoldenGate probe logging (matches e2fa373)`，并在获得网络后 rebase/replace；**不要 push**（本任务约束）。

---

## 5. 补丁草稿与验证方法（不构建、不部署）

> 完整 diff 片段见 `Docs/PatchDraft-20261117.md`。这里给设计意图与验证步骤。

### 5.1 先决条件：确认当前加载构建

当前统一日志没有 `SimpleBCM:` 行（`--last 2m | grep -c 'SimpleBCM:'` = 0；`--last 20m` 过滤 `iouc/probe/loader/bridge` 为空），而 `DBGLOG` 在 Release 被编译掉（`Patcher.hpp:19-23`），Debug 下 `simpleBCMDebug=true`（`SimpleBCM.cpp:143-147`）。因此：

- 若 EFI 里是 `77514b72…`（e2fa373 DEBUG，见 `DEPLOY-20261116.txt` 第六次部署），probe/iouc 应该出现；现在没有 → **很可能当前挂载的是 RELEASE 构建**。
- 验证（需用户/父代理执行，本会话无权限）：挂载 EFI，`shasum -a 256 /Volumes/EFI/EFI/OC/Kexts/SimpleBCM.kext/Contents/MacOS/SimpleBCM`，与 DEPLOY 记录比对。

在拿到带 DBGLOG 的构建之前，任何"请求流"结论都只能依赖 `ioreg` 计数器与 Apple 侧日志。

### 5.2 Patch A（推荐，纯诊断，零行为变化）

1. `WirelessABI.hpp` 增加常量：

```cpp
constexpr uint32_t ScanRequest = 10;
constexpr uint32_t CurrentNetworkRequest = 103;
constexpr uint32_t UsbHostNotificationRequest = 363;
constexpr uint32_t OsFeatureFlagsRequest = 469;
constexpr uint32_t ExternalPowerStateRequest = 483;
constexpr uint32_t ProductInfoRequest = 490;
constexpr uint32_t InfraEnumeratedRequest = 512;
constexpr uint32_t OsEligibilityRequest = 575;
constexpr uint32_t LegacyHandlerTableCapacity = 417;   // 内嵌 IO80211FamilyLegacy
```

2. `Bridge.hpp` 的 `Counters` 增加（放在 `powerAvailabilityEvents` 之后，不影响任何 ABI）：
   `scanRequests`、`scanMultipleRequests`、`scanResultRequests`、`currentNetworkRequests`、`superRangeRequests`、`unsupportedRequests`（0x66）、`lastUnsupportedRequest`。

3. `UserClient.cpp` 在 `runCommand` 里计数（`done:` 之前更新 `unsupported*`），并把 probe 条件扩到
   `10/86/11/12/15/19/20/69/103/207/363/469/483/490/512/575`，日志加 `kind`（Classic/Virtual/Skywalk）。

4. `Bridge.cpp:805-832` 发布新计数器与 ABI 尺寸：
   `ScanResultSize`、`CapabilitySize`、`DriverAvailableSize`、`FilterMonitorEvents`（来自 `activeABI`，注意判空）。

**验证方法**

1. Debug 构建（CI workflow `Native Build and Publish`），产物 sha256 记录。
2. 部署到 EFI 后重启（用户操作，本会话不重启）。
3. 采集：
   ```sh
   ioreg -rn SimpleBCM -l | grep -E 'ScanRequests|ScanMultipleRequests|ScanResultRequests|CurrentNetworkRequests|SuperRangeRequests|UnsupportedRequests|LastUnsupportedRequest|ScanResultSize|CapabilitySize|DriverAvailableSize|FilterMonitorEvents'
   log show --last 5m --style compact | grep 'SimpleBCM: probe'
   ```
4. 判定：
   - `ScanRequests/ScanMultipleRequests` 是否递增 → 直接回答"扫描有没有发起"；
   - `LastUnsupportedRequest` 是否落在 `{363,469,483,490,512,575}`；
   - 若 `SuperRangeRequests` 持续增长而 `ScanRequests==0`，且每次增长后紧跟一次 `Opens` 增加（新 airportd 实例），则支持"airportd 在扫描前退出"；否则说明 Set 失败不阻塞后续流程。

### 5.3 Patch B（不推荐）：本地吞掉 27-only Set 返回成功

对 `469/483/490/512/575` 直接 `result = kIOReturnSuccess` 而不转发，可能让 airportd 继续，但这是**伪造成功、掩盖能力缺口**，违反"根因优先"约束；且 512 的语义（infra enumerated）未验证，可能造成更隐蔽的状态错乱。**不要合入**。若仅作为受控实验，必须 boot-arg 门控、DEBUG 构建、明确标注"实验"，实验后回滚。

### 5.4 Patch C（真修复方向，非小改）

- **27-only Set 转发**：把这类请求转发到 27 系统 `IO80211Family` 的 internal handler（`apple80211setOS_FEATURE_FLAGS` 等）。需要：正确的 `IO80211SkywalkInterface*` 对象、27 结构体布局、以及确认这些函数可从 kext 上下文安全调用。当前证据不足，属研究方向。
- **103 CURRENT_NETWORK**：OCLP Legacy 是 stub，无可复用实现；需要按 27 的 `apple80211_scan_result`（0x8E8）布局从驱动关联状态合成"当前 BSS"记录。字段映射未验证，不是小改。
- **扩展 legacy 分派表到 590/457**：需要改内嵌镜像代码/表，风险最高，不建议。

### 5.5 Patch D（文档更正，建议随下一次提交）

- `Docs/First-Run-macOS27.md:81`：417 归 `IO80211FamilyLegacy`，不是 AirPortBrcmNIC-Tahoe。
- 同文件"469/483/490/512/575/363 超界"：363 在表内，是 handler 返回 0x66；日志文案不能区分两者。
- 同文件"request 103 是 27 的扫描结果新请求号"：103 = CURRENT_NETWORK，OCLP Legacy 未实现，27 用 0x8E8 scan_result 承载；不要映射到 11。

---

## 6. 附录：复现命令与未验证清单

### 6.1 复现命令（均只读）

```sh
# 计数器
ioreg -rn SimpleBCM -l | grep -E 'Status|ActiveABI|LastRequest|LastResult|Scan|Availability|Command|Opens|Selector'

# 内嵌镜像日志（无需 sudo；IOLog 以 (Embedded) 出现）
log show --last 15m --style compact | grep -E 'not recognized|SimpleBCM:'

# 417 表静态证据（需要先提取 payload，见 §1.1）
nm -n .research/extract/payload0.bin | grep -E 'gGetHandlerTable|gSetHandlerTable'
llvm-objdump -d --arch=x86_64 --start-address=0x91e1a --stop-address=0x91ede .research/extract/payload0.bin

# 27 系统 IO80211Family 表容量（需要 Tools/kernel_collection.py）
python3 - <<'EOF'
import sys; sys.path.insert(0,'Tools')
from kernel_collection import KernelCollection
kc=KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
im=kc.images['com.apple.iokit.IO80211Family']
for n in ('_gGetHandlerTableLegacyCount','_gSetHandlerTableLegacyCount'):
    print(n, im.read(im.symbols[n],4).hex())
EOF
```

### 6.2 未验证清单

1. **当前加载的 kext 是否为 e2fa373 DEBUG**：无法读 EFI；统一日志无 `SimpleBCM:` 行，推断为 RELEASE。
2. **airportd SIGSEGV 的频率与栈**：`/Library/Logs/DiagnosticReports`、`~/Library/Logs/DiagnosticReports` 无 airportd 报告；`log show --last 6m` 无 `a2x-stop: program ...airportd`。父代理的崩溃归因本会话未复现。
3. **512 `setINFRA_ENUMERATED` 失败是否影响扫描发起**：无代码/日志证据。
4. **27 `apple80211EventFilter` 的尺寸/布局是否等于 0x20**：本地拦截只按 0x20 拷贝。
5. **合成 0xF8 可用性负载的字段语义**：只验证了长度与 27 `setDriverAvailable` 的 0xF8 校验一致。
6. **27 internal 表解码规则的普适性**：用 `getSCAN_RESULT`/`getCURRENT_NETWORK`/`setASSOCIATE` 校验过；legacy 表部分项的符号解析失败（未影响结论）。
7. **六个 Set 失败后 airportd 是否继续**：需要 §5.2 的 trace 计数器。

### 6.3 证据文件

- 提取的内嵌镜像：`simplebcm-r27/.research/extract/payload0.bin`、`payload1.bin`（`.research/` 被 gitignore）。
- 构建产物：`simplebcm-artifacts/artifact-e2fa373/debug/SimpleBCM-v1.2.1-DEBUG-alpha-e2fa373/EFI/OC/Kexts/SimpleBCM.kext`。
- 部署记录：`simplebcm-artifacts/DEPLOY-20261116.txt`（六次部署的 kext sha256）。
