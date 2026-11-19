# AirDrop / SDActivityAdvertiser 广告链取证报告

- 日期：2026-11-18 18:20–19:00（Asia/Shanghai）
- 主机：macOS 27.2（26B123），x86_64（i7-12700K，Mac15,14），a2x 解释执行 arm64e guest
- 只读取证；除 /tmp 下自建分析文件与日志导出外，未修改任何系统文件、未重启、未部署

---

## 0. 结论摘要（先看这里）

1. **被引用的状态块不是 AirDrop 的广告状态。** 日志里 `SDActivityAdvertiser / Advertising Enabled: NO / Should Not Advertise Requesters: {()} / … / Current Advertisement Payload: GOODBYE` 属于 **“Handoff State”** 转储（`sharingd[11302] 2026-11-18 18:20:31.930`，level `Sd`），来自 Handoff/Continuity 的 activity 广告器。AirDrop 的 BLE 广告是 **另一条**：`SDNearbyAgent → SDBLEAdvertiser → CBAdvertiser`，同一进程 18:20:31.896 已经激活并携带 AirDrop hash：
   ```
   18:20:31.896 sharingd[11302] [com.apple.bluetooth:CBAdvertiser] Activate: … adVs 3, adH1 0xAE3C, adH2 0x9961, adH3 0x5C67, adH4 0x048D
   18:20:31.900 … Update: … adFl 0x40 < TempAuthTag >, adTa <1e e9 6d>, adVs 3, adH1…adH4 …
   ```
2. **`Should Not Advertise Requesters` 不是“请求广告的客户端集合”。** 它是 ivar `_shouldNotAdvertiseRequesters`（`NSMutableSet`，class ivar 偏移 48），装的是**抑制广告的原因字符串**。空集 `{()}` 是**正常**状态（没有任何抑制原因），不是“UI 没连上/请求被丢弃”。把它当成故障指标是误读。
3. **`resumeForReason:` 在进程内没有任何调用者。** 整个 sharingd 中该 selector 只有一个 selref 槽（`0x10072a590`），且只被 SDActivityAdvertiser 的 method list 引用；`__text` 与 `__objc_stubs` 里都没有对该槽的 `adrp+ldr`/`adrp+add`，也没有对 `resumeForReason:` stub（`0x100585ce0`）的 `bl`/`b`。`stopForReason:` 同理（槽 `0x10072d120`，stub `0x100590b20`）。
4. **唯一的外部入口是 XPC 方法 `advertiseAdvertisementPayload:options:withErrorHandler:`**，协议 `SFActivityAdvertiserProtocol`（4 个方法），MachService **`com.apple.sharing.handoff.advertising`**（不是 `com.apple.sharing.airdrop.service`）。客户端实现在 Sharing.framework 的 `SFActivityAdvertiser`（字符串证据见 §2.1）。该方法的反汇编在 `0x100066150` 执行 `strb w9(=1), [self+_advertisingEnabled]`，然后 `updateAdvertiser → restart`。
5. **实测：服务可连，但没有客户端发过 advertise 请求。** 3 小时 sharingd 日志（84,130 行，安全谓词导出）中 `Request to advertise` / `Started advertising` / `resumeForReason` / `stopForReason` 均为 **0 条**；89 次 `Handoff State` 转储全部 `Advertising Enabled: NO`、requesters `{()}`、payload `GOODBYE`。期间确有客户端连入 `com.apple.sharing.handoff.advertising`（`peer[2717]`，PID 2717 = `usernotificationsd`），但从不调用 advertise 方法。→ `_advertisingEnabled=NO` 是“无人请求”的结果，不是请求被丢弃。
   *方法学警示*：`/usr/bin/log` 在本机也是 a2x guest，`eventMessage CONTAINS` 谓词会使其崩溃（rc=139）并返回 0 行假阴性；所有日志统计必须用 `process == "sharingd"` 之类安全谓词导出后本地 grep。
6. **Finder 的 `SFXPCResilientAsyncSequence FAILED` 与 advertise 链不是同一条 XPC。** 它发生在 `com.apple.sharing.airdrop.service` 上的 `SFAirDropInvocationTransfersMonitor`（`SFXPCAsyncSequence.iteratorMaker/nextMake`）。Finder 从未连接 `com.apple.sharing.handoff.advertising`（Finder 日志 0 命中）。
7. **但 Finder 的失败是真实且可定位到“连接被中断”这一层：** `sharingd[4073]` 在 18:16:59.062/59.159/59.160 已 accept 来自 Finder(9752) 的 3 条 `airdrop.service` peer 连接，随后 **18:16:59.162–163 Finder 三条连接同时收到 `XPC_ERROR_CONNECTION_INTERRUPTED`**，序列创建报 4097、重试报 4099，12 s 后 `iterationError`。daemon 进程当时未崩溃、仍在打印日志。
8. **因此本轮的“根因”判定分两层：**
   - AirDrop BLE 广告（adVs 3 + AirDrop hash）**在跑**；`SDActivityAdvertiser` 的空闲是 Handoff 子系统的正常状态，与 AirDrop 可见性无因果关系（除非另有证据表明 iPhone 侧看不到 Mac，那要查 `adFl 0x40 TempAuthTag` 与 `DiscoverableMode` 的匹配）。
   - 真正阻塞 Finder AirDrop 视图的是 `airdrop.service` 上 **NSXPC 连接被对端/本端取消**（`XPC_ERROR_CONNECTION_INTERRUPTED`），属于 a2x 下 NSXPC 生命周期/跨桥问题或 sharingd 侧连接对象生命周期问题，**尚未证明是哪一侧**（见 §5、§6）。

---

## 1. 取证基线与方法

### 1.1 二进制同一性（关键：guest 是 Apple 原件）

| 文件 | 架构 | SHA-256 |
|---|---|---|
| `/usr/local/libexec/sharingd`（当前路由，a2x host） | x86_64 + arm64e + arm64e.x1 | `c3dd316a…c358347d` |
| `/usr/local/libexec/sharingd.ship.bak` | 同上 | `05017cb2…7e9efed` |
| `/Library/NullMoth/golden-gate/orig/usr/libexec/sharingd`（IPSW 原件） | arm64e + arm64e.x1 | `f521451d…d211516e` |
| 以上三者的 **arm64e guest 切片** | — | **全部 `0208a965…4acdf447`（相同）** |
| 以上三者的 **arm64e.x1 切片** | — | **全部 `25d42ba6…b227e02`（相同）** |

结论：修复版只替换了 **x86_64 host 切片**（比 ship 大 176 KB，含 a2x 运行时/`A2X_ASYNC_NEG_AREA` 逻辑），**guest arm64e 代码是 Apple 原样**。因此对 guest 切片的静态分析等价于分析 Apple 的 sharingd 26B123 本体。

### 1.2 为什么可以静态分析 guest

`vmmap 11302` 显示 sharingd 进程映射的是 **x86_64 系统库**（`libobjc.A.dylib`、`Foundation`、`Network`、`SkyLight`…）和 `/System/Library/dyld/dyld_shared_cache_x86_64`。即 a2x 用 x86_64 host 承载 arm64e guest 代码，guest 对系统 framework 的调用经 a2x 桥接到 **本机 x86_64 framework**。所以：

- sharingd 的业务逻辑（ObjC/Swift）= guest arm64e 代码，可直接反汇编；
- Sharing.framework / Finder 的 framework 代码 = dyld shared cache 的 **x86_64** 副本（磁盘上 framework 二进制已被系统移除，只剩 Resources）。

### 1.3 工具与产物（均在 /tmp/ad）

- `lipo -thin` 切出 4 个切片；`nm/strings/otool -oV` 做初步定位；
- 自写 Mach-O 解析（`macho.py`/`dump.py`）：解析 `__objc_classlist/__objc_protolist`、relative method list、chained fixups；
- **selector 反解**：`selrefs.py` 扫描 `__DATA/__DATA_CONST` 中所有指向 `__objc_methname` 的链式指针，得到 13951 个 selref 槽；`stubs.py` 逐 4 字节解码 `__objc_stubs`，得到 5277 个 `objc_msgSend` stub → selector 映射；
- `ann.py`：对 `llvm-objdump --macho -d` 全量反汇编（1,406,803 行）做二次注解，自动解析 `adrp+add` 字符串/CFString、`bl` 目标（IMP 名或 `[objc] selector`）、ivar 偏移表；
- 运行期：`launchctl print gui/501/com.apple.sharingd`、`log show --predicate 'processID == …'`。

> 说明：本机 ObjC method list 的 `name` 字段是**自相对地指向一个 SEL 槽**（槽内存放指向 selector 字符串的链式指针），并非直接指向字符串；`types`/`imp` 则是自相对直指。按此规则 383 个类、7346 个 IMP 全部解析成功（`-[SDActivityAdvertiser resumeForReason:]` 等名称即由此得到）。

---

## 2. 任务 1：谁应该调用 `SDActivityAdvertiser resumeForReason:`？

### 2.1 SDActivityAdvertiser 的 XPC 面（实测 + 反汇编）

| 项 | 值 | 证据 |
|---|---|---|
| 类 | `SDActivityAdvertiser`（父类 `SDActivityController`） | `class_t 0x1007347d8` / `ro 0x1006fdec0` |
| 实例方法数 | 44（含 `resumeForReason:`、`stopForReason:`、`state`、`updateAdvertiser`、`advertiseAdvertisementPayload:options:withErrorHandler:`） | `baseMethods 0x100598b08` |
| 监听服务 | **`com.apple.sharing.handoff.advertising`** | `-[SDActivityAdvertiser machServiceName]` `0x10006404c`：`adrp/add` → CFString `0x1006d0e98` |
| 导出协议 | **`SFActivityAdvertiserProtocol`** | `-[SDActivityAdvertiser exportedInterface]` `0x100064058`：protoref `0x1006e2650` → protocol_t `0x10073c748`，`name` = `SFActivityAdvertiserProtocol` |
| 协议方法（4） | `loginIDWithOptions:completionHandler:`、`peerForUUID:completionHandler:`、`pairedSFPeerDevicesWithOptions:completionHandler:`、**`advertiseAdvertisementPayload:options:withErrorHandler:`**（`v40@0:8@16@24@?32`） | `__objc_protolist` `0x10073c748` / method list `0x1005adb38` |
| 回调协议 | `SFActivityAdvertiserClient`：`activityPayloadForAdvertisementPayload:command:requestedByDevice:withCompletionHandler:`、`didSendPayloadForActivityIdentifier:toDevice:error:`、`pairedDevicesChanged:` | protocol `0x10073c7a8` |
| 运行期 | 18:20:31.829 `activating connection: mach=true listener=true … name=com.apple.sharing.handoff.advertising` | sharingd[11302] 日志 |

客户端侧证据（Sharing.framework，x86_64 cache 切片 `__TEXT 0x7FF8214B1000–0x7FF821870E72`，只读抽取）：

```
0x7ff8217d89b9  "SFActivityAdvertiser"                     （类名，8 处）
0x7ff8217d8a76  "com.apple.sharing.handoff.advertising"    （客户端连接的 MachService）
0x7ff8217d8a44  "v16@?0@\"NSObject<SFActivityAdvertiserProtocol>\"8"
0x7ff821807230  "Sharing/SFActivityAdvertiser/advertiseAdvertisementPayload"   （os_log 分类）
0x7ff8218072a8  "%{public}@ dispatching request to advertise %{public}@"       （客户端发送日志）
0x7ff8217d8960  SFActivityAdvertiserOptionVersionKey / …MinorVersionKey / …FlagCopyPasteKey
```

**因此链路的“上端”是：** `SFActivityAdvertiser`（Sharing.framework 客户端实例） → NSXPC（`com.apple.sharing.handoff.advertising`，`SFActivityAdvertiserProtocol`） → sharingd `SDActivityAdvertiser`。

### 2.2 `resumeForReason:` 的真实语义与调用者

反汇编 `-[SDActivityAdvertiser resumeForReason:]`（`0x100063c58–0x100063d70`）：

```
0x100063c78  retain(reason)                       ; x2 = reason（NSString/原因）
0x100063c84  handoff_log
0x100063cac  SFCompactStringFromCollection(_shouldNotAdvertiseRequesters)   ; 打印当前集合
0x100063cc8  log "%s %@ - \"%@\""  with "-[SDActivityAdvertiser resumeForReason:]"
0x100063d1c  [_shouldNotAdvertiseRequesters containsObject:reason]          ; stub 0x100575c60
0x100063d2c  cbz → 直接返回（**原因本来不在集合里就什么都不做**）
0x100063d38  [_shouldNotAdvertiseRequesters removeObject:reason]            ; stub 0x100585080
0x100063d40  [_shouldNotAdvertiseRequesters count]                          ; stub 0x100576200
0x100063d44  cbnz → 返回（还有别的抑制原因）
0x100063d4c  [self restart]                                                 ; stub 0x100585a20
```

`-[SDActivityAdvertiser stopForReason:]`（`0x100063b4c–0x100063c58`）对称：日志 `"%s %@ + \"%@\""` → `addObject:reason`（stub `0x100571580`）→ `count` → `restart`。

**结论：这两个方法是“抑制原因集合”的维护 API**（resume = 解除某个原因；stop = 增加某个原因），**不是**“开始/停止广告”的入口；`resumeForReason:` 甚至在原因不在集合中时**完全无操作**。

**调用者搜索（穷举）：**
- selref 槽唯一：`resumeForReason:` → `0x10072a590`，`stopForReason:` → `0x10072d120`（全文件 8 字节链式指针低 36 位等于字符串偏移的仅此各一处）；
- 上述两个槽在 `__text` 中**没有任何 `adrp+ldr` / `adrp+add` 引用**（`scan2.py` 全量扫描 1.4 M 行反汇编）；
- `__objc_stubs` 中确有 `resumeForReason:`（`0x100585ce0`）和 `stopForReason:`（`0x100590b20`）的 stub，但**没有任何函数 `bl`/`b` 到它们**；
- `resumeForReason:` 也**不在** `SFActivityAdvertiserProtocol` / `SFActivityAdvertiserClient` 中，XPC 客户端无法按协议调用它。

**因此：Finder、ControlCenter、`SFActivityAdvertiserClient` 都不应该（也无法）调用 `resumeForReason:`。** 在 26B123 这一版里，它在本进程内是“有实现、无调用者”的 API（很可能是历史/内部 API，留给带特权或调试路径）。真正驱动广告的是 `advertiseAdvertisementPayload:options:withErrorHandler:`。

### 2.3 `advertiseAdvertisementPayload:options:withErrorHandler:`（`0x100065e3c–0x100066338`）关键指令

```
0x100065fc0  log "Request to advertise %{public}@ with options %@"
0x100065ffc  options[SFActivityAdvertiserOption…] / componentsSeparatedByString: / intValue   ; 解析版本
0x1000660b4  isEqual: …                                  ; 与当前 payload/options 比较
0x100066118  log "Advertisement contents does not differ from current, continuing previous advertising"
0x100066138  [self invalidateGoodbyeTimer]
0x100066150  strb w9(=1), [self + _advertisingEnabled]    ; ★ 置位
0x100066164  _currentAdvertisementPayload = copy(payload) ; ivar +96
0x10006616c  _currentAdvertisementOptions = copy(options) ; ivar +104
0x100066190  [self updateAdvertiser]
```

`-[SDActivityAdvertiser updateAdvertiser]`（`0x100065230–0x1000652a0`）：

```
_advertisementData     = [self createAdvertisingInformation]   ; ivar +80
_rawAdvertisementData  = nil                                    ; ivar +72
[self restart]                                                  ; 尾调用
```

### 2.4 实测：客户端连上了服务，但从不发 advertise 请求（这是“不广告”的直接原因）

> 方法学修正（重要）：本机 `/usr/bin/log` 也是 a2x 路由的 guest（3 切片，含 arm64e.x1），
> `--predicate 'eventMessage CONTAINS "…"'` 会让它抛 `NSInvalidArgumentException`
> （`Unable to parse the format string …`）并以 **rc=139** 崩溃，**返回 0 行是假阴性**。
> 本节所有数据改用安全谓词 `process == "sharingd"` 导出后用本地 grep 统计
> （3 小时、84,130 行，覆盖 17:26 起的全部 sharingd 实例 12961/13031/13079/4073/10686/10735/11302）。

| 检查（3 h，valid） | 结果 |
|---|---|
| `grep -c 'Request to advertise'`（daemon 端入口日志，`0x100065fc0`） | **0** |
| `grep -c 'Started advertising'`（restart 成功日志，`0x100063834`） | **0** |
| `grep -c 'resumeForReason' / 'stopForReason'`（这两个方法入口必打日志） | **0 / 0** ← 与 §2.2 静态结论一致 |
| `Handoff State` 转储次数 | 89 |
| 其中 `Advertising Enabled: YES / NO` | **0 / 89** |
| `Should Not Advertise Requesters` 取值 | 89 次全部 `{()}` |
| `Current Advertisement Payload` 取值 | 89 次全部 `GOODBYE` |
| `com.apple.sharing.handoff.advertising` 相关日志 | 42 条：listener 注册 + **客户端 peer 连接**（如 `peer[2717]`，17:26:04.493） |
| `com.apple.bluetooth:CBAdvertiser` 日志 | 166 条（AirDrop hash 广告在跑，见 §4.1） |

**修正后的结论：** 服务是活的、可连的（有 peer[2717] 这样的客户端连入，PID 2717 = `usernotificationsd`），
但这些连接**没有调用 `advertiseAdvertisementPayload:options:withErrorHandler:`**（否则一定有
`Request to advertise` 日志、`_advertisingEnabled=1`、payload 不再是 GOODBYE）。
所以 `Advertising Enabled: NO` 的直接原因是“没有客户端请求广告”，而不是“请求被丢弃/UI 没连上”。

（`resumeForReason:`/`stopForReason:` 两个方法入口都会打 `"%s %@ - \"%@\""` 日志，3 小时 0 条，
从运行期再次确认它们在本机从未被调用。）

---

## 3. 任务 2：`Should Not Advertise` / `Should Start` 的判定条件

### 3.1 字段与 ivar 对应（`-[SDActivityAdvertiser state]` = `0x100064770–0x100064adc`）

类 ivar 表在 `0x1006fdc50`（16 个 ivar），运行期用 `0x1007317a8–0x1007317e4` 的自相对偏移表取址：

| 打印字段 | ivar | 偏移 | 取值方式 |
|---|---|---|---|
| Version Byte | `_versionByte` | +8 | `ldrb` |
| Goodbye Timer Interval | `_goodbyeTimerInterval` | +32 | double |
| **Advertising Enabled** | `_advertisingEnabled` | **+56** | `ldrb` |
| **Should Start** | —（无 ivar） | — | **`bl 0x10058f980 = [self shouldStart]`**（`SDActivityController`，`0x10003ca14`） |
| **Should Not Advertise Requesters** | `_shouldNotAdvertiseRequesters` | **+48** | `SFCompactStringFromCollection` |
| **Is Advertising** | `_isAdvertising` | **+57** | `ldrb` |
| Has Power Assertion | `_powerAssertionID` | +88 | int |
| Current Advertisement Payload | `_currentAdvertisementPayload` | +96 | object |
| Current Advertisement Options | `_currentAdvertisementOptions` | +104 | object |

> 该 dump 在 `log show` 中以 `Sd`（state dump）级别、标题 **“Handoff State”** 出现在 18:20:31.930，紧接 `SDActivityScanner`、`SDActivityEncryptionManager` 两段——再次说明它是 Handoff 子系统状态，不是 AirDrop 广告状态。

### 3.2 真正的判定：`-[SDActivityAdvertiser restart]`（`0x1000636b0–0x100063abc`）6 道门

`-[SDActivityAdvertiser start]`（`0x1000636ac`）在本版**是空方法（仅 `ret`）**，真正干活的是 `restart`；`restart` 依次检查：

| # | 地址 | 条件 | 不满足时 |
|---|---|---|---|
| 1 | `0x100063700` | **`_advertisingEnabled == 1`**（+56） | → `0x100063888` 停止/保持 GOODBYE 分支 |
| 2 | `0x100063714` | `[_monitor currentConsoleUser] != nil` | 同上 |
| 3 | `0x10006372c` | **`[_continuity state] == 3`**（IDSContinuity） | 同上 |
| 4 | `0x100063748` | **`[_shouldNotAdvertiseRequesters count] == 0`** | 同上 |
| 5 | `0x100063754` | **`[self shouldStart] != 0`**（`SDActivityController`） | 同上 |
| — | `0x10006376c` | 惰性构造 `_rawAdvertisementData = [self encryptedAdvertisingInformation]` | — |
| — | `0x10006378c` | `_currentAdvertisementPayload == nil` → `[self startGoodbyeTimer]` | — |
| — | `0x10006379c` | `_advertisingTransaction = os_transaction_create("SDActivityAdvertiser")` | — |
| — | `0x100063878` | **`[_continuity startAdvertisingOfType:0 withData:_rawAdvertisementData withOptions:nil]`**（stub `0x1005901a0`） | — |

成功后日志：`"Started advertising %@ as %@ with options %@"`（`0x100063834` → `0x10063eaab`）。

`restart` 的调用者（stub `0x100585a20` 的 `bl` 全量）：`-[SDActivityAdvertiser stop]`、`stopForReason:`、`resumeForReason:`、`continuityDidUpdateState:`、`continuity:didStopAdvertisingOfType:withError:`、基类 `-[SDActivityController service:devicesChanged:]`。也就是说，广告状态会在 Continuity 状态变化 / 设备变化 / 抑制原因变化时**重新求值**，而不是由某个客户端一次性打开。

`-[SDActivityController shouldStart]`（`0x10003ca14`）的 4 个条件（selector 已反解）：

```
[SDStatusMonitor sharedMonitor]                      (stub 0x10058f500)
  └ isSharingServicesAllowed == 0  → log "Handoff is currently disabled on this device due to assessment mode being active" → NO
  └ deviceWasUnlockedOnce  == 0    → NO
  └ deviceUIUnlocked       == 0    → NO
  └ alwaysSendPayload      != 0    → log "Real Handoff is disabled since alwaysSendPayload is enabled" → NO
  └ 否则 YES
```

**回答“为何 Requesters 是空集”：**
- 不存在“requesters（请求广告的客户端）”集合；`_shouldNotAdvertiseRequesters` 是**抑制原因**集合，空集 = 没有任何抑制原因 = **健康**。
- “Advertising Enabled: NO”的直接原因是**没有客户端调用 `advertiseAdvertisementPayload:options:withErrorHandler:`**（§2.4 的 0 命中证据），所以 `_advertisingEnabled` 保持 init 时的 0。
- 即使有客户端调用，还要同时满足 §3.2 的 2–5 门（console user、`IDSContinuity.state==3`、抑制集合为空、Handoff `shouldStart`）。当前会话 `IDS: IsSignedIn: no`（18:20:31.846 日志），因此**即使客户端请求，Handoff 广告器也很可能停在门 3/5**。这与 AirDrop 的 BLE 广告无关（见 §4.1）。

---

## 4. 任务 3：Finder 的 `SFXPCResilientAsyncSequence` 失败与 advertise 是否同一条 XPC？

### 4.1 结论：不是同一条

| | Handoff 广告链（本题要查的） | Finder AirDrop 视图失败的链 |
|---|---|---|
| MachService | `com.apple.sharing.handoff.advertising` | **`com.apple.sharing.airdrop.service`** |
| 协议/接口 | `SFActivityAdvertiserProtocol` | `SFAirDropInvocationTransfersMonitor` / `SFXPCAsyncSequence.iteratorMaker/nextMake` |
| 触发者 | `SFActivityAdvertiser`（Sharing.framework 客户端） | `SFAirDropClient.registerTransfersMonitor` → `SFXPCResilientAsyncSequence` |
| 失败信息 | `Request to advertise` / gate 日志（本机 8h 内 0 条） | `XPCResilientAsyncSequence[%s] FAILED. Unable to recreate sequence. Throwing iterationError` |
| 本机实测 | 无人连接 | 3 条连接被中断（见 §4.2） |

`XPCResilientAsyncSequence[%s] …` 格式串位于 Sharing.framework `__oslogstring 0x7ff821810d40` 起（`XPCResilientAsyncSequence[%s] FAILED. Failed to create initial sequence.  {error: %@}` 等 5 条），是 `SFXPCAsyncSequence` 的通用日志，与 advertiser 无关。

### 4.2 Finder 侧实测时间线（Finder = a2x host PID 9752，AirDrop 视图 18:16:58.879 打开）

```
18:16:58.879  Finder  OpenSync: Node '<FIDSNode_AirDrop … 隔空投送 …>'
18:16:58.957  Finder  activating xpc connection → com.apple.sharing.airdrop.service  (0x7fc741719d90)
18:16:58.959  Finder  activating xpc connection → com.apple.sharing.airdrop.service  (0x7fc723810200)
18:16:59.059  Finder  activating xpc connection → com.apple.sharing.airdrop.service  (0x7fc741761150)
18:16:59.061  Finder  syncXPC [SFAirDropInvocations.SharingName] START/END  (走 com.apple.sharingd)
18:16:59.157  Finder  [DeviceDiscoveryUI:AirDropUI] Started tracking transfers
18:16:59.157  Finder  asyncXPC [SFAirDropInvocations.BecomeTransferPresenter]
18:16:59.159  Finder  asyncXPC [SFAirDropInvocationTransfersMonitor]
18:16:59.161  Finder  XPCResilientAsyncSequence[<private>] START. Created initial sequence.
18:16:59.161  Finder  syncXPC [SFXPCAsyncSequence.iteratorMaker]
18:16:59.162  Finder  XPCResilientAsyncSequence[<private>] FAILED. Failed to create initial sequence. {4097}
18:16:59.163  Finder  [0x7fc723810200] XPC_ERROR_CONNECTION_INTERRUPTED / [0x7fc741761150] 同
18:16:59.162  Finder  [0x7fc741719d90] XPC_ERROR_CONNECTION_INTERRUPTED
18:16:59.165  Finder  RETRY. Recreating sequence {4099}
18:17:11.461  Finder  FAILED. Unable to recreate sequence. Throwing iterationError {4097, 4099}
             （daemon 侧：）
18:16:59.062  sharingd[4073] activating peer connection name=com.apple.sharing.airdrop.service.peer[9752].0x19e964af0
18:16:59.159  sharingd[4073] … peer[9752].0x1a3427130
18:16:59.160  sharingd[4073] … peer[9752].0x1a3427ff0
```

**关键点：**
- XPC 通道**建立成功**（daemon 侧有 3 条 accept 记录），随后约 **100 ms 内三条连接全部 `INTERRUPTED`**；daemon 未崩溃（18:16:59.125–59.160 持续打日志），因此不是“服务没起来”。
- `XPC_ERROR_CONNECTION_INTERRUPTED` 表示**连接被某一端 cancel/对端连接对象销毁**；`Re-initialization successful` 是 libxpc 的重连日志。
- Finder 同窗口还有 `invalidated after the last release of the connection object`（例如 18:16:58.864 CursorUIViewService、18:16:58.980 tccd、18:16:59.153 主动 `xpc_connection_cancel()`），说明该进程确实存在“连接对象被过早释放”的现象；但**目前无法证明这 3 条 airdrop 连接也是同一原因**（见 §6）。
- 另有一个 a2x 相关异常值得记录：sharingd 的 `[com.apple.sharing:AirDropNW.Discovery*]` 在同一时段刷出大量 `<compose failure [UUID]>>`，即 os_log 变参/UUID 结构在 a2x 桥下格式化成空——属“日志变参桥接缺陷”（与 patch 0019 同类），**不影响广告逻辑**，但会掩盖真实诊断信息。

### 4.3 链路图

```
【链 A：Handoff / activity 广告，本报告主角】
 Finder? / 任意 SFActivityAdvertiser 客户端（Sharing.framework）
   └─ NSXPC  mach service = com.apple.sharing.handoff.advertising
        interface = SFActivityAdvertiserProtocol（4 方法）
        call     = advertiseAdvertisementPayload:options:withErrorHandler:
   └─ sharingd(a2x host, guest arm64e)  SDActivityAdvertiser
        ├ connectionEstablished: / shouldAcceptNewConnection:（entitlement 见下）
        ├ [advertise…] → _advertisingEnabled=1（0x100066150）, payload/options 入 ivar
        ├ updateAdvertiser（0x100065230）→ createAdvertisingInformation → restart
        └ restart（0x1000636b0）门 1..5 → [_continuity startAdvertisingOfType:0 withData:rawOptions:]
             └─ IDSContinuity ──(XPC com.apple.identityservicesd? / IDS daemon)──> CBAdvertiser(BLE)
   旁路/抑制：_shouldNotAdvertiseRequesters（resume/stopForReason: 维护，当前无调用者）

【链 B：AirDrop BLE 广告（真正让 iPhone 看到 Mac 的那条）】
 DiscoverableMode(pref, Everyone) ──> SDNearbyAgent
   ├ AirDropHashDB（~/Library/Sharing/AirDropHashDB）
   ├ _bleNearbyInfoAdvertiserEnsureStarted / NearbyInfo 广告数据
   └ SDBLEAdvertiser → CBAdvertiser  Activate/Update: adVs 3, adH1..adH4 = AirDrop hash,
                                      adFl 0x40 <TempAuthTag>, adTa <…>   ← 18:20:31.896 已实测
   （BoostNearbyInfo: no→yes，18:20:31.951）

【链 C：Finder AirDrop 视图失败的那条（与 A、B 都不同）】
 Finder（a2x host，guest Finder arm64e）
   └ SFAirDropClient → NSXPC com.apple.sharing.airdrop.service
        ├ SFAirDropInvocations: SharingName / BecomeTransferPresenter（成功）
        └ registerTransfersMonitor → SFXPCResilientAsyncSequence
              └ SFXPCAsyncSequence.iteratorMaker / nextMake  ← 4097/4099，连接被 INTERRUPTED
   └ sharingd SDAirDropController/…（daemon 侧 accept 后连接被取消，原因未定）
```

> 注：Finder 的 AirDrop 视图**没有**发起 `advertiseAdvertisementPayload:`（日志 0 命中），因此不能把链 A 的空闲归因于 Finder；反过来，链 A 的空闲也不影响链 B。

---

## 5. 任务 4：可验证的修复 / 绕过（按层级）

> 约束不变：不改 /System、/Library、EFI；不重启；不部署。以下每项都给出**只读或 /tmp 实验**的验证方式与判据。

### L0（已成立，只需要纠正认知）

- **AirDrop BLE 广告已在工作**：判据 `log show --last 10m --predicate 'processID == <sharingd pid>'` 中 `CBAdvertiser … adVs 3 … adH1..adH4` 的 `Activate/Update` 出现且 `adFl` 含 `TempAuthTag`。
- **`SDActivityAdvertiser` 的 GOODBYE 不是 AirDrop 故障指标**：它只在 `advertiseAdvertisementPayload:` 被调用后才会变；本机 8h 无任何调用。
- 验证命令（只读）：
  ```sh
  PID=$(launchctl print gui/501/com.apple.sharingd | awk '/pid =/{print $3}')
  log show --last 10m --style compact --predicate "processID == $PID" | grep -E 'CBAdvertiser|Handoff State|Request to advertise'
  ```

### L1 a2x 的 XPC/NSXPC 桥接（针对链 C，最可能出真根因的一层）

- **假设 H1**：a2x 桥接在 `NSXPCConnection` / 导出对象（`SDAirDropController` 侧）的 retain/release 或 block 回调上没有保持对象生命周期，导致 accept 后的连接被 cancel → 客户端看到 `INTERRUPTED`。
- **只读证据已具备**：daemon accept 记录（18:16:59.062/159/160）+ 客户端 100 ms 内 `INTERRUPTED`（18:16:59.162/163）+ daemon 未崩溃。
- **可验证实验 E1（不改系统）**：在 /tmp 编译一个**原生 x86_64** 小型 NSXPC 客户端（`dlopen` Sharing.framework，`NSClassFromString(@"SFAirDropClient")` 或直接用 `NSXPCConnection` + `objc_getProtocol("SFAirDrop…")`）复现 `registerTransfersMonitor`：
  - 若**原生客户端也被 INTERRUPTED** → 问题在 sharingd(a2x) 侧，H1 成立概率高；
  - 若只有 a2x Finder 被 INTERRUPTED → 问题在 Finder 宿主/桥接的客户端侧。
  - 判据：客户端错误码（4097/4099）+ daemon 日志是否出现 peer accept 后立即断链。
- **可验证实验 E2**：对 a2x 增加 `xpc_connection_cancel` 调用点日志（host 层，workspace 内可编译的 a2x 运行时；不改系统服务），记录 cancel 的调用栈/线程，确认是 libxpc 自动回收还是显式 cancel。
- **成功判据**：同一客户端连续 10 次 `registerTransfersMonitor` 均能收到 `Created initial sequence` 且 60 s 内无 `INTERRUPTED`。

### L2 sharingd 的部署方式

- 现状：`Program=/usr/local/libexec/sharingd`（a2x host）+ `A2X_ASYNC_NEG_AREA=16`；IPSW 原件只有 arm64e，本机 x86_64 **没有原生可执行的 sharingd**，所以“换回系统原件”在这台机器上不可行（原件无法在 Intel 上直接执行）。
- **可验证实验 E3**：在同一 a2x host 上仅切换 `A2X_ASYNC_NEG_AREA`（0/8/16/-8）与 `A2X_*` 调试开关，观察链 C 的 `INTERRUPTED` 是否消失；这只改 LaunchAgent 的 env（用户级），**不触碰系统文件**，但需用户批准后由主代理执行。判据同 E1。
- **可验证实验 E4（只读）**：`lsof -p <sharingd pid>` + `vmmap` 确认 a2x host 是否重复映射/提前 unmap 了 `dyld_shared_cache_x86_64` 中的 `Sharing`/`Foundation` 段（现有 vmmap 正常）。
- 边界：若根因在 a2x 的 `NSXPCListener`/导出对象桥接，**sharingd 部署层无法修复**，只能回到 L1。

### L3 Finder 的 dev 宿主配置

- 现状：`/Users/geek/Library/LaunchAgents/com.apple.Finder.plist` → `a2xhost-finder-source-v5`，`CFProcessPath=/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder`，`A2X_GUEST=/Library/NullMoth/golden-gate/orig/…/Finder`。
- **可验证实验 E5**：用同一 a2x devkit 的**另一份 Finder host**（例如 finder-malloc-r27 里其它 build）或不同 patch 级别启动 Finder，重复 `open` AirDrop 视图，比较链 C 是否仍 `INTERRUPTED`（判据：Finder 日志的 4097/4099 与 daemon accept 记录）。这只是切换用户级 LaunchAgent 的 `program`，不改系统文件；需要用户批准。
- **不可做**：不要为了“让 AirDrop 广告出现”去改 `com.apple.sharingd.plist` 的 `MachServices` 或伪造 entitlement —— 那既违反系统文件约束，也不会改变 §3.2 的门。

### L4 只能报告边界

- 若 E1 证明**原生客户端也断链**，则根因在 sharingd(a2x) 的 NSXPC 导出对象生命周期，属 a2x 桥接缺陷；按工作区约束应交付 a2x 侧补丁/复现器，而不是改系统。
- 若 E1 证明只有 a2x Finder 断链，则根因在 Finder 宿主桥接（客户端侧 `NSXPCConnection` 生命周期/Swift async 续体），同样只能在 a2x 层修。
- AirDrop 的“iPhone 能否看到 Mac”还需端到端验证（iPhone 侧是否出现该 Mac、`adFl 0x40 TempAuthTag` 是否匹配 Everyone 模式）；本轮未做设备侧验证。

---

## 6. 未验证项（明确缺口）

1. **谁在何时 cancel 了 Finder 的 3 条 airdrop 连接**：客户端主动 cancel（`xpc_connection_cancel` 日志在 Finder 侧只出现在别的连接）、还是 daemon 侧对象释放导致，未证明。
2. **a2x 是否错误处理 NSXPCConnection/导出对象生命周期**：仅有时序相关性，无调用栈证据。
3. **`SFActivityAdvertiser` 由哪个 UI 调用**：本轮只证明 Finder 没调；ControlCenter / SharingUI / AirDropUI 是否在别的路径调用未验证（需要它们的日志或对 Sharing.framework 上层调用者的进一步反汇编）。
4. **`IDSContinuity.state == 3` 的确切枚举含义**：按 `state` 返回 3 反推为“active”，未在 IDS 头文件/日志中确认。
5. **`startAdvertisingOfType:` 的类型参数 0 的含义**（`x2=0`）：未确认是 activity 还是 AirDrop 专用类型。
6. **entitlement 门**：`com.apple.private.sharing.activity-advertiser` 字符串存在，但 `shouldAcceptNewConnection:` 是否校验未反汇编确认；因此“未签名的 /tmp 客户端能否连上”未验证（E1 会顺带回答）。
7. **AirDrop 端到端**：iPhone 侧是否看到 Mac、`adFl 0x40 <TempAuthTag>` 是否符合 Everyone 模式、以及 `DiscoverableMode=Everyone` 与 AirDropHashDB 的对应，未做设备验证。
8. **`<compose failure [UUID]>`**：只确认为 a2x 变参/os_log 桥接的格式化失败，是否影响 `AirDropNW.Discovery` 的业务数据（UUID 参与 hash/去重？）未验证。
9. **`peer[2717]`（`usernotificationsd`）连入 `com.apple.sharing.handoff.advertising` 的目的与调用序列**未确认：它没有触发 `Request to advertise`，可能只调用 `loginIDWithOptions:`/`pairedSFPeerDevicesWithOptions:` 或仅注册回调。
10. **历史日志结论需复核**：本机 `/usr/bin/log` 是 a2x guest，`eventMessage CONTAINS` 谓词会崩溃（rc=139）并输出 0 行；任何据此得出的“某事件从未发生”的旧结论都应改用 `process == "…"` 导出 + 本地 grep 重做。
11. **`resumeForReason:` 是否真为死代码**：结论是“本进程内无调用者”，但不排除有调试/私有 XPC 客户端或未来系统组件通过非协议路径调用（无证据）。

---

## 7. 复现命令（只读）

```sh
# 1) 部署与 PID
launchctl print gui/501/com.apple.sharingd | sed -n '1,40p'

# 2) Handoff 广告器状态转储（“Handoff State”，非 AirDrop）
PID=$(launchctl print gui/501/com.apple.sharingd | awk '/pid =/{print $3}')
log show --last 30m --style compact --predicate "processID == $PID" \
  | grep -n -A10 'Handoff State'

# 3) AirDrop BLE 广告（真正在跑的）
log show --last 30m --style compact --predicate "processID == $PID" \
  | grep -E 'CBAdvertiser|BoostNearbyInfo|NearbyInfo found'

# 4) 是否有人请求 Handoff 广告（注意：eventMessage CONTAINS 会让 a2x 版 log 崩溃！）
log show --last 3h --style compact --predicate 'process == "sharingd"' > /tmp/sd3h.log
grep -c -E 'Request to advertise|Started advertising' /tmp/sd3h.log      # 预期 0
grep -c -E 'resumeForReason|stopForReason' /tmp/sd3h.log                # 预期 0
grep 'Should Not Advertise Requesters' /tmp/sd3h.log | sort | uniq -c   # 预期全部 {()}

# 5) Finder AirDrop 视图失败链
FPID=$(launchctl print gui/501/com.apple.Finder | awk '/pid =/{print $3}')
log show --last 90m --style compact --predicate "processID == $FPID" \
  | grep -E 'airdrop.service|XPCResilientAsyncSequence|XPC_ERROR_CONNECTION_INTERRUPTED|TransfersMonitor'

# 6) daemon 侧 accept 记录（对照 5 的时间）
log show --start '<t0>' --end '<t1>' --style compact --predicate 'processID == <old sharingd pid>' \
  | grep 'airdrop.service.peer'

# 7) 静态：方法/协议/字符串（本报告用到的）
lipo -thin arm64e /usr/local/libexec/sharingd -output /tmp/ad/sharingd.arm64e
shasum -a 256 /tmp/ad/sharingd.arm64e    # 期望 0208a965…4acdf447
strings -a -t x /tmp/ad/sharingd.arm64e | grep -E 'Should Not Advertise|resumeForReason|handoff.advertising'
```

---

## 8. 附：关键地址速查

| 符号 | guest 地址 |
|---|---|
| `-[SDActivityAdvertiser resumeForReason:]` | `0x100063c58` |
| `-[SDActivityAdvertiser stopForReason:]` | `0x100063b4c` |
| `-[SDActivityAdvertiser start]`（**空方法**，仅 `ret`） | `0x1000636ac` |
| `-[SDActivityAdvertiser restart]` | `0x1000636b0` |
| `-[SDActivityAdvertiser stop]` | `0x100063abc` |
| `-[SDActivityAdvertiser state]` | `0x100064770` |
| `-[SDActivityAdvertiser machServiceName]` | `0x10006404c` |
| `-[SDActivityAdvertiser exportedInterface]` | `0x100064058` |
| `-[SDActivityAdvertiser updateAdvertiser]` | `0x100065230` |
| `-[SDActivityAdvertiser createAdvertisingInformation]` | `0x1000652a0` |
| `-[SDActivityAdvertiser advertiseAdvertisementPayload:options:withErrorHandler:]` | `0x100065e3c` |
| `-[SDActivityAdvertiser isAdvertising]` | `0x1000668d4` |
| `-[SDActivityController shouldStart]` | `0x10003ca14` |
| selref `resumeForReason:` / `stopForReason:` | `0x10072a590` / `0x10072d120` |
| objc stub `resumeForReason:` / `stopForReason:` / `restart` / `shouldStart` | `0x100585ce0` / `0x100590b20` / `0x100585a20` / `0x10058f980` |
| protocol `SFActivityAdvertiserProtocol` / `…Client` | `0x10073c748` / `0x10073c7a8` |
| Sharing.framework `__TEXT`（x86_64 cache 切片） | `0x7FF8214B1000–0x7FF821870E72` |
