# 设置 App（Wi-Fi.appex / WiFiSettingsKit）关联与状态逆向：XPC 路径、「隐藏的网络」判据、双 UI 不一致与分层修复

日期：2026-11-18（Asia/Shanghai）
系统：macOS 27.2（26B123 / Darwin 27.2.0，x86_64，Mac15,14）
取证对象与地址基准：

| 对象 | 路径 / 基准 | 说明 |
| --- | --- | --- |
| 设置扩展 | `/System/Library/ExtensionKit/Extensions/Wi-Fi.appex/Contents/MacOS/Wi-Fi` | 3 切片（x86_64 / arm64e / arm64e.x1），本次实测**未被 a2x route** |
| 设置 UI 实现 | `/System/Library/PrivateFrameworks/WiFiSettingsKit.framework/Versions/A/WiFiSettingsKit` | 真逻辑在这里（appex 只是 SwiftUI 外壳）；`__TEXT` vmaddr `0x7FFE06E26000`，取自 `dyld_shared_cache_x86_64.06` |
| CoreWiFi | `/System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi` | 版本 1042.8.0；`__TEXT` vmaddr `0x7FF81EE32000`，主缓存 |
| airportd | `/usr/libexec/airportd` | **Identifier=`.a2xhost-mac`、`Signature=adhoc`** → 被 a2x route |
| ControlCenter / WiFiAgent | `.../ControlCenter.app/...`、`.../WiFiAgent.app/...` | 同样 `Identifier=.a2xhost-mac` → 被 route |

> 取证边界：无 `sudo`（`sudo -n` 需密码）；未重启；未改动 `/System`、`/Library`、EFI；所有实验产物在 `/tmp/rv-wifi/`。
> 日志窗口：`--last 3h`（01:47–04:47），Wi-FiManager 子系统 **620,770** 行，securityd 子系统 **440,836** 行，appex 进程日志 **5,709** 行。
> 全文用「401-5G」指用户那个 SSID；请勿与上一篇文档里「401 个网络」的计数混淆。

---

## 0. 结论摘要（先看这里）

1. **前提要修正**：`Wi-Fi.appex` **没有**被 a2x route —— 磁盘上 `Identifier=com.apple.wifi-settings-extension`、Apple 签名（CDHash `5d4896f2…`），`vmmap -summary 3188` 显示 `Code Type: X86-64`、0 个 a2x 镜像，加载的是缓存里的 x86_64 CoreWiFi/WiFiSettingsKit。真正跑在 a2x 上的是 `airportd`、`ControlCenter`、`WiFiAgent`（`codesign` 均为 `.a2xhost-mac` + adhoc）。
2. **设置 App 的关联走 `[ASSOC]`**，service = `com.apple.private.corewifi.internal-xpc`，落到 airportd 的
   `-[CWXPCSubsystem associateToWiFiNetworkUsingSystemKeychain:tetherDevice:interfaceName:authorization:connection:isAutoJoin:possiblyHidden:error:]`。
   **ControlCenter 从不发 `[ASSOC]`**（3 小时 0 次），它只轮询 `[GET SSID]` / `[GET BSSID]`。
3. **「未能加入」的根因不在 Wi-Fi 协议栈，而在 a2x 改写了 airportd 的代码身份**：AirPort 钥匙串条目的 ACL 要求
   `identifier "com.apple.airport.airportd" and anchor apple`；route 之后 airportd 变成 adhoc + `identifier ".a2xhost-mac"`，
   securityd 判定 `code requirement check failed (-67050), client is not Apple-signed` → 弹不出/批不了钥匙串授权
   （`MacOS error: -25337`）→ `ObjectAcl REJECTS access` → `CWKeychainFindWiFiPassword()` 返回 **-25308（errSecInteractionNotAllowed）** → ASSOC 直接失败。
   3 小时内 airportd 因此被拒 **155 次**。
4. **「报未能加入却显示已连接」是设置 App 自己的乐观更新**：收到 -25308 后它只打一条
   `Received unknown error with code: -25308, prompting diagnostics run`，**41 ms 后仍然** `handle association result` →
   `Setting current network cell for <…>` → `Setting current network cell rssi … : -21`，把该行标成当前网络（即「已连接」）。
   时间线：`04:47:09.085`(错误) → `.126`(handle) → `.190`/`.236`(设 cell + RSSI)。
5. **「隐藏的网络」不是 UI 从扫描结果现算的**：`CWFScanResult` 运行时枚举出 **147 个方法，没有任何 hidden 访问器**；
   隐藏态来自 `CWFNetworkProfile.hiddenState`（`q16@0:8`，另有 `wasHiddenBefore` / `wasRecentlyHidden`），
   由 airportd 在关联时按 `possiblyHidden` 盖进已知网络档案：
   `Info: Default <redacted> as a hidden network based on being flagged as 'possiblyHidden'`（`04:07:15.191`）。
6. **判据的源头（驱动侧）已由同日另一篇文档定位**：`apple80211_scan_result +0x88` 的 **bit1(0x02)** = hidden，
   `IO80211BSSBeacon::toScanResult` 用 `orb $0x2,0x88(%rbx)` 写入。该字节**在 0x48C 前缀内，不在扩展区**；
   legacy 0x48C ABI 从不定义它（驱动 `scanConvertResult` 全程不写 0x88，payload0 `getScanResult` 原样透传，
   输出缓冲还先用 `0xAA` 毒化，而 `0xAA & 0x02 != 0`）。详见 [Reverse-ScanResult-Layout-20261118.md](Reverse-ScanResult-Layout-20261118.md)。
   **本文补上它缺的用户态一环**（该文 §5 缺口 2）：27 用户态没有任何「scanResult.isHidden」API，
   隐藏语义只经 `CWFNetworkProfile.hiddenState` 体现 → 一旦盖上就**持久**，所以重启/重扫都不会自动恢复。
7. **两套 UI 不一致是因为状态源不同**：设置 App 3 小时里 **`GET SSID` 调用次数 = 0**，只靠事件 + `[GET CURR SCAN RESULT]`
   （**7304/7304 全部 err=0，从不失败**，不能当连通性判据）；ControlCenter 轮询 `[GET SSID]`（18007 次 err=0 / 15496 次 -3903）
   和 `[GET BSSID]`（1986 / 595），-3903 就是「当前无 SSID」。所以**连接正常时 ControlCenter 可能错、断连时设置 App 会一直错**，
   谁对取决于哪一侧的缓存/事件先更新。
8. **驱动侧另有一个独立缺陷**：`currentNetworkValid` 只在 `UserClient.cpp:485` 被置 1，**全仓库没有任何清零路径**
   （无 link-down/disassoc 处理）；`request 103` 的 fallback 会把这份 0x48C 扫描记录副本 + 0x45C 零尾一直当「当前网络」返回。
   它会让所有基于 103 的「当前网络」读方拿到陈旧值。
9. **修复分层**：根因在 **L1（a2x route 破坏代码身份）**，正解是让 airportd 保持 Apple 签名（bundle-as-guest / 原生宿主），
   而不是给钥匙串 ACL 开后门；驱动侧（L0）能修的是 `+0x88` 的 hidden 位与 103 latch；
   设置 App 的乐观更新、airportd 的 `possiblyHidden` 持久化、SharingServices 回退失败属于 Apple 逻辑，**只能报告边界**。

---

## 1. 关键前提修正：谁真的跑在 a2x 上

| 进程 | 磁盘签名 Identifier | 运行架构 | 是否 a2x |
| --- | --- | --- | --- |
| `Wi-Fi.appex` | `com.apple.wifi-settings-extension`（Apple，CDHash `5d4896f20b8a7bfbb376827a7abb53dfad42f67e`） | `X86-64` | **否** |
| `airportd` | `.a2xhost-mac`，`flags=0x2(adhoc)`，`Signature=adhoc` | x86_64（a2xhost 解释 arm64e） | **是** |
| `ControlCenter` | `.a2xhost-mac` | X86-64 | 是 |
| `WiFiAgent` | `.a2xhost-mac` | X86-64 | 是 |

验证命令与结果：

```
$ vmmap -summary 3188 | grep 'Code Type'      → Code Type: X86-64
$ vmmap 3188 | grep -ci a2x                   → 0
$ codesign -dv --verbose=4 /usr/libexec/airportd
   Identifier=.a2xhost-mac … flags=0x2(adhoc) … Signature=adhoc … TeamIdentifier=not set
```

**这直接改变了 Q3 的因果假设**：两套 UI 的差异不是「原生 vs 转译」造成的渲染差异，而是
「原生 Apple 客户端 + 被转译且**签名被换掉**的守护进程」这一组合造成的**能力缺失**。

---

## 2. Q1：设置 App 的关联代码路径

### 2.1 调用链（自 UI 向下）

```
SwiftUI 行 (WiFiSettingsKit.rawResult/cwfScanResult)
  → WiFiSettingsKit.WiFiSettingsAssociator            (导出符号 0x00068710 / MD 0x3D4B50B0)
  → WiFiSettingsKit.WiFiSettingsAssociationCoordinator(0x00020440，Observation)
  → CWFAssocParameters { password, scanResult, forceBSSID, rememberUponSuccessfulAssociation }
  → -[CWFInterface …]  (appex 导入 _OBJC_CLASS_$_CWFInterface，来自 CoreWiFi)
  → XPC  [ASSOC]  service=com.apple.private.corewifi.internal-xpc
  → airportd -[CWXPCSubsystem associateToWiFiNetworkUsingSystemKeychain:tetherDevice:
              interfaceName:authorization:connection:isAutoJoin:possiblyHidden:error:]
```

appex 的 entitlements 只声明了 `com.apple.private.corewifi.internal` 与
`mach-lookup: com.apple.private.corewifi.internal-xpc`（实测日志一致），所以它的 `[ASSOC]` **只能**走 internal 端点。
另有一路 `corewlan-xpc`（公开 CoreWLAN 端点，不需要私有 entitlement，appex 导入了 `_OBJC_CLASS_$_CWWiFiClient`），
这也解释了 ControlCenter 为什么 5,082 次都在 `corewlan-xpc` 上——它用的是公开 CoreWLAN，不是私有 CoreWiFi。
对照：`ControlCenter` 的 `com.apple.private.corewifi` + lookup `com.apple.private.corewifi-xpc`，
`WiFiAgent` 另有 `.user-agent` / `.keychain`。

### 2.2 三个客户端的请求画像（3 小时实测，`subsystem == "com.apple.WiFiManager"`）

| 请求 | 设置 App (`proc=Wi-Fi`) | ControlCenter | WiFiAgent |
| --- | --- | --- | --- |
| `[ASSOC]` | **11** | **0** | 15 |
| `[GET SSID]` | **0** | 912 | 多 |
| `[GET BSSID]` | 0 | 270 | 多 |
| `[GET CURR SCAN RESULT]` | 1213 | 753 | — |
| `[GET KNOWN NETWORK MATCHING SCAN RESULT]` | **1215** | 0 | — |
| `[SCAN]` | 153 | 0 | — |
| `[GET RSSI]/[GET TX RATE]/[GET PHY MODE]…` | 0 | 各 ~251 | — |

端点分布：`corewlan-xpc` 253,555；`private.corewifi-xpc` 21,212；`private.corewifi.internal-xpc` 16,673；`user-agent-xpc` 948。

> **同名请求、不同结果**：设置 App 与 WiFiAgent 发的是同一个 `[ASSOC]`、同一个 internal 端点，
> 但 3 小时内设置 App **9 败 2 成**，WiFiAgent **15 次全成**。差异不在请求类型，而在**调用方身份/凭据来源**。

### 2.3 失败点：一行日志定死

```
03:50:49.945 [corewifi] BEGIN REQ [ASSOC] (pid=5852 proc=Wi-Fi bundleID=com.apple.wifi-settings-extension
             codesignID=com.apple.wifi-settings-extension service=com.apple.private.corewifi.internal-xpc …)
03:50:49.954 Info: <airport[274]> -[CWXPCSubsystem associateToWiFiNetworkUsingSystemKeychain:…]:
             CWKeychainFindWiFiPassword() failed with error code -25308
03:50:49.957 [corewifi] END REQ [ASSOC] took 0.012225249s … err=-25308
```

- 失败耗时 8–21 ms：**不是关联超时**，是关联前就被拒。
- `-25308` = `errSecInteractionNotAllowed`（`MacOSX27.sdk/…/SecBase.h:361`「User interaction is not allowed」）。
- 走 `UsingSystemKeychain` 变体，是因为客户端**没带密码**；appex 自己的日志写着
  `04:45:37.475 no password provided for '<private>'`。

### 2.4 为什么拿不到密码：securityd 拒绝，根因是 a2x 的签名替换

同一时刻（`04:47:09`，最后一次失败）securityd 的日志：

```
04:47:09.077 [com.apple.securityd:clientid] code requirement check failed (-67050), client is not Apple-signed
04:47:09.077 [com.apple.securityd:kcacl]    Keychain query for process 217 (UID 0)
04:47:09.077 [com.apple.securityd:kcacl]    displaying keychain prompt for /usr/libexec/airportd(217);
   ACL: <AclValidationContext(action:24) SUBJECT[<ThresholdAclSubject(1 of 3)[
        <CodeSignatureAclSubject[legacyHash:35ccb5719f405ddc60829d27e450d1aeca9d2d82][path:/usr/libexec/airportd]
         [requirement:identifier "com.apple.airport.airportd" and anchor apple]>] …]>
04:47:09.078 [com.apple.securityd:security_exception] MacOS error: -25337 / CSSM Exception: 224
04:47:09.078 [com.apple.securityd:kcacl]    (systemdb) user did not approve 'allow' for /usr/libexec/airportd(217)
04:47:09.078 [com.apple.securityd:acleval]  ObjectAcl REJECTS access using ACL: …
```

`mkroute.sh` 用 `codesign -f -s - -i .a2xhost-mac` 重签解释器切片，airportd 的设计要求因此变成
`identifier ".a2xhost-mac"`，既不是 `com.apple.airport.airportd`，也没有 Apple 锚。ACL 三个主体
（airportd 本签名 / `group://AirPort` 且 anchor apple / 用户点头）**一个都满足不了**，
只能落到「弹钥匙串授权」这条兜底；root 守护进程在无人值守上下文弹不出来 → 拒绝。

独立复现（只读，`/tmp/rv-wifi/secanchor.py`，用 `SecStaticCodeCheckValidity` + `anchor apple`）：

| 路径 | OSStatus |
| --- | --- |
| `/usr/libexec/airportd` | **-67050**（errSecCSReqFailed） |
| `/System/Library/CoreServices/WiFiAgent.app` | -67050 |
| `/System/Library/ExtensionKit/Extensions/Wi-Fi.appex` | **0** |
| `/bin/ls` | 0 |

-67050 与 securityd 那句 `code requirement check failed (-67050)` **完全同码**，因果闭环。

**量级**（3 小时 securityd 子系统）：

| 现象 | 次数 |
| --- | --- |
| `client is not Apple-signed` | 466 |
| `displaying keychain prompt for /usr/libexec/airportd` | **155** |
| `user did not approve 'allow' for /usr/libexec/airportd` | 155 |
| `ObjectAcl REJECTS access` | 155 |

按 PID 分布：225:84、274:21、288:18、217:16、220:8、218:8。除机场外只有 1 例 `/usr/bin/security`。
**只有被 route 的 airportd 被系统性拒绝**。

> 另有一处 `SecTaskLoadEntitlements: failed to get cs_flags, error=3`（pid 7686）出现在同一秒，
> 但 7686 是 sharing 相关进程（`com.apple.sharing` 子系统），**不是** airportd，本文不把它计入因果链。

### 2.5 为什么「报未能加入」却把状态标成已连接

设置 App 自己的子系统 `com.apple.wifi.wifisettings` 的原始序列（同一次关联）：

```
04:47:09.085  Received unknown error with code: -25308, prompting diagnostics run
04:47:09.126  handle association result: <private>
04:47:09.190  Setting current network cell for <private>
04:47:09.236  Setting current network cell for <private>
04:47:09.236  Setting current network cell rssi for <private>: -21
```

- `-25308` 对它来说是**未知错误码**（10 次全部只打这一句，没有分类），UI 只能落到通用文案
  `assoc_error_unable_to_join_network`（WiFiSettingsKit `__TEXT` 偏移 `0x12f320`）→「未能加入」。
- 但 `association result` 的回调**照常执行**，`handle association result` 把该行升级成「当前网络 cell」并写入 RSSI，
  于是列表里那一行变成已连接 → **错误被吞、状态被乐观更新**。
- ControlCenter 不受影响：它不看这个 cell，只问 `GET SSID`。

**这解释了「有时其实已连上」**：设置 App 11 次关联里有 2 次真的成功（`04:45:38` 耗时 0.96 s、`04:46:03` 耗时 15.55 s，`err=0`）——
当钥匙串那一步侥幸被放行（SecurityAgent 同意/条目已授权）时，关联真的走完；失败那 9 次里，
`Setting current network cell` 又把 UI 标成已连接，于是看起来「提示失败但状态是连上」。

---

## 3. Q2：「隐藏的网络」判据

### 3.1 结论先行

| 层 | 判据 | 证据 |
| --- | --- | --- |
| 内核/驱动 | `apple80211_scan_result` **`+0x88` bit1(0x02)** | `IO80211BSSBeacon::toScanResult` `orb $0x2,0x88(%rbx)`；详见上一篇文档 §2.1 |
| CoreWiFi | **没有** scanResult 级 hidden API | 运行时枚举 `CWFScanResult` 共 **147** 个方法，无任何 hidden 名 |
| airportd | `possiblyHidden` 参数 → 写 `CWFNetworkProfile.hiddenState` | `Info: Default <redacted> as a hidden network based on being flagged as 'possiblyHidden'`（`04:07:15.191`） |
| WiFiSettingsKit | 行模型的 `isHidden` 字段 | `__TEXT` `0x153500` 字段描述符表：`… securityType, isHidden(0x153548), rawResult, cwfScanResult …` |

**所以对用户问题的直接回答是：判据不来自 `0x48C` 之后的扩展区，也不来自 SSID 长度。**
`+0x88` 在 0x48C 前缀内（SSID 长度 `+0x60`、SSID `+0x61`、IE 长度 `+0x8A`、IE `+0x8C`）。
27 的内核写方进函数先 `bzero(0x8E8)` 再逐字段填，**尾部全 0 是 27 认可的「未知」合法值**，
任何读方都必须容忍，因此 `expandScanResult` 的 0x48C→0x8E8 清零本身不是 hidden 的来源。

### 3.2 用户态这一环（本文新增，补上上一篇的缺口 2）

上一篇文档留下的缺口是「27 用户态解析器未定位（CoreWiFi 无符号表、classlist 是 chained fixup）」。
本次用「缓存抽取 + 运行时 ObjC 反射」绕过了符号表问题：

```
$ python3 dsc.py extract …/CoreWiFi CoreWiFi.thin   # 从 dyld_shared_cache_x86_64 取 __TEXT，修补 load commands
$ python3 objcclasses.py CoreWiFi CWF hidden
CWFAutoJoinContext  -maxHiddenKnownNetworkSSIDAge
CWFNetworkProfile   -hiddenState -wasHiddenBefore -wasRecentlyHidden -__descriptionForHiddenState
CWFScanParameters   -includeHiddenNetworks
CWFHostAPConfiguration -forceHiddenMode
CWFAutoJoinManager  -__hiddenSSIDListForLocation:knownNetworks:…
CWFUIScanManager    -hiddenNetworkNameHandler
```

`CWFScanResult`（147 个方法）里 **`isHidden`/`hidden` 一个都没有**。隐藏语义只存在于
`CWFNetworkProfile.hiddenState`（类型编码 `q16@0:8`，即 NSInteger 枚举）与 `wasHiddenBefore`。

WiFiSettingsKit 的行模型（`__TEXT 0x153500` 起的字段描述符）正好把 `isHidden` 夹在
`securityType` 与 `rawResult` / `cwfScanResult` 之间 —— 它展示的是「**已知网络档案的 hidden 状态**」，
不是「这条扫描记录当前是否隐藏」。因此一旦被盖章，**重扫、重启 App 都不会自己恢复**。

### 3.3 为什么 401-5G 会被盖章

airportd 的盖章日志（3 小时内**仅 1 次**）：

```
04:07:15.191 Info: <airport[225]> Default <redacted> as a hidden network based on being flagged as 'possiblyHidden'
04:07:15.208 [corewifi] [nearbysync] Updated current network (network=<redacted> - ssid=<redacted> (1388028567),
             security=wpa3-transition, …, hidden=yes, …, channel=2g13/20, hasPassword=0, …)
```

链路：扫描记录 `+0x88` bit1 被置位（legacy 0x48C 里该字节未定义，payload0 用 `0xAA` 毒化缓冲后原样透传，
`0xAA & 0x02 != 0`）→ 27 读成「隐藏」→ 客户端关联时带 `possiblyHidden=YES` → airportd 把档案 `hiddenState`
盖章为 hidden → 设置 App 从此按档案渲染「隐藏的网络」。

> **置信度分层**（必须区分）：
> - 高：UI 的隐藏标签来自 `CWFNetworkProfile.hiddenState`；盖章来自 `possiblyHidden`（有原文日志）。
> - 高（上一篇）：扫描结果 hidden = `+0x88` bit1，legacy 侧无人定义该字节。
> - **中（未验证）**：`+0x88` 的实际线上取值（`scanSnapshot` 只抓 0x00–0x7F 共 32 word，正好看不到 0x88）；
>   以及「扫描记录被判隐藏」→「客户端置 possiblyHidden」这一步没有直接日志（`info=` 与网络名均被 `<redacted>`）。

---

## 4. Q3：两套 UI 为什么状态不一致

### 4.1 状态源对照

| | 设置 App | ControlCenter | WiFiAgent |
| --- | --- | --- | --- |
| 端点（实测次数） | `private.corewifi.internal-xpc` 4,333；`corewlan-xpc` 12 | **`corewlan-xpc` 5,082**；`private.corewifi-xpc` 仅 6 | `corewlan-xpc` 13,452；`internal-xpc` 2,764（含全部 ASSOC）；`user-agent-xpc` 429 |
| 连通性判据 | **无轮询**：`GET SSID` = 0 次；靠 `SSID CHANGED EVENT`(28) / `LINK CHANGED EVENT`(28) + 自己 model | **`GET SSID` 912 次**、`GET BSSID` 270 次、RSSI/PHY/TX RATE 各 251 | 事件 + 自身 join 状态机 |
| 列表现状 | `GET CURR SCAN RESULT`(1213，**err 恒 0**) + `GET KNOWN NETWORK MATCHING SCAN RESULT`(1215) | 不建列表 | 扫描 + auto-join |
| 与 103 关系 | 不直接调 103 | 不直接调 103 | 不直接调 103 |

`GET SSID` 的错误分布证明它是**可用的连通性判据**：`err=0` 18,007 次（有链路），`err=-3903` 15,496 次（无 SSID）。
`GET CURR SCAN RESULT` 则 **7,304 次全部 `err=0`** —— 无论是否关联都返回，**不能**用来说明「已连接」。

驱动侧计数器也支持「103 不是这两个 UI 的来源」：`C103Hits = 849`，比 `GET SSID` 的 3 万次小两个数量级。

### 4.2 两个方向的错

- **断连时设置 App 错**：它不轮询 SSID。若 `SSID CHANGED`/`LINK CHANGED` 事件没送到（扩展被电源开关重启、
  事件在重建连接期间丢失），model 里上一次的「当前 cell」不会被清 → 仍然显示「已连接 401-5G」，而 `en1` 已无 SSID。
- **连接时 ControlCenter 可能错**：它完全依赖 `GET SSID`/`GET BSSID`。就在设置 App 两次成功关联之后
  （`04:45:45–04:47:05` 的 80 秒窗口），ControlCenter 仍拿到 **16 次 -3903 / 15 次 err=0**；
  而同一时刻 `en1` 是 `status: active`、持有 `192.168.1.25`。即这条查询在链路可用时也会失败，
  菜单栏只能跟着显示未连接（另有 82 = ENETDOWN、1 = EPERM 等错误码零星出现）。

**结论**：不是「谁在撒谎」，而是两者用了互不校验的两个源，且都不以「链路/关联真实状态」为准。

### 4.3 驱动侧叠加缺陷：103 的 latch 永不清零

```cpp
// SimpleBCM/UserClient.cpp:397-410
} else if (get && request == 103) {
    last103OutputSize = outputSize;
    if (outputSize >= LegacyScanResultSize && Bridge::currentNetworkEnabled() &&
        currentNetworkBuffer && currentNetworkValid) {
        bzero(shadow, capacity);
        memcpy(shadow, currentNetworkBuffer, LegacyScanResultSize);   // 只有 0x48C
        legacy.request.length = outputSize;                           // 却声称 0x8E8
        result = kIOReturnSuccess;
        c103Hits++;
    } else { …真实命令… }
}
```

- `currentNetworkValid` 的唯一写点是 `UserClient.cpp:485`（扫描记录里 `memcmp` 到关联 SSID 时置 1）；
- 全仓库 `grep` 找不到任何清零路径，也**没有任何 link-down / disassoc 处理**（`grep -i 'LinkDown|disassoc'` 无命中）；
- 于是第一次关联成功后，103 会**永远**返回那份 0x48C（+0x45C 零尾）的旧记录。
- 现行 ioreg：`Legacy103Fallback=1`、`CurrentNetworkValid=1`、`C103Hits=849`、`Last103OutputSize=2280`。

这是真缺陷，但**不是**本次「未能加入」和「隐藏」的根因（那两条分别由 2.4 与 3.3 解释）。

---

## 5. Q4：修复方向与层级

### 5.1 层级总表

| # | 层 | 改动 | 是否根因 | 风险 / 回滚 |
| --- | --- | --- | --- | --- |
| A | **L1 a2x** | 让 airportd **保持 Apple 签名**：不替换它的 x86_64 半身，改为原生运行 + 对 arm64-only 的 `com.apple.network.EAPOLController` 做 **bundle-as-guest**（进程内 dlopen 走 a2x 解释） | **是**（-25308 / 未能加入 / CWFIsCodesignedByApple 100003 的总根因） | 改动只在 a2x 与 route 清单；需重新验证 EAPOL 与关联；可回滚到现有 route |
| B | L1 a2x | 在 a2x 里 interpose `SecCodeCheckValidity*`/`SecStaticCode*`，让**进程内**的「我是否 Apple 签名」查询按原始二进制（arm64e 半身仍有 Apple 签名）回答 | 否（只修 `CWFIsCodesignedByApple` 这类**进程内**判断，**修不到 securityd**：ACL 判定用的是内核 cs_blob） | 低风险但收益有限；不要当成 A 的替代 |
| C | L1 a2x（不推荐） | 把 `.a2xhost-mac` 加进 AirPort 钥匙串条目 ACL | 否，且是**安全倒退**：`.a2xhost-mac` 是**所有** route 程序共用的 identifier，等于让任意转译程序都能读 Wi-Fi 密码 | 需要用户明确授权；不建议 |
| D | **L0 驱动** | `expandScanResult`：`kernel>=27 && buffer[0x60]!=0` 时清 `0x88 & ~0x02` | 是（「隐藏的网络」的源头） | 1 字节 1 bit；需重建 kext + 重启才生效 |
| E | L0 驱动 | 103 fallback：关联丢失/无链路时清 `currentNetworkValid`，或在 link 未 up 时不答 103 | 是（陈旧「当前网络」） | 需要接入 link/assoc 事件；影响面小 |
| F | L0 驱动 | 查 `AssociateLengthMismatch = 4`（ioreg 实测 4 次长度不符） | 未知，可能是独立的关联失败源 | 先读计数器再改 |
| G | 报告边界 | 设置 App 的乐观更新（`Setting current network cell`）、airportd 的 `possiblyHidden` 持久化、SharingServices 回退失败 | — | Apple 逻辑，改它 = L3，禁止 |

### 5.2 为什么 A 才是正解（而不是「修钥匙串」）

`securityd` 的判定基于**内核记录的该进程 cs_blob**，而 a2x 的 route 机制**必然**把 x86_64 半身换成
adhoc 签名的解释器（否则内核不会 exec 它）。因此：

- 只要 airportd 被 route，`identifier "com.apple.airport.airportd" and anchor apple` 就**永远**不成立；
- 进程内 interpose（B）改变不了 securityd 看到的东西；
- 放宽 ACL（C）能绕过，但把 Wi-Fi 密码暴露给所有 route 程序，且不是根因修复。

airportd 本身**有 x86_64 切片**（3 切片 fat），原生运行是可行的；11-17 之所以 route 它，是因为
`com.apple.network.EAPOLController` 只有 arm64e、原生 dlopen 失败（见 [A2X-r27-工作规范.md](../../A2X-r27-工作规范.md) §八）。
把「arm64-only 插件加载」做成 a2x 的能力（bundle-as-guest），就能同时满足「EAPOL 可用」与「airportd 保持 Apple 签名」。
这与该规范 §八 第 4 条给出的长期方向一致。

### 5.3 驱动侧（D/E）能修什么、不能修什么

- **能修**：新扫描记录的 `+0x88` hidden 位（阻止继续把正常网络标成隐藏）；103 的陈旧「当前网络」。
- **不能修**：**已经被盖章的** `CWFNetworkProfile.hiddenState` 不会因为清 bit 而回滚 —— 那份状态在 airportd 的
  已知网络档案里。验证 D 时必须先「忘记该网络再重新加入」，否则会误判失败（这是**验收陷阱**）。
- **不能修**：-25308（钥匙串）、乐观更新、`possiblyHidden` 判定本身。

---

## 6. 验收方法（真实行为，不接受「编译通过」）

| 目标 | 判据 | 现状基线 |
| --- | --- | --- |
| A（a2x） | `securityd` 不再出现 `client is not Apple-signed` + `user did not approve … /usr/libexec/airportd`；`CWKeychainFindWiFiPassword` 不再返回 -25308；设置 App 连续 5 次「加入」全 `err=0` | 3h 内 155 次拒绝；`[ASSOC]` 9 败 2 成 |
| A | `SecStaticCodeCheckValidity('/usr/libexec/airportd','anchor apple') == 0` | 现为 **-67050** |
| D（驱动） | 扫描记录 `+0x88 & 0x02 == 0`（需把 `scanSnapshot` 从 32 word 扩到 ≥36，`ScanW34` 低字节即 `0x88`） | 目前抓不到，**未验证** |
| D | 忘记网络→重扫→重加后，设置 App 不再把 401-5G 归入「隐藏的网络」；真隐藏 AP 仍显示为隐藏 | — |
| E（驱动） | 断开关联后 `CurrentNetworkValid` 归 0，103 不再返回旧记录 | 现恒为 1 |
| 回归 | `AssociationRequests` / `AssociationAccepted` 继续增长；`en1` 能拿到 IPv4；ControlCenter 与设置 App 对同一时刻的连通性判断一致 | 现 `4/4`，但两 UI 不一致 |

采集命令：

```
log show --last 5m --info --debug --predicate 'subsystem == "com.apple.WiFiManager"' | grep -E '\[ASSOC\]|25308|hidden'
log show --last 5m --info --debug --predicate 'process == "securityd"'   | grep -E 'not Apple-signed|did not approve|ObjectAcl REJECTS'
ioreg -rn SimpleBCM -l | grep -E 'C103Hits|CurrentNetworkValid|AssociateLengthMismatch|ScanW34|AssociationRequests|AssociationAccepted'
```

> 注意：`log`、`strings` 等 CLT 工具在 27 上是 **arm64-only**，本身经 a2x 运行，**复杂 `--predicate`
> （`CONTAINS` 组合）会让 guest 崩溃**（`FATAL: SIGSEGV / a2x-stop`）。请只用 `processID ==`、
> `subsystem ==`、`process ==` 这类简单谓词，过滤交给 `grep`。

---

## 7. 未验证项与缺口（不得当成结论）

1. **`+0x88` 线上取值**：`scanSnapshot` 只有 32 word（0x00–0x7F），看不到 0x88；需要扩快照 + 重建 + 重启（本轮禁止）。
2. **「扫描记录被判隐藏」→「客户端置 `possiblyHidden`」**：中间没有直接日志（`info=`、网络名均 `<redacted>`）。
   验证路径：修复 D 后观察 `Default … as a hidden network` 是否消失。
3. **`CWFIsCodesignedByApple` 的 100003 与 securityd 的 -67050 不同码**：前者是 CoreWiFi 进程内调用的返回
   （`CWFUtilPrivate.m:2727`），后者是 securityd 的 ACL 判定；两者都指向「非 Apple 签名」，但未逐一解释码制差异。
4. **`-25337` 的含义**：securityd 记为 `MacOS error: -25337` 后紧跟 `CSSM Exception: 224`，本文按「用户未批准」处理，
   未在 SDK 头里逐一确认符号名。
5. **设置 App 2 次成功的原因**：推测为 SecurityAgent 当时放行/条目已授权，**未取得**对应时刻的 SecurityAgent 日志。
6. **`AssociateLengthMismatch = 4`**：只读到计数器，未定位是哪 4 次、差多少。
7. WiFiSettingsKit 的 `isHidden` 字段是**如何从 profile 取值**的（哪条 Swift 访问器）：受限于 Swift 非导出符号，
   只确证到「字段存在 + profile 有 hiddenState」，未做到逐指令对应。

---

## 8. 证据索引

### 8.1 日志原文（可直接复核）

| 主题 | 行/时间 | 内容 |
| --- | --- | --- |
| ASSOC 失败 | `03:50:49.954` | `CWKeychainFindWiFiPassword() failed with error code -25308` |
| ASSOC 结果 | `03:50:49.957` | `END REQ [ASSOC] took 0.012225249s … err=-25308` |
| 成功对照 | `04:45:38.449` / `04:46:03.777` | 设置 App `[ASSOC]` `err=0`（0.96 s / 15.55 s） |
| 客户端画像 | `BEGIN REQ` 统计 | `proc=Wi-Fi` 无 `GET SSID`；`proc=ControlCenter` 无 `ASSOC` |
| securityd 拒绝 | `04:47:09.077–.078` | `not Apple-signed` / `displaying keychain prompt for /usr/libexec/airportd(217)` / `ObjectAcl REJECTS` |
| ACL 要求 | 同上 | `requirement:identifier "com.apple.airport.airportd" and anchor apple`，`legacyHash:35ccb5719f405ddc60829d27e450d1aeca9d2d82` |
| 乐观更新 | `04:47:09.085/.126/.190/.236` | `Received unknown error … -25308` → `handle association result` → `Setting current network cell` |
| 盖章 hidden | `04:07:15.191` / `.208` | `Default <redacted> as a hidden network based on being flagged as 'possiblyHidden'` / `hidden=yes … hasPassword=0` |
| 无密码 | `04:45:37.475` | `no password provided for '<private>'` |
| Sharing 回退失败 | `04:45:47.584` | `NSCocoaErrorDomain Code=4099 … com.apple.SharingServices` / `Availability check timed out` |

### 8.2 二进制证据

| 对象 | 地址/偏移 | 含义 |
| --- | --- | --- |
| WiFiSettingsKit `__TEXT` | `0x153500` 起字段描述符 | 行模型：`… securityType, isHidden(0x153548), rawResult, cwfScanResult, isCarPlay …` |
| WiFiSettingsKit `__TEXT` | `0x12f320` | `assoc_error_unable_to_join_network`（「未能加入」文案） |
| WiFiSettingsKit 导出 | `0x00068710` / `0x00020440` / `0x00124F1C` | `WiFiSettingsAssociator` / `WiFiSettingsAssociationCoordinator` / `NetworkWarningType.hidden` |
| WiFiSettingsKit `__TEXT` | `0x13c6a0` / `0x13c6d0` | `scanForHiddenNetworks(networks:)` / `Scanning for hidden network:` |
| CoreWiFi 运行时 | 147 方法 | `CWFScanResult` **无** hidden API |
| CoreWiFi 运行时 | `q16@0:8` | `-[CWFNetworkProfile hiddenState]`（另有 `wasHiddenBefore`） |
| SimpleBCM | `UserClient.cpp:397-410` | 103 fallback：0x48C 拷贝 + 0x8E8 长度声明 |
| SimpleBCM | `UserClient.cpp:478-486` | `currentNetworkValid` 唯一置位点（无清零） |
| SimpleBCM | `WirelessABI.hpp:78/117` | `LegacyScanResultSize = 0x48C`、GG `scanResultSize = 0x8E8` |
| airportd | `codesign` | `Identifier=.a2xhost-mac`、`flags=0x2(adhoc)`、CDHash `64d3ecb0…` |

### 8.3 本次用到的只读工具（`/tmp/rv-wifi/`）

| 文件 | 用途 |
| --- | --- |
| `dsc.py` | 从多文件 dyld 共享缓存（`.00`–`.06`）按 `dyld_info` 的 `fileoff` 探测并抽取指定镜像 `__TEXT`，修补 load commands 成可 `otool` 的 thin Mach-O |
| `strs.py` | 自带字符串提取（不依赖已损坏的 `strings`），支持按文件偏移区间与 vaddr 打印 |
| `objcdump.py` / `objcclasses.py` | ctypes + ObjC runtime 反射：枚举类/方法/类型编码（只读，不实例化、不发 XPC） |
| `secanchor.py` | `SecStaticCodeCheckValidity(path, "anchor apple")`，用于复现 `CWFIsCodesignedByApple` 的失败 |
| `keychainprobe.py` | 关闭 UI 交互后 `SecKeychainFindGenericPassword`，证明 AirPort 条目存在且受 ACL 保护（`-25293`） |

（全部只读；未改动 `/System`、`/Library`、EFI。）
