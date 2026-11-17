# 27.2 扫描结果结构逆向：`apple80211_scan_result` = 0x8E8 布局、hidden 判据与 SimpleBCM 填法

日期：2026-11-18（Asia/Shanghai）
系统：macOS 27.2（26B123 / Darwin 27.2.0，x86_64）
取证对象：

| 对象 | 路径 / 地址基准 | 说明 |
| --- | --- | --- |
| 27 内核 IO80211Family | `BootKernelExtensions.kc` → `com.apple.iokit.IO80211Family`，基址 `0xffffff8001e80000` | 27 的结构权威（写方 + 读方都在这里） |
| IO80211FamilyLegacy（payload0） | `.research/extract/payload0.bin`（基址 0，__TEXT 从 0xeb0 起） | 当前 SimpleBCM 注入的 legacy 栈 |
| AirPortBrcmNIC（payload1 = Tahoe base） | `.research/extract/payload1.bin`（基址 0） | 真正构造 `apple80211_scan_result` 的驱动 |
| 运行期 | `ioreg -rn SimpleBCM -l`、`system_profiler SPAirPortDataType`、`log show` | 只读实测 |

> 取证边界：本会话无 `sudo`（`sudo -n` 要求密码），未重启、未改 `/System`、`/Library`、EFI；实验产物全部在 `/tmp`。
> 「未验证」= 明确缺口，不是结论。

---

## 0. 结论摘要（先看这里）

1. **27 的 `apple80211_scan_result` 总长 0x8E8**：type 11 的 get handler 用字面量硬门禁 `cmpl $0x8e8, 0x18(%rcx)`（`0xffffff8001f7e629`）。
2. **hidden 标志 = `+0x88` 的 u8 flags 的 `0x02` 位**（不是扩展区、不是 ssid_len==0）：`IO80211BSSBeacon::toScanResult` 调 `isHidden()`，为真才 `orb $0x2,0x88(%rbx)`（`0xffffff8001fdc2e6` / `0x1fdc2f0`）。
3. **SSID = `+0x61`（33B），ssid_len = `+0x60`（u8）**，都在 legacy 0x48C 前缀内；27 的写方/读方三处一致，运行期实测 legacy 记录确实填了（`ssid_len=7`、`"miao-5G"`）。
4. **0x48C 之后的扩展区没有 SSID/hidden 字段**：只有 IE 容量 0x400→0x800，尾部 `0x8D0`(u64 时间戳)、`0x8D8`、`0x8DC`、`0x8E0`(PHY_MODE)、`0x8E4`/`0x8E5`。27 的写方先 `bzero(0x8E8)` 再填，**尾部全 0 就是 27 认可的「未知」状态**，所以 `expandScanResult` 清零 0x48C 之后在结构上是正确的。
5. **但 `+0x88` 不是当前根因**：驱动两条构造路径（`scanComplete`→`osl_mallocz(0x498)`、`wlSortBsslist`→`osl_mallocz(0x48C)`）都是**清零分配**，且 `scanConvertResult` 从不写 `+0x88` → 到达 27 的 `+0x88` 是 **0**，hidden 位为 0。
6. **更可能的根因在 IE 块**：legacy 的 `getScanResult` 把 IE 长度算成 **`min(客户端传入的 +0x8A, 缓存里的 +0x8A)`**（payload0 `0x78c38..0x78c4c`），而 SimpleBCM 的 `prepareScanResult` **只钳制不写入** `buffer[0x8A]`；`runCommand` 里的 `shadow` 就是客户端缓冲区（`packet + sizeof(CommandHeader)`，来自 `structureInput`）。27 的 wifid 若传 0（新建/清零的请求缓冲），**每条记录的 IE 块都会变成 0 字节** → 27 侧看到「有 SSID、没有 SSID IE」的记录，被判为隐藏网络；同一条也缺 RSN IE，关联自然「未能加入」。
7. 现场日志直接证实 27 用户态的分类：`AUTO-JOIN: Hidden SSIDs (2) : 401, 401-5G`、`Hidden Network Channels (2) : 2g13/20, 5g36/20`——**SSID 已知却判为 hidden**，正是「SSID 字段有值 + IE 块为空」的签名。
8. 最小修复（一行）：`prepareScanResult` 里把 `buffer[0x8A]` 直接写成 `0x400`（legacy IE 容量），让 legacy 的 `min()` 不再被客户端的 0 压掉；附带把 `+0x88` 的 `0x02` 位在 SSID 非空时清掉（防御性，零成本）。

---

## 1. 27 的 `apple80211_scan_result`（0x8E8）字段表

来自 `IO80211BSSBeacon::toScanResult(apple80211_scan_result&)` @ **`0xffffff8001fdc1ee`**（函数体到 `0x1fdc4e7 retq`；下一个符号 `IO80211ScanSanitizer::MetaClassC1Ev` @0x1fdcf9c）。
它是 27 内核里唯一把 beacon 全字段写进 0x8E8 的地方，也是 `WCLScanRequest::getNextScanResult(apple80211_scan_result&)`（@`0xffffff80020033e4`）经虚表槽 `+0x338`（= vtable `+0x348`）调用的生产者。

| 偏移 | 宽度 | 语义 | 取值来源 / 证据地址 |
| --- | --- | --- | --- |
| 0x000 | u32 | `version` = **1** | `0x1fdc203 call __bzero`；`0x1fdc208 movl $0x1,(%rbx)` |
| 0x004 | 12B | `apple80211_channel`{version,channel,flags} | `0x1fdc220 call ChanSpecConvToApple80211Channel(getChanSWSpec(), r+4)`（`0xffffff8001e9692b`） |
| 0x010 | u16 | 噪声/SNR 有效门控（27 的 dict 据此决定是否输出 NOISE/SNR） | `0x1fdc25b movw %cx,0x10(%rbx)`（1 或 0） |
| 0x012 | i16 | noise | `0x1fdc244`（beacon+0x290） |
| 0x014 | i16 | SNR | `0x1fdc24f`（beacon+0x292） |
| 0x016 | i16 | RSSI | `0x1fdc230`（beacon+0x28c） |
| 0x018 | u16 | beaconInterval = `getBeaconPeriod()` | `0x1fdc2bc` |
| 0x01A | u16 | capability = `getCapabilities()` | `0x1fdc2cc` |
| 0x01C | u8[6] | BSSID = `getAddress(u8*)` | `0x1fdc2da`（虚表 +0x170） |
| 0x022 | u8 | numRates（≤16） | `0x1fdc3fc movb %cl,0x22(%rbx)` |
| 0x024 | u32[16] | rates | `0x1fdc3e3 movl %r8d,0x24(%rbx,%rcx,4)` |
| **0x060** | **u8** | **SSID 长度** = min(`getSSIDLength()`,32) | `0x1fdc420 movb %al,0x60(%rbx)` |
| **0x061** | **u8[33]** | **SSID** | `0x1fdc444 call memmove`，dst=`r+0x61` |
| 0x084 | u32 | AGE = `getAgeInMS()` | `0x1fdc455`（dict key `AGE`） |
| **0x088** | **u8** | **flags：bit1(0x02)=隐藏**（见 §2.1） | `0x1fdc2f0 orb $0x2,0x88(%rbx)` |
| 0x08A | u16 | IE 长度 | `0x1fdc492 movw %dx,0x8a(%rbx)`（`len!=0 && len<0x801` 才拷贝） |
| 0x08C | u8[0x800] | IEs | `0x1fdc4c1 call memmove` → 0x8C+0x800 = **0x88C** |
| 0x88C | 0x44 | 27 写方从不写（bzero 后保持 0） | 保留区（用途未验证） |
| 0x8D0 | u64 | `TIMESTAMP`（纳秒） | `0x1fdc46d call absolutetime_to_nanoseconds(beacon+0x2c8, r+0x8d0)` |
| 0x8D8 | u8 | beacon+0x5a4 的枚举原值 | `0x1fdc4d0 movb %cl,0x8d8(%rbx)` |
| 0x8DC | u32 | beacon+0x2f8 | `0x1fdc4dc movl %eax,0x8dc(%rbx)` |
| 0x8E0 | u32 | `PHY_MODE` = `getAllPhyMode()` | `0x1fdc47e`；dict key `PHY_MODE`/`CAPABILITIES` |
| 0x8E4 | u8 | `(u32)beacon[0x5a4]-1 < 2` 的布尔（只有 CURRENT_NETWORK 写） | `0xffffff8001febeb5` |
| 0x8E5 | u8 | `bssMgr[0x146] != 0`（只有 CURRENT_NETWORK 写） | `0xffffff8001febebb` |
| 0x8E6..0x8E7 | — | 对齐；结构总长 **0x8E8** | — |

### 1.1 交叉验证（同一布局的另外两个内核读方）

* `convertScanToDictionary(apple80211_scan_result*)` @ **`0xffffff8001fe4126`**：
  `CHANNEL`=0x08、`CHANNEL_FLAGS`=0x0C、`NOISE`=0x12、`SNR`=0x14、`RSSI`=0x16、`BEACON_INT`=0x18、`AP_MODE`←0x1A、`PHY_MODE`/`CAPABILITIES`=0x8E0、`BSSID`=0x1C、`SSID`=0x61（长度 0x60，且要求 `0x60!=0 && 0x61!=0`）、`RATES`=0x22 计数 + 0x24 数组、`AGE`=0x84、`TIMESTAMP`=0x8D0（qword）。
  key 表字符串地址：`0xffffff8002141ffa`（`CHANNEL` / `CHANNEL_FLAGS` / `NOISE` / `SNR` / `RSSI` / `BEACON_INT` / `AP_MODE` / `PHY_MODE` / `CAPABILITIES` / `%X:%X:%X:%X:%X:%X` / `BSSID` / `SSID` / `RATES` / `AGE` / `TIMESTAMP`）。
* `IO80211BssManager::getCurrentNet(apple80211_scan_result&)` @ **`0xffffff8001febdcc`**：ssid_len→0x60、ssid→0x61、bssid→0x1C、尾部 0x8E4/0x8E5。
* legacy 侧（payload0）读方 `convertScanToDictionary` @ `0xabb69` 读的也是 0x60/0x61（`0xabe45`/`0xabe4c`/`0xabe53`）与 0x22/0x24 —— **0x48C 前缀与 27 前缀在两代之间没有漂移**。

### 1.2 与 legacy 0x48C 的差异（回答「0x48C 之后有什么」）

| 区间 | legacy 0x48C | 27 0x8E8 | 说明 |
| --- | --- | --- | --- |
| 0x000..0x08B | 同 | 同 | 逐字段一致（见上表 + 运行期实测） |
| 0x08C..0x48B | IE[0x400] | IE[0x800] 的前半 | legacy 上限 0x400 |
| **0x48C..0x88B** | — | IE[0x800] 的后半 | 仅当 `ieLength > 0x400` 才有内容；legacy 侧被上限定死在 0x400（驱动 `0x5cdfb`、legacy `0xaed67` 都钳到 0x400）→ **全 0 正确** |
| 0x88C..0x8CF | — | 保留（写方不碰） | 全 0 |
| 0x8D0 | — | u64 TIMESTAMP(ns) | 0 = 未知，等同 27 bzero 初值 |
| 0x8D8 | — | u8（beacon+0x5a4 枚举） | 0 = 未知 |
| 0x8DC | — | u32（beacon+0x2f8） | 0 |
| 0x8E0 | — | u32 PHY_MODE 位图 | 0 = 未知 |
| 0x8E4/0x8E5 | — | u8×2（CURRENT_NETWORK 专用） | 0 |

**结论：扩展区里没有任何「SSID 有效 / hidden」字段；SimpleBCM 把 0x48C 之后清零在结构上是正确的。**

---

## 2. 「隐藏网络」到底用哪个字段

### 2.1 内核写方（决定性，直接证据）

```
ffffff8001fdc2e0:  movq  (%r14), %rax          ; rax = beacon vptr
ffffff8001fdc2e3:  movq  %r14, %rdi
ffffff8001fdc2e6:  callq *0x300(%rax)          ; vptr+0x300 → vtable+0x310 = isHidden()
ffffff8001fdc2ec:  testb %al, %al
ffffff8001fdc2ee:  je    0xffffff8001fdc2f7
ffffff8001fdc2f0:  orb   $0x2, 0x88(%rbx)      ; ★ result->flags |= 0x02  → HIDDEN
```

槽位对照（对 `_ZTV16IO80211BSSBeacon` @ `0xffffff80021954f0` 逐槽解 fixup：vptr = vtable+0x10，Itanium ABI）：

| vptr 偏移 | 目标 | 语义 |
| --- | --- | --- |
| **+0x300** | `__ZNK16IO80211BSSBeacon8isHiddenEv` @ `0xffffff8001fdb58e` | **isHidden()** ← 上面的调用点 |
| +0x2f8 | `__ZN16IO80211BSSBeacon9setHiddenEb` @ `0xffffff8001fdb57c`（写 beacon+0x2da） | setHidden(bool) |
| +0x160 | `getSSIDLength()` | → 0x60 |
| +0x138 | `getSSID()` | → 0x61 |
| +0x278 | `getAgeInMS()` | → 0x84 |
| +0x2e0 | `getAllPhyMode()` | → 0x8E0 |
| +0x1e8 | `getChanSWSpec()` | → channel |

`+0x88` 其余位的含义（同一函数，全部来自 beacon 内部字节）：

| 位 | 条件 | 证据 |
| --- | --- | --- |
| 0x01 | `!(beacon[0x2dc] & 1)` | `0x1fdc2fb..0x1fdc304` |
| **0x02** | **`isHidden()`** | `0x1fdc2e6..0x1fdc2f0` |
| 0x04 | `beacon[0x2e0] & 1` | `0x1fdc316..0x1fdc318` |
| 0x08 | `beacon[0x2df] & 1` | `0x1fdc32a..0x1fdc32c` |
| 0x10 | `beacon[0x340] & 1` | `0x1fdc33e..0x1fdc340` |
| 0x40 | `beacon[0x2e3] & 1` | `0x1fdc352..0x1fdc354` |
| 0x20 | 本函数不设（另一处 builder 是别的结构，勿混用） | — |

整个 IO80211Family 的 `__cstring` 里与 hidden 有关的字符串只有 `APPLE80211_IOC_HOST_AP_MODE_HIDDEN`（`0xffffff8002171116`，HostAP 用）；**扫描结果里的 hidden 只有 `+0x88` bit1 这一种表示**。

### 2.2 现场证据：27 用户态确实把 401 归为 hidden，同时知道它的 SSID

```
$ log show --last 15m --style compact | grep -i hidden | grep -i wifi
[corewifi] AUTO-JOIN: Hidden SSIDs (2) : 401, 401-5G
[corewifi] AUTO-JOIN: Hidden Network Channels (2) : 2g13/20, 5g36/20
[corewifi] AUTO-JOIN: Auto-join (remaining) HIDDEN NETWORKS (2)
```

进程是 `a2xhost-mac[217]`（承载 airportd 的 `airport[217]` / `com.apple.WiFiManager`），`Df` 级别，可复现。

**这组日志的形式本身就是判据**：CoreWiFi 打印出了 `401` / `401-5G` 的 **SSID 字符串**，同时又把它们算进 hidden 列表 —— 说明它拿到的记录**SSID 字段有值**，但**被其它信息判成隐藏**。这与「ssid_len==0 → 隐藏」互斥，与「`+0x88` bit1 置位」或「IE 块里没有 SSID IE」二者之一相容（见 §2.4 / §2.5）。

`system_profiler SPAirPortDataType` 的「Other Local Wi-Fi Networks」同样表现：已连接网络显示 `<redacted>:`（有 key、被隐去），而扫描条目**连名字那一行都没有**，但 PHY Mode / Channel / Security 正常 —— 说明记录本身可用、只是被判为 hidden。

### 2.3 为什么不是 ssid_len / 缺 SSID 字段

运行期实测（`ioreg -rn SimpleBCM -l` 的 32 word 快照，word24/25 = 0x60..0x67）解出最后一条扫描记录：

```
version=1, channel=36, chflags=0x410, noise=-84, snr=0, rssi=-27,
beaconInterval=100, capability=0x11, bssid=44:f7:70:17:be:27,
numRates=8, rates={6,9,12,18,24,36,48,54},
ssid_len=7, ssid="miao-5G"          ← SSID 字段被 legacy 记录填好了
```

即 legacy 记录携带有效 SSID/长度，「设置里能看到网络名」与此一致。

### 2.4 `+0x88` 在 legacy 路径上的实际值 = 0（所以不是当前根因）

| 层 | 函数 | 对 `+0x88` 的行为 |
| --- | --- | --- |
| 驱动（用户路径） | `AirPort_BrcmNIC::scanComplete(wlc_bss_list*)` @ payload1 `0x424a6` | `osl_mallocz(0x498)` 分配节点（**清零**），`scanConvertResult(bss, node+8)`（`0x4257a`） |
| 驱动（排序路径） | `AirPort_BrcmNIC::wlSortBsslist` @ payload1 `0x60e7c` | `osl_mallocz(0x48C)`（`0x60eff`/`0x60f3b`，**清零**），再 `scanConvertResult`（`0x60f25`） |
| 驱动转换 | `AirPort_BrcmNIC::scanConvertResult(wlc_bss_info*, apple80211_scan_result*)` @ payload1 `0x5cd1c` | 只写 0x00、0x04(channel)、0x12、0x16、0x18、0x1A、0x1C、0x20、0x22、0x24、0x60、0x61、0x84、0x8A、0x8C；**全程不写 0x88**，`0x5ce28 retq` 结束 |
| 驱动取结果 | `AirPort_BrcmNIC::getSCAN_RESULT` @ payload1 `0x3c37e` | 从链表弹节点，不碰内容 |
| legacy 框架 | `IO80211ScanManager::scanDone` @ payload0 `0xaec1c` | `memcpy(node+0x14, r, 0x48C)`，不碰 0x88 |
| legacy get handler | `getScanResult` @ payload0 `0x78a33`（type 11） | 输出缓冲先 `memset(buf,0xAA,0x48C)`，再逐字段覆盖；`0x78c2c/0x78c32` 把缓存记录的 `+0x88` 原样拷出 |
| 类库 | payload0 符号表 | **没有** `IO80211BSSBeacon::isHidden/setHidden`（只有 HostAP 的 `get/setHostApModeHidden`） |

⇒ 记录缓冲区是 `mallocz` 清零的，`scanConvertResult` 不写 0x88，legacy 原样透传 → **到达 27 的 `+0x88` 是 0，hidden 位为 0**。
（唯一保留：运行的是 payload2 = payload1+delta 的 Tahoe 变体，delta 是否改写 `scanConvertResult`/`osl_mallocz` 路径**未验证**。）

### 2.5 更可能的根因：IE 块被 `min()` 清零

legacy `getScanResult`（payload0 `0x78a33`）对 IE 长度的处理：

```
00078b05  call IO80211Controller::copyIn      ; 先把「客户端缓冲」拷进来（0x48C）
00078c2c  movb -0x8c8(%rbp),%al ; 缓存记录 +0x88（flags，原样透传）
00078c32  movb %al,-0x438(%rbp) ; → 输出 +0x88
00078c38  movzwl -0x436(%rbp),%eax ; AX = 客户端缓冲 +0x8A
00078c3f  movzwl -0x8c6(%rbp),%ecx ; CX = 缓存记录 +0x8A
00078c46  cmpw %cx,%ax
00078c49  cmovbl %eax,%ecx         ; ★ ECX = min(客户端, 缓存)
00078c4c  movw %cx,-0x436(%rbp)    ; 输出 +0x8A = min
00078c5f  movzwl %cx,%edx          ; ★ memcpy 长度 = min
00078c62  movl $0x400,%ecx         ; 上限 0x400
00078c67  ... memcpy(buf+0x8C, cached+0x8C, min(len,0x400))
```

而 SimpleBCM 这一侧（`SimpleBCM/UserClient.cpp`）：

* `runCommand`：`shadow = packet + sizeof(CommandHeader)`，`packet` 内容来自 **`arguments->structureInput`（客户端缓冲区）**（`UserClient.cpp:271-278`）。
* `prepareScanResult`（`WirelessABI.hpp:221`）只做 **钳制**：读出 `buffer[0x8A]`，`>0x400` 才截断，然后写回 —— **从不主动设置**。

因此：**只要 27 的 wifid 在请求缓冲里把 `0x8A` 留成 0（新建/清零缓冲的典型情况），legacy 侧的 `min()` 就把 IE 长度压成 0，整块 IE 被丢弃**。27 收到的记录于是变成「SSID 字段有值 + IE 块为空」：

* CoreWiFi 按「没有 SSID IE」判为隐藏网络 → 与 §2.2 的日志完全吻合（知道 SSID、仍算 hidden）；
* 同一条记录也没有 RSN IE → 关联时构造不出正确的 RSN/加密信息 → 「未能加入」；
* 26 时代同样的 `min()` 也在，但 26 的客户端/解析路径不把「无 SSID IE」当隐藏，所以只有 27 暴露 —— 这解释了「26 好用、27 才出问题」。

> 该假设的**未验证点**：27 的 wifid 请求缓冲在 `+0x8A` 的实际取值。SimpleBCM 的 `scanSnapshot` 只覆盖 0x00..0x7F（word 0..31），`0x8A`/`0x88` 在 word 34/34 高半，恰好差 2 个 word 看不到（§4.1 给出补法）。

---

## 3. SimpleBCM 应该怎么填

### 3.1 0x48C 之后（扩展区，保持现状即可）

| 偏移 | 建议值 | 理由 |
| --- | --- | --- |
| 0x48C..0x88B | 0 | IE 后半段；legacy 上限 0x400，27 侧 `ieLength ≤ 0x400` 时本就该是 0 |
| 0x88C..0x8CF | 0 | 27 写方也不写（保留区） |
| 0x8D0 | 0（可选：真实纳秒时间戳） | 0 = 未知，等同 27 `bzero` 初值 |
| 0x8D8 / 0x8DC | 0 | 信道宽度/BSS 元数据，无法从 legacy 记录推导 |
| 0x8E0 | 0（可选：由 IE 推导 PHY 位图） | 0 = 未知，27 会显示未知而不是错误 |
| 0x8E4 / 0x8E5 | 0 | 仅 CURRENT_NETWORK 有值 |

### 3.2 最小改动（按优先级）

**改动 1（根因候选，必须）—— `SimpleBCM/WirelessABI.hpp` `prepareScanResult`：把客户端 IE 长度顶到上限**

```cpp
inline bool prepareScanResult(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.scanResultSize || request.length != abi.scanResultSize)
        return false;
    /* legacy getScanResult 用 min(客户端 +0x8A, 缓存 +0x8A) 作为 IE 长度：
       客户端若把 +0x8A 留成 0，整块 IE 会被丢弃，27 侧就成了「有 SSID、无 SSID IE」的隐藏网络，
       关联也拿不到 RSN IE。这里直接把请求端的 IE 容量顶到 legacy 上限 0x400。 */
    const uint16_t length = LegacyScanIECapacity;      // 0x400
    buffer[ScanIELengthOffset] = static_cast<uint8_t>(length);
    buffer[ScanIELengthOffset + 1] = static_cast<uint8_t>(length >> 8);
    request.length = LegacyScanResultSize;
    return true;
}
```

替代写法（更保守，便于 A/B）：`max(客户端值, 0x400)`，语义与上面等价（客户端值 >0x400 也会被 legacy 侧钳到 0x400）。

**改动 2（防御性，零成本）—— `expandScanResult`：SSID 非空时清 hidden 位**

```cpp
if (abi.kernel >= 27 && buffer[0x60] != 0)
    buffer[0x88] &= static_cast<uint8_t>(~0x02);   // 27: +0x88 bit1 = hidden (toScanResult)
```

* 只清 bit1，不动 0x01/0x04/0x08/0x10/0x40（含义未验证）。
* 若改动 1 生效后隐藏现象消失，可把改动 2 保留为「防回归」或回滚做 A/B 对照。
* 真隐藏网络（`ssid_len == 0`）不受影响。

**不建议**：改 `expandCapabilities`、改 `expandScanResult` 的扩展区填充、把 103（CURRENT_NETWORK）映射到 11 —— 与本问题无关（见 `Docs/Analysis-20261117-driver-side.md` §2）。

---

## 4. 验证方法

### 4.1 直接读出 `+0x8A` / `+0x88`（决定性，需要构建 + 重启）

`SimpleBCM/UserClient.cpp` 的快照循环是 `for (unsigned w = 0; w < 32; ++w)`（0x00..0x7F）。把上界改成 **40**（0x00..0x9F）或单独加一个 `ScanFlags` 属性：

```
ioreg -rn SimpleBCM -l | grep -E '"ScanW34"|"ScanW35"'
```

* `ScanW34` = 0x88..0x8B：低字节 = flags（bit1 = hidden），高 2 字节 = `ieLength` 高 16 位的一部分。
* `ScanW34` 的 `ieLength` 与 `ScanW35`（0x8C..0x8F = IE 起始）配合可直接判读：
  * 修复前若 `ieLength == 0` → 证实 §2.5；
  * 修复后应等于缓存记录的真实长度（≤0x400，且 0x8C 起是 `SSID IE(0x00,len,...)`）；
  * `flags & 0x02` 应恒为 0（配合改动 2）。

### 4.2 用户态行为（最终验收，不需要重启即可观察基线）

```
log show --last 5m --style compact --predicate 'process == "a2xhost-mac"' | grep -E 'Hidden SSIDs|HIDDEN NETWORKS'
system_profiler SPAirPortDataType | sed -n '/Other Local Wi-Fi Networks/,$p'
```

* 期望：`Hidden SSIDs (N)` 不再包含 `401` / `401-5G`（真隐藏 AP 仍应保留）；`system_profiler` 的扫描条目出现名字行。
* 「系统设置 → Wi‑Fi」：`401-5G` 出现在正常列表并带名称，不再归入「隐藏的网络」。
* 关联：设置里点 `401` 能加入；若仍「未能加入」但 hidden 已修好，则关联是另一条独立问题（RSN IE 缺失可能同源，需再看 `+0x8A`）。

### 4.3 ioreg / 日志判据

```
ioreg -r -c IO80211Interface -l | grep -E 'IO80211SSID|IO80211BSSID'   # 关联状态基线
ioreg -rn SimpleBCM -l | grep -E 'ScanRecords|LastResult|ScanW34'      # 计数与关键字节
log show --last 2m --predicate 'eventMessage CONTAINS "SimpleBCM"'     # probe/iouc（DEBUG 构建才有）
```

* `ScanRecords` 随扫描递增、`LastResult = 0` 只说明返回成功，**不能**作为 hidden 已修的判据。
* 修复前后都取一次 §4.2 的日志做对照，避免把「扫描没发生」误判成「不再隐藏」。

---

## 5. 缺口（明确标注未验证）

1. **27 的 wifid 在请求缓冲 `+0x8A` 的实际取值未验证** —— 决定 §2.5 成立与否；验证路径见 §4.1（需构建 + 重启）。
2. **payload2（运行中的 AirPortBrcmNIC-Tahoe）是否改写 `scanConvertResult`/`osl_mallocz` 未验证** —— 本报告用的是 payload1（base）。若 delta 改了这条路径，`+0x88` 的「必为 0」结论需要重算。
3. **27 用户态解析器未定位**：x86_64 dyld 缓存（`/System/Library/dyld/dyld_shared_cache_x86_64`，CoreWiFi `__TEXT=0x7FF81EE32000`）无符号表，`__objc_classlist` 指针为 chained-fixup 编码（原始值形如 `0x20043641450`，按 `dyld_chained_ptr_64_rebase` 解不出合法地址），未能解出 `CWFScanResult` 方法表，因此「用户态读到 `+0x88`/IE 后如何判 hidden」仍是**推断**。工具已就绪（附录 B）。
4. **0x8D8 / 0x8DC / 0x8E4 / 0x8E5 语义未验证**：只确定来源（beacon+0x5a4、beacon+0x2f8、bssMgr+0x146/0x451），无符号名佐证。
5. **0x88C..0x8CF（0x44 字节）用途未知**：27 写方从不写，疑为保留/对齐。
6. 所有内核地址基于 26B123 / Darwin 27.2.0 的 `BootKernelExtensions.kc`（IO80211Family 基址 `0xffffff8001e80000`），换版本需重取。

---

## 附录 A：关键证据指令摘录

### A.1 type 11 get handler（0x8E8 硬门禁）

```
ffffff8001f7e61d  pushq %rbp
ffffff8001f7e624  testq %rsi,%rsi
ffffff8001f7e627  je    ...                    ; 无接口 → 0x66
ffffff8001f7e629  cmpl  $0x8e8,0x18(%rcx)       ; ★ 请求长度必须 == 0x8E8
ffffff8001f7e630  movl  $0x16,%eax
ffffff8001f7e635  jne   ...
ffffff8001f7e637  movq  0x20(%rcx),%r14         ; req->data
ffffff8001f7e643  movl  $0x8e8,%r8d
ffffff8001f7e64c  movl  $0xc02869c9,%esi        ; 'APPLE' get tag
ffffff8001f7e651  movl  $0xb,%edx               ; type 11
ffffff8001f7e659  callq 0xffffff8001ffe712
ffffff8001f7e65e  cmpl  $0xe082280f,%eax
ffffff8001f7e66f  jmp   0xffffff8001f66bfd    ; apple80211getSCAN_RESULT(skywalk, data)
```

对照：payload0 的 legacy handler 同一位置是 `cmpl $0x48c,0x18(%rbx)`（`0x78a7c`）；27 自己的 legacy 兼容 handler（`0xffffff800202c48b`）用的是 `cmpl $0x8cc,0x18(%rdx)`。**三个 ABI 尺寸不同，SimpleBCM 拦在 0x8E8 这一层是正确的。**

### A.2 `toScanResult`（27）头部与尾部

```
ffffff8001fdc1fb  movl  $0x8e8,%esi
ffffff8001fdc203  callq __bzero                 ; ★ 先整体清零 0x8E8
ffffff8001fdc208  movl  $0x1,(%rbx)              ; version = 1
ffffff8001fdc220  callq ChanSpecConvToApple80211Channel     ; channel @+4
ffffff8001fdc2e6  callq *0x300(%rax)             ; isHidden()
ffffff8001fdc2f0  orb   $0x2,0x88(%rbx)          ; ★ HIDDEN
ffffff8001fdc420  movb  %al,0x60(%rbx)           ; ssid_len
ffffff8001fdc444  callq memmove                  ; ssid @+0x61
ffffff8001fdc46d  callq absolutetime_to_nanoseconds  ; +0x8D0
ffffff8001fdc47e  movl  %eax,0x8e0(%rbx)         ; PHY_MODE
ffffff8001fdc492  movw  %dx,0x8a(%rbx)           ; ieLength
ffffff8001fdc4c1  callq memmove                  ; IEs @+0x8C (≤0x800)
ffffff8001fdc4d0  movb  %cl,0x8d8(%rbx)
ffffff8001fdc4dc  movl  %eax,0x8dc(%rbx)
```

### A.3 驱动构造记录（payload1，清零分配 + 不写 0x88）

```
00042554  movq  $0x0,...                 ; scanComplete
0004255b  movl  $0x498,%esi
00042560  callq _osl_mallocz             ; ★ 清零分配（用户路径）
0004257a  callq scanConvertResult        ; 填 record @node+8

00060eff  movl  $0x48c,%esi              ; wlSortBsslist
00060f04  callq _osl_mallocz             ; ★ 清零分配
00060f25  callq scanConvertResult

0005cd29  movl  $0x1,(%rdx)              ; scanConvertResult: version = 1
0005cd37  callq chanspec2applechannel
0005cd40  movw  %ax,0x12(%r14)           ; noise
0005cd49  movw  %ax,0x16(%r14)           ; rssi
0005cd52  movw  %ax,0x18(%r14)           ; beacon interval
0005cd5b  movw  %ax,0x1a(%r14)           ; capability
0005cd62  movl  %eax,0x1c(%r14)          ; bssid[0..3]
0005cd6a  movw  %ax,0x20(%r14)           ; bssid[4..5]
0005cd7d  movb  %al,0x22(%r14)           ; numRates
0005cd96  movl  %edx,0x24(%r14,%rcx,4)   ; rates
0005cdb0  movb  %cl,0x60(%r14)           ; ssid_len = min(bss[8],0x20)
0005cdbf  callq memcpy(&r[0x61], bss+9, len)
0005cdda  movl  %eax,0x84(%r14)          ; age
0005cdf0  movw  %ax,0x8a(%r14)           ; ieLength = bss[0x70]-0xc
0005ce15  jmp   memcpy(&r[0x8c], bss[0x68]+0xc, len)   ; IEs ≤0x400
0005ce28  retq                           ; ★ 没有写 0x88
```

### A.4 legacy get handler：`min()` 压掉 IE（payload0）

```
00078ae5  movl $0x48c,%edx
00078aed  movl $0xaa,%esi
00078af2  call memset                    ; 输出缓冲毒化 0xAA
00078b05  call IO80211Controller::copyIn  ; 客户端缓冲 0x48C 拷入
00078c2c  movb -0x8c8(%rbp),%al          ; 缓存 +0x88
00078c32  movb %al,-0x438(%rbp)          ; ★ 原样写入输出 +0x88
00078c38  movzwl -0x436(%rbp),%eax       ; AX = 客户端 +0x8A
00078c3f  movzwl -0x8c6(%rbp),%ecx       ; CX = 缓存 +0x8A
00078c46  cmpw %cx,%ax
00078c49  cmovbl %eax,%ecx               ; ★ ECX = min(客户端, 缓存)
00078c4c  movw %cx,-0x436(%rbp)          ; 输出 +0x8A = min
00078c62  movl $0x400,%ecx               ; 上限
00078c67  ... memcpy(+0x8C, cached+0x8C, min(len,0x400))
```

---

## 附录 B：复现用工具（均在 /tmp，只读）

| 文件 | 用途 |
| --- | --- |
| `/tmp/kcdis.py` | 从 `BootKernelExtensions.kc` 抽单个 kext 镜像 → 合成 Mach-O（含 `__text` 段）→ `llvm-objdump` 可按内核虚拟地址直接反汇编 |
| `/tmp/kcstr.py` | 读 KC 内任意地址的 C 字符串 |
| `/tmp/dyldcache.py` | 多文件 x86_64 dyld 共享缓存读取（vmaddr → 文件偏移） |
| `/tmp/objc_cache.py` | 缓存内镜像的 Mach-O/ObjC 元数据解析骨架（classlist 为 chained fixup，编码待解） |

复现命令示例：

```bash
PY=/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3
$PY /tmp/kcdis.py ffffff8001fdc1ee ffffff8001fdc4e7        # toScanResult
$PY /tmp/kcdis.py ffffff8001fe4126 ffffff8001fe45a0        # convertScanToDictionary
$PY /tmp/kcdis.py ffffff8001febdcc ffffff8001fec850        # getCurrentNet
$PY /tmp/kcdis.py ffffff8001f7e61d ffffff8001f7e900        # type 11 get handler
```
