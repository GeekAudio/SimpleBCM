# AirDrop/AWDL 传输路径与 27 ↔ payload0 set 请求映射（驱动侧逆向）

- 日期：2026-11-18
- 目标系统：macOS 27.2（26B123，x86_64，BCM43602），`/System/Library/KernelCollections/BootKernelExtensions.kc`
- 被分析镜像：
  - 27 的 `com.apple.iokit.IO80211Family`（fileset 入口 `0xffffff8001e80000`）
  - `.research/extract/payload0.bin`（IO80211FamilyLegacy，注入后类名注册为 `SB80211*`）
  - `.research/extract/payload1.bin`（AirPort_BrcmNIC，驱动侧）
- 仓库：`simplebcm-r27`，分支 `wifi-assoc-probe`，HEAD `d792dca`
- **全部只读**：只读 KC/二进制/iorg/log，未加载卸载 kext，未改 `/System`、`/Library`、EFI，未重启、未部署。反汇编用的 KC 抽取副本只写到 `/tmp/sbawdl/`。

---

## 0. 结论摘要

1. **AWDL set 请求在 payload0 里"不缺"**：`_gSetHandlerTable`（417 项）在 **116–139、148、155、162–167、201–233、253、343、417** 都有真实 handler（`setAwdlSyncParams`/`setAwdlSyncEnabled`/…/`setAWDLUMIToPeer`），不是桩、不返回 0x66。此前"payload0 没有 AWDL"的判断不成立。
2. **27 的三张表里，只有 IOUC(607) 与 internal(607) 有 AWDL；legacy(457) 表 AWDL 槽位全为 NULL。** 也就是说 27 的 AWDL 只走 IO80211APIUserClient/内部路由，不走 BSD ioctl legacy 表。这与 payload0 的 417 表（legacy 形态）不是同一"层"，但请求号一一对应。
3. **同名/近名 handler 语义等价**：对 116–139/148/155/162–167/201–233/417，27 新表 handler 与 payload0 handler 的**入参长度检查完全相同**，且最终都 tail-call/call 同一个 `IO80211AWDLPeerManager::setAwdl*` 方法（已逐个核对到方法级，例如 116 `setAwdlSyncParams`、134 `setAwdlSyncState`、417 `setAWDLUMIToPeer`）。
4. **唯一的结构差异**：27 通过 `skywalk+0x120 → +0x28` 取 `IO80211AWDLPeerManager`；payload0 通过 **`virtualInterface+0xb0`** 取。两者"取不到"时分别返回 `0x2d`（无 virt/无 peer manager 容器）与 `0x13`（metaCast 失败）。**这是驱动侧唯一真正需要修的入口问题**。
5. **17 个 AWDL 请求 27 有、payload0 无**（149/151/158/213/224/225/226/229/262/263/342/416/432/467 等），其中 >417 的在 payload0 分派器里直接吃 `0x66`（越界），≤417 的是空槽 `0x66`。它们中的大多数在 **payload1 驱动侧有对应 `AirPort_BrcmNIC::setAWDL_*`**（`setAWDL_OOB_REQUEST`、`setAWDL_DFSP_CONFIG`、`setAWDL_ADVERTISERS`、`setAWDL_MIN_RATE`、`setAWDL_ENABLE_ROAMING`…），所以可以用 Classic 端点转发到驱动表，而不是伪造成功。
6. **两个 AWDL 统计结构的长度在 27 上变大了**：type 223 `0xa88 → 0xea8`、type 343 `0xf88 → 0xfb8`。payload0 的 handler 是 `cmp length, imm; jne → 0x16`，27 用户态按新长度发送时**必然 EINVAL**。这类必须做结构裁剪或不转发。
7. **CLink 依赖的是完整 AWDL 链路**：控制面（116/117/129/132/134/136/164…）→ 驱动 `version_check(0 或 1)` + iovar `"awdl"` → 固件；数据面 = **417 `setAWDL_UMI_TX_PEER` → `IO80211AWDLPeerManager::setAWDLUMIToPeer` → `findPeer(mac)` → `sendRealTimeUMI(peer, …)`**。417 是"把实时 UMI 发给某个已存在 AWDL peer"的开关，没有 peer 就无从谈起。
8. **运行期现状（只读采样）**：`SB80211AWDLPeerManager=1`、`SB80211AWDLMulticastPeer=1`、`SB80211VirtualInterface=1`，但 **`SB80211AWDLPeer=0`（无单播 peer）、`IO80211AWDLProtocol=0`、`IO80211RealTimePeerManager=0`**；`awdl0` 计数 **Ipkts=0 / Opkts=6**；`SetHist0..15` 全是 **483**、`SetRes*=102`。即：AWDL 对象树建起来了，但**从未有过一个 AWDL peer**，数据面一个包都没收。
9. **观测盲区**：`SetHist/SetRes` 只在 `Bridge::command` 里记，而 AWDL 的 set/get 很可能根本不经过 Bridge（`awdl0` 的客户端是 `BCMLegacyInterface`→Skywalk 端点，或直接是 native 客户端）。所以"SetHist 里没有 116–139"**不能**推出"27 没发过"。
10. **边界**：payload1 里 `wlc_awdl_*`、`awdlIfTxPacketsPending`、`wl_awdl_queued_pkt_upd`、iovar `"awdl"`、`AWDL LL Pool` 队列全都在 → **硬件/固件层具备 AWDL 能力**，不需要伪造；真正的缺口在"谁持有 AWDL peer manager、由哪个端点把请求送进去"。若后续证明 27 用户态根本不发 AWDL 控制请求，则问题在 wifip2pd/sharingd 一侧，驱动改动无法解决——这一点必须用计数器先区分。

---

## 1. 方法与复现（只读）

1. 27 的 kext 用 `Tools/kernel_collection.py` 读 KC；为能反汇编，把 fileset entry 重定位抽成独立 Mach-O（`/tmp/sbawdl/kcextract.py` → `/tmp/sbawdl/IO80211Family27.macho`）。关键点：`LC_SEGMENT_64` 的 `fileoff` 在 `pos+40`，`nsects` 在 `pos+64`，section 从 `pos+72` 起、section 的 `offset` 在 `sp+48`；`LC_SYMTAB`、`LC_DYSYMTAB`、`LC_FILESET_ENTRY` 相应重写/清零。抽取后 `llvm-objdump` 可直接按 KVA 反汇编。
2. 表项解码：`kc.pointer(addr)`（chained fixup `fixup_base + (raw & 0x3FFFFFFF)`），payload0 侧是 8 字节直接地址。
3. 符号名：`nm -arch x86_64`（payload0/1）+ KC 符号表（27），`llvm-cxxfilt` 还原签名。
4. 运行期只读：`ioreg -rn SimpleBCM -l`、`ioreg -w0 -p IO80211Plane`、`ifconfig awdl0`、`netstat -I awdl0`、`ps aux`、`log show`。

---

## 2. AWDL set 请求映射（type → 27 handler → payload0 handler）

### 2.1 双方都有：27 新表(607) / internal(607) / payload0(417) 三处均有实现，27 legacy(457) 为 NULL

> 长度列是 handler 对 `req->length` 的**严格相等**检查（`cmpl $imm,0x18(%r*)`），`27/p0` 两侧一致即表示结构体大小相同。

| type | 27 新表 handler（地址） | 27 legacy(457) | 27 internal(607) | payload0 handler（地址） | len 27/p0 |
|---|---|---|---|---|---|
| 116 | `setAWDL_SYNC_PARAMS` `0xffffff8001f8ad75` | NULL | `apple80211setAWDL_SYNC_PARAMS` | `setAwdlSyncParams` `0x87c5a` | 0x18 / 0x18 |
| 117 | `setAWDL_SYNC_ENABLED` `0xffffff8001f8add7` | NULL | `…SYNC_ENABLED` | `setAwdlSyncEnabled` `0x87d30` | 0xc / 0xc |
| 118 | `setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS` `0xffffff8001f8ae39` | NULL | 同名 | `setAwdlExtensionParams` `0x87e07` | 0x14 / 0x14 |
| 119 | `setAWDL_SERVICE_PARAMS` `0xffffff8001f8ae9b` | NULL | 同名 | `setAwdlPeerServiceParams` `0x87ee0` | 0x2c / 0x2c |
| 120 | `setAWDL_PEER_SERVICE_REQUEST` `0xffffff8001f8af38` | NULL | 同名 | `setAwdlPeerServiceRequest` `0x88001` | 变长：`≥0x14` 且 `u16@+0x10 + 0x14 == len`，两侧一致 |
| 122 | `setAWDL_ELECTION_ID` `0xffffff8001f8afac` | NULL | 同名 | `setAwdlElectionId` `0x88156` | 8 / 8 |
| 124 | `setAWDL_GUARD_TIME` `0xffffff8001f8b00e` | NULL | 同名 | `setAwdlGuardTime` `0x88226` | 8 / 8 |
| 125 | `setAWDL_BSSID` `0xffffff8001f8b070` | NULL | 同名 | `setAwdlBssid` `0x882ef` | 0x10 / 0x10 |
| 126 | `setAWDL_ELECTION_METRIC` `0xffffff8001f8b0d2` | NULL | 同名 | `setAwdlElectionMetric` `0x883c1` | 0xc / 0xc |
| 127 | `setAWDL_AVAILABILITY_WINDOW_AP_ALIGNMENT` `0xffffff8001f8b134` | NULL | 同名 | `setAwdlAvailabilityWindowApAlignment` `0x88498` | 0x10 / 0x10 |
| 128 | `setAWDL_SYNC_FRAME_AP_BEACON_ALIGNMENT` `0xffffff8001f8b196` | NULL | 同名 | `setAwdlSyncFrameApAlignment` `0x8856a` | 0xc / 0xc |
| 129 | `setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE` `0xffffff8001f8b1e4` | NULL | 同名 | `setAwdlChannelSequence` `0x88608` | 0x190 / 0x190 |
| 131 | `setAWDL_OUI` `0xffffff8001f8b249` | NULL | 同名 | `setAwdlOUI` `0x887ac` | 8 / 8 |
| 132 | `setAWDL_MASTER_CHANNEL` `0xffffff8001f8b2ab` | NULL | 同名 | `setAwdlMasterChannel` `0x8887c` | 8 / 8 |
| 133 | `setAWDL_TOP_MASTER` `0xffffff8001f8b30d` | NULL | 同名 | `setAwdlTopMaster` `0x8894c` | 0x10 / 0x10 |
| 134 | `setAWDL_SYNC_STATE` `0xffffff8001f8b35b` | NULL | 同名 | `setAwdlSyncState` `0x889e5` | 0x18 / 0x18 |
| 135 | `setAWDL_ELECTION_RSSI_THRESHOLDS` `0xffffff8001f8b3bd` | NULL | 同名 | `setAwdlElectionRssiThresholds` `0x88abb` | 0x14 / 0x14 |
| 136 | `setAWDL_PRESENCE_MODE` `0xffffff8001f8b41f` | NULL | 同名 | `setAwdlPresenceMode` `0x88b94` | 8 / 8 |
| 138 | `setAWDL_PERIODIC_SYNC_FRAME_PACKET_LIFETIME` `0xffffff8001f8b481` | NULL | 同名 | `setAwdlSyncFramePacketLifetime` `0x88c64` | 8 / 8 |
| 139 | `setAWDL_MASTER_MODE_SYNC_FRAME_PERIOD` `0xffffff8001f8b4e3` | NULL | 同名 | `setAwdlMasterSyncFramePeriod` `0x88d34` | 8 / 8 |
| 148 | `setAWDL_STRATEGY` `0xffffff8001f8b52e` | NULL | 同名 | `setAwdlStrategy` `0x88df4` | 0x18 / 0x18 |
| 155 | `setAWDL_ELECTION_PARAMS` `0xffffff8001f8b67a` | NULL | 同名 | `setAwdlElectionParams` `0x891bb` | 0x38 / 0x38 |
| 162 | `setAWDL_CTL` `0xffffff8001f8b7bb` | NULL | 同名 | `setAwdlCtl` `0x8942f` | 0x3b8a0 / 0x3b8a0 |
| 163 | `setAWDL_SOCIAL_TIME_SLOTS` `0xffffff8001f8b8ed` | NULL | 同名 | `setAwdlSocialTimeSlots` `0x895aa` | 8 / 8 |
| 164 | `setAWDL_PEER_TRAFFIC_REGISTRATION` `0xffffff8001f8b94f` | NULL | 同名 | `setAwdlPeerTrafficRegistration` `0x8967a` | 0xb8 / 0xb8 |
| 167 | `setAWDL_FORCED_ROAM_CONFIG` `0xffffff8001f8b9b4` | NULL | 同名 | `setAwdlForcedRoamConfig` `0x89767` | 0x10 / 0x10 |
| 201 | `setAWDL_BTLE_PEER_INDICATION` `0xffffff8001f8bc6b` | NULL | 同名 | `setAwdlBtlePeerIndication` `0x8ade5` | 0x20 / 0x20 |
| 204 | `setAWDL_BTLE_ENABLE_SYNC_WITH_PARAMS` `0xffffff8001f8bccd` | NULL | 同名 | `setAwdlBtleEnableSynchWithParams` `0x8aebf` | 0x14 / 0x14 |
| 205 | `setAWDL_SECONDARY_MASTER_CHANNEL` `0xffffff8001f8bd2f` | NULL | 同名 | `setAwdlSecondaryMasterChannel` `0x8af98` | 8 / 8 |
| 208 | `setAWDL_AF_TX_MODE` `0xffffff8001f8bd91` | NULL | 同名 | `setAwdlAfTxMode` `0x8b068` | 8 / 8 |
| 217 | `setAWDL_OPER_MODE` `0xffffff8001f8bf18` | NULL | 同名 | `setAwdlOperatingMode` `0x8b34e` | 8 / 8 |
| 219 | `setAWDL_ENCRYPTION_KEYS` `0xffffff8001f8bf7a` | NULL | 同名 | `setAwdlKey` `0x8b41e` | 0x94 / 0x94 |
| 220 | `setAWDL_ENCRYPTION_TYPE` `0xffffff8001f8bfdf` | NULL | 同名 | `setAwdlEncryptType` `0x8b50b` | 8 / 8 |
| **223** | `setAWDL_STATISTICS` `0xffffff8001f8c041` | NULL | 同名 | `clearAwdlStatistics` `0x8b8df` | **0xea8 / 0xa88** ⚠ |
| 233 | `setAWDL_BLOCK_SET_COMMANDS` `0xffffff8001f8c350` | NULL | 同名 | `setAwdlBlockSetCommands` `0x8bd63` | 8 / 8 |
| 253 | `setAWDL_NEARBY_LOG_TRIGGER` `0xffffff8001f8c76f` | NULL | 同名 | `setAwdlNearbyLogTrigger` `0x8c37e` | 8 / 8 |
| **343** | `setAWDL_LOW_LATENCY_STATISTICS` `0xffffff8001f8e44d` | NULL | 同名 | `clearAwdlLowLatencyStatistics` `0x8cd06` | **0xfb8 / 0xf88** ⚠ |
| **417** | `setAWDL_UMI_TX_PEER` `0xffffff8001f8f32f` | NULL | 同名 | `setAWDLUMIToPeer` `0x8d505` | 0x10 / 0x10 |

get 方向同样成对存在（116–139/148/155/162/163/202/203/205/208/213/217/220/223/233/343/416 的 `getAWDL_*` vs `getAwdl*`），长度也逐项对上。

### 2.2 27 有、payload0 无（表内空洞或越界）

| type | 27 新表 | 27 internal | payload0 | payload0 侧实际行为 |
|---|---|---|---|---|
| 149 | — | `apple80211setAWDL_OOB_REQUEST` | NULL（槽位 148） | 空槽 → `0x66`（并打两条 `not recognized`） |
| 151 | — | `…AWDL_SYNC_FRAME_TEMPLATE` | NULL | `0x66` |
| 158 | — | —（仅 get `AWDL_DEVICE_CAPABILITIES`） | NULL | `0x66` |
| 213 | `setAWDL_MIN_RATE` | `…MIN_RATE` | NULL | `0x66` |
| 224 | — | `…AWDL_ENABLE_ROAMING` | NULL | `0x66` |
| 225 | — | `…AWDL_OOB_AUTO_REQUEST` | NULL | `0x66` |
| 226 | — | `…AWDL_TXCAL_PERIOD` | NULL | `0x66` |
| 229 | `setAWDL_AWDL_ADVERTISERS` | 同名 | NULL | `0x66` |
| 262 | — | `…AWDL_DFSP_CONFIG` | NULL | `0x66` |
| 263 | — | `…AWDL_DFSP_UCSA_CONFIG` | NULL | `0x66` |
| 342 | — | `…AWDL_OOB_SEC_PAYLOAD_REQUEST` | NULL | `0x66` |
| 416 | `setAWDL_MI_BITMAP` | 同名 | NULL（槽位 415） | `0x66` |
| 432 | — | `…AWDL_CONFIG` | **越界**（>417） | 分派器 `type≥418` → `0x66` |
| 467 | — | `…AWDL_RTG_PEER_STATS_CONFIG` | 越界 | `0x66` |

### 2.3 三类归类（对应任务要求）

- **「27 有、payload0 无」**：上表 14 个（真正结论：payload0 的 AWDL 覆盖到 2026 年前的号段，27 新增的 DFSP/OOB/MI/RTG 系列没有）。
- **「名字不同但语义一致」**：全部共享号段。命名规则是机械映射：27 `setAWDL_XXX` ↔ payload0 `setAwdlXxx`（`setAWDL_UMI_TX_PEER` ↔ `setAWDLUMIToPeer`、`setAWDL_STATISTICS` ↔ `clearAwdlStatistics`、`setAWDL_BLOCK_SET_COMMANDS` ↔ `setAwdlBlockSetCommands`）；internal 表名统一加 `apple80211` 前缀。**已逐个核对到最终 tail-call 的 peer manager 方法名**（见 §3）。
- **「payload0 是桩/返回 0x66」**：**AWDL 号段里没有桩**。payload0 已知的桩在别的号上（例如 **get** 表 103 `getCurrentNetwork` 是三指令返回 `0x66` 的桩，见 `Bridge.cpp` 注释）；AWDL 116–139/148/155/162–167/201–233/253/343/417 都是完整实现。只有 §2.2 的空洞/越界返回 `0x66`（空槽还会连打两条 `IOCTL (from pid …) not recognized`）。

---

## 3. handler 语义等价性：差在"怎么拿到 peer manager"

### 3.1 27 新表 handler 的形状（以 116/417 为例）

```
setAWDL_SYNC_PARAMS(IO80211Controller*, IO80211SkywalkInterface*, IO80211APIUserClient*, apple80211req*)
  cmpl $0x18, 0x18(%rcx)      ; req->length 必须 == 0x18，否则 0x16
  jne  -> 0x16
  movq 0x20(%rcx), %rbx       ; req->data
  testq -> 0x16               ; data==NULL
  testq %rsi,%rsi -> 0x2d     ; skywalk==NULL
  movq 0x120(%rsi), %rcx      ; skywalk->awdlProtocol（IO80211AWDLProtocol 对象）
  movq 0x28(%rcx),  %rdi      ; protocol->peerManager
  testq -> 0x2d               ; 无 peer manager
  safeMetaCast(rdi, IO80211AWDLPeerManager::gMetaClass) -> 0x13（失败时）
  jmp  IO80211AWDLPeerManager::setAwdlSyncParams(apple80211_awdl_sync_params*)
```

417 完全同形，末跳 `0xffffff8001f1c7f4 IO80211AWDLPeerManager::setAWDLUMIToPeer(apple80211_awdl_UMI_data*)`。

### 3.2 payload0 handler 的形状（116/417）

```
setAwdlSyncParams(IO80211Controller*, IO80211Interface*, IO80211VirtualInterface*, IO80211InfraInterface*, apple80211req*, bool)
  cmpl $0x18, 0x18(%r8)       ; 同样的长度检查
  copyIn(0x18) 到栈
  movq 0xb0(%r15), %rdi       ; r15 = rdx = virtualInterface；+0xb0 = peerManager
  testq -> 0x2d               ; virt==NULL 或 无 peer manager
  safeMetaCast(..., IO80211AWDLPeerManager::gMetaClass) -> 0x13
  call IO80211AWDLPeerManager::setAwdlSyncParams(...)
  copyOut(0x18)               ; 把结构回写用户态（in/out 结构）
```

逐项核对的 tail-call/call 目标（payload0 → peer manager）：

| type | payload0 handler 调用的 peer manager 方法 |
|---|---|
| 116 | `IO80211AWDLPeerManager::setAwdlSyncParams(apple80211_awdl_sync_params*)` |
| 117 | `…::setAwdlSyncEnabled(apple80211_awdl_sync_enabled*)`（内部还会 `configure()`、`resetElectionState()`、`do_ioctl`） |
| 120 | `…::setAwdlPeerServiceRequest(apple80211_peer_service_request*, u8*)` |
| 129 | `…::setAwdlChannelSequence(apple80211_awdl_sync_channel_sequence*)` |
| 134 | `…::setAwdlSyncState(apple80211_awdl_sync_state*)` |
| 136 | `…::setAwdlPresenceMode(apple80211_awdl_presence_mode*)` |
| 417 | `…::setAWDLUMIToPeer(apple80211_awdl_UMI_data*)` |

27 新表 handler 的对应目标解出来是**同名方法**（27 里 struct typedef 去掉了 `apple80211_` 前缀，例如 `awdl_sync_state` vs `apple80211_awdl_sync_state`），因此**结构布局按长度+同方法可判定一致**（223/343 除外，见 §2.1）。

### 3.3 关键差异表

| 项 | 27 新表 | payload0 | 影响 |
|---|---|---|---|
| peer manager 来源 | `skywalk+0x120` → `+0x28` | `virtualInterface+0xb0` | 入口参数不同，**不能只靠"同号同表"就走通** |
| 无容器 | `0x2d` | `0x2d` | 一致 |
| metaCast 失败 | `0x13` | `0x13` | 一致 |
| 长度不符 | `0x16` | `0x16` | 一致 |
| 入参 | `(ctrl, skywalk, uc, req)` | `(ctrl, iface, virt, infra, req, bool)` | SimpleBCM 分派时必须正确填 `virt` |
| 回写 | 无 | `copyOut(req->data)`（in/out） | 27 侧无回写，走 SimpleBCM 时多一次 copyOut 是幂等的 |

---

## 4. AirDrop 的 CLink/AWDL 传输实际依赖什么

### 4.1 用户态证据

- `sharingd` 里存在 `CLink`、`CLinkClient`、`CLinkScreenOff` 三个符号串（`grep -a` 命中）。CLink 是 sharingd 侧基于 AWDL 的点对点链路抽象，`NeedsCLink` 是它在 BLE 发现阶段给出的"需要 CLink"标记。
- `awdl0` 的 user client 由 **`wifip2pd`（pid 378）** 与 **`airportd`（pid 220）** 持有（`IOUserClientCreator`）。`awdl0` 的 ifnet 是 `AirPort_BrcmNIC_P2PInterface`，`IO80211VirtualInterfaceRole = "AirLink"`，前缀 `awdl`。
- 因此 CLink 的数据面不在 sharingd 里，而是 **sharingd(CLink) → wifip2pd → awdl0 → 驱动 AWDL 数据通路**。

### 4.2 内核侧依赖链（payload0 + payload1）

```
控制面（必须先成立）
  wifip2pd / airportd
    → set 116/117 (sync params/enabled) → 117 内 configure()+resetElectionState()+do_ioctl
    → set 129 (channel sequence) / 132 (master channel) / 136 (presence mode)
    → set 155 (election params) / 162 (awdl ctl) / 163 (social time slots)
    → set 164 (peer traffic registration)    ← AirDrop 会话级的流量注册
        ↓  IO80211AWDLPeerManager::do_ioctl(cmd=0x803069c8, subcmd, data)
        ↓  IO80211Controller::apple80211VirtualRequestIoctl / apple80211RequestIoctl
        ↓  AirPort_BrcmNIC::apple80211(Virtual)Request → setAWDL_* (payload1)
        ↓  version_check(struct->version, "...") 只接受 0 或 1
        ↓  wlIovarOp("awdl", ...) → wlc_awdl_* → 固件
发现面
  驱动上报 AWDL 帧/事件 → IO80211AWDLPeerManager::inputPacket/addAWDLPeer
    → IO80211AWDLPeer 对象（每个对端一个）
数据面（CLink 真正跑起来的那一刻）
  wifip2pd → set 417 setAWDL_UMI_TX_PEER(apple80211_awdl_UMI_data, 0x10 字节)
    → IO80211AWDLPeerManager::setAWDLUMIToPeer
        if (!data) log + 返回
        peer = findPeer(data->peerMac @+0x8)      ← 没有 peer 直接失败
        sendRealTimeUMI(peer, data->field_4)      ← 真正把实时 UMI 排给该 peer
```

要点：

1. **417 不是"建链"，而是"对已存在 peer 发实时 UMI"**。payload0 里 `setAWDLUMIToPeer` 第一步就是 `findPeer((u8*)data+8)`，找不到就 logDebug 后失败（`0x47873` 分支）。所以哪怕 417 的映射、长度、入口全都对，**只要 peer 数据库为空，它就不可能成功**。
2. **peer 数据库由发现面填充**，而发现面依赖控制面把 AWDL 调起来（sync/election/channel sequence）。
3. 27 的 417 handler 与 payload0 的 417 handler 最终调用**同一个** `IO80211AWDLPeerManager::setAWDLUMIToPeer`，所以 417 本身没有"27 语义 vs legacy 语义"的差异问题。

### 4.3 运行期状态（只读采样，2026-11-18 15:2x）

| 观测 | 值 | 含义 |
|---|---|---|
| IOKit 类计数 `SB80211AWDLPeerManager` | 1 | **AWDL peer manager 已创建**（注入的 legacy family 对象，类名被 namespace 成 SB80211*） |
| `SB80211AWDLMulticastPeer` | 1 | peer manager 初始化时建的组播 peer |
| `SB80211AWDLPeer` | **0** | **从未创建过任何单播 AWDL peer** |
| `SB80211VirtualInterface` | 1 | 存在一个 virtual interface 实例 |
| `IO80211AWDLProtocol` / `IO80211RealTimePeerManager` | 0 / 0 | 27 侧对应对象不存在（27 的 family 未被用作 AWDL 宿主） |
| `awdl0` `netstat -I` | Ipkts=0 / Opkts=6 | 只发过 6 个（IPv6 ND/MLD 级），**一个包都没收** |
| `SetHist0..15` | 全 483 | 最近 16 次 set 全是 483（EXTERNAL_POWER_STATE），**没有 AWDL 号** |
| `SetRes0..15` / `LastSetResult` | 全 102（0x66） | 483 被驱动拒绝 |
| `SetCount` / `ReqCount` | 1651 / 38924 | Bridge 侧总请求量 |
| `AWDLCoexistenceStatus` / `Selections` | `Disabled` / 0 | 该补丁默认关闭，`selectChannelsToUseForAWDL` 计数当前**不可用作证据** |

结论：**AWDL 对象树存在，但没有 peer、没有 RX；CLink 不可能建立**。这与"BLE 发现正常（`SFBLEDevice`/`NeedsCLink`）、iPhone→Mac 传输失败、sharingd 侧无 CLink"的现象完全一致。

---

## 5. 驱动侧缺口（按优先级）

### G1 — 入口参数错配（最可能的直接原因）

`Bridge::command` 对三种端点分别调用：

```c
Classic : classicCommand(iface, controller, cmd, NULL, req)          // 走驱动表
Virtual : setRequest(controller, NULL, iface(virtual), NULL, req)    // rdx=virt, rcx=NULL
Skywalk : setRequest(controller, NULL, NULL, iface(skywalk), req)    // rdx=NULL, rcx=skywalk
```

而 payload0 的 AWDL handler **只从 `rdx`（virtualInterface）取 peer manager（`+0xb0`）**。因此：

- 若 `awdl0` 的请求走 **Skywalk 端点**：`rdx == NULL` → 所有 AWDL set/get **恒返回 `0x2d`**（即使 `SB80211AWDLPeerManager` 存在）。
- 若走 **Virtual 端点**：`rdx` 是 SimpleBCM 侧的接口对象，只有它本身就是 `IO80211VirtualInterface` 且 `+0xb0` 已挂 peer manager 时才成立；否则 `0x2d`/`0x13`。
- 只有 **Classic 端点**（`IO80211Interface::performCommand` → `AirPort_BrcmNIC_Interface::performCommand` @`0x23f90` → `AirPort_BrcmNIC::apple80211Request` @`0x596a6`）会走到驱动自己的 `setAWDL_*`，但那样**不会更新 family 的 peer manager 状态**（sync 参数、election、channel sequence 都不同步），AWDL 仍不会真正起来。

补充：payload0 自己还有一条 **2 参数 `apple80211_ioctl_set(IO80211SkywalkInterface*, void* req)` @`0x92016`** 的入口（`movq %rdx,%r8; movq %rsi,%rcx; xor esi,esi; xor edx,edx; jmp 0x91ede`），它把 5 参数分派器的 `rsi/rdx`（interface/virtualInterface）**直接清零**。也就是说：即使请求完全在 payload0 内部走（native 客户端 / Skywalk IOUC 路径），只要落到这条入口，AWDL handler 仍然拿不到 `virtualInterface`，同样恒返 `0x2d`。这与 Bridge 的 Skywalk 端点问题是同一个根因的两种表现。

证据链：`Bridge.cpp:626-631`（分派三元组）、`payload0 0x87c5a`（`movq 0xb0(%r15)` + `testq → 0x2d`）、`payload0 0x92016`（2 参数入口清零 virt）、`payload0 0xa1604`（`IO80211P2PInterface::createPeerManager`：type==7→P2P peer manager；type 6→`IO80211VirtualInterface::createPeerManager`→`AWDLPeerManager`）、`IO80211VirtualInterface::createPeerManager @0xb14fe`（`cmpl $0x6,0xc0(%rdi)` 才建 AWDL peer manager）、`payload1 0x2dd88 AirPort_BrcmNIC::createVirtualInterface`（`type∈{3,4,5,6}`，type==6 用 `"awdl"` 前缀）。

### G2 — 27-only 的 AWDL 请求没有落点

14 个号（§2.2）。其中 ≤417 的是空槽、>417 的是越界，都会 `0x66`。这些号里 **payload1 驱动侧大多有实现**（`setAWDL_OOB_REQUEST`/`OOB_AUTO_REQUEST`/`DFSP_CONFIG`/`DFSP_UCSA_CONFIG`/`ENABLE_ROAMING`/`ADVERTISERS`/`MIN_RATE`/`SYNC_FRAME_TEMPLATE`/`TXCAL` 等），所以可转发到驱动表；`416 MI_BITMAP`、`432 AWDL_CONFIG`、`467 RTG_PEER_STATS`、`342 OOB_SEC_PAYLOAD` 在 payload1 中也无对应 → 只能明确不支持。

### G3 — ABI 长度/版本门禁

1. **长度**：type 223 需要 `0xea8`（27）但 payload0 要求 `0xa88`；343 需要 `0xfb8` 但 payload0 要求 `0xf88`。payload0 是 `jne → 0x16`，因此 27 按新结构发送必然 EINVAL。要么裁剪到旧长度（多余字段丢弃），要么在 SimpleBCM 里直接实现。
2. **版本**：payload1 的每个 `setAWDL_*` 开头都有 `version_check(struct->version, "setAWDL_XXX")`（`0x4106d`）：**version==1 通过、version==0 打 warning 后通过、其它 → 返 `0x16`**。若 27 用户态把版本号升到 2，所有 AWDL 配置都会 EINVAL。

### G4 — 观测盲区（导致前面几轮定位困难）

`SetHist/SetRes` 只在 `Bridge::command` 记录；AWDL 请求若走 native user client 或驱动表，就完全没有计数。`AWDLCoexistenceSelections` 也因补丁默认 `Disabled` 而无意义。**目前无法从运行期数据判定"27 到底有没有发 AWDL 请求"**，这是必须先补的仪表。

---

## 6. 最小可验证方案（驱动侧）

### 步骤 A：先判定"有没有请求"（不改行为）

在 `Bridge::command` 里为 `type ∈ [110..260] ∪ {343,416,417}` 增加：

```
AwdlSetHits[type] / AwdlGetHits[type]   // 计数
AwdlLastType / AwdlLastResult / AwdlLastSet
AwdlVirtNull      // rdx(或 virt) 为 NULL 的次数
AwdlPeerMgrNull   // 取到 virt 但 +0xb0 为 0 的次数
AwdlMetaCastFail  // safeMetaCast 失败次数
```

并把这些连同 `(uintptr_t)virt`、`(uintptr_t)skywalk`、`endpoint.kind` 发布成 ioreg 属性。

判据：
- 若 `Awdl*Hits` 全 0 且 `awdl0` 仍 0 RX → **27 用户态没发 AWDL 控制请求**，问题在 wifip2pd/sharingd 侧，驱动侧到此为止（需另开线查 wifip2pd）。
- 若 `AwdlHits` 有值且 `AwdlVirtNull` 同步增长 → 命中 **G1**，进步骤 B。

### 步骤 B：修正入口参数（针对 G1）

在 `Bridge::command` 的 set/get 分支前，对 AWDL 号段做参数修正：**把该端点对应的真实 `IO80211VirtualInterface`（`SB80211VirtualInterface` / `IO80211P2PInterface` 实例）作为 `rdx` 传入**，而不是 `NULL` 或伪对象。可用两种取法之一：

1. `endpoint.interface` 若本身 `metaCast("IO80211VirtualInterface")` 则直接用；
2. 否则从 controller 的虚拟接口链（`IO80211VirtualInterface` 的 `+0x208` 反向链，见 `createPeerManager @0xb159c`）或注册表里 `metaCast("IO80211P2PInterface")` 找到 role=="AirLink" 的那个实例。

预期：AWDL set 的返回从 `0x2d`/`0x13` 变成 `0`；`IO80211AWDLPeerManager` 的 `do_ioctl(0x803069c8, …)` 开始被调用；随后才可能看到 `SB80211AWDLPeer > 0`。

### 步骤 C：27-only 号的转换（针对 G2）

在 `Bridge::command` 中把 §2.2 的号映射到 **Classic 端点**（`classicCommand`），让驱动表处理：

| 27 type | 转发目标（payload1 handler） |
|---|---|
| 149 / 225 | `AirPort_BrcmNIC::setAWDL_OOB_REQUEST` `0x4dfc8` / `setAWDL_OOB_AUTO_REQUEST` |
| 151 | `setAWDL_SYNC_FRAME_TEMPLATE` |
| 213 | `setAWDL_MIN_RATE` `0x4f13c` |
| 224 | `setAWDL_ENABLE_ROAMING` |
| 226 | `setAWDL_TXCAL_PERIOD` |
| 229 | `setAWDL_ADVERTISERS` `0x4cbfa` |
| 262 / 263 | `setAWDL_DFSP_CONFIG` `0x4e8be` / `setAWDL_DFSP_UCSA_CONFIG` |
| 416 / 432 / 467 / 342 | 无对应 → 明确返回 `0x66`，**不要伪造 0** |

### 步骤 D：长度/版本适配（针对 G3）

- 223/343：把 27 结构裁剪到 payload0 期望的 `0xa88`/`0xf88` 再喂给 417 表（只保留前缀公共字段），或直接实现"clear statistics"（本质是把计数器清零）。
- 版本：在转发前打印 `struct->version`；若为 0/1 放行，其它记录 `AwdlVersionReject` 并明确返回 `0x16`（不要改写版本号伪装通过）。

### 验收判据（必须同时满足才叫修好）

1. `ioreg -rn SimpleBCM -l` 里 AWDL 号段的 `AwdlHits` 增长且 `AwdlLastResult = 0`；
2. `ifconfig awdl0` 之后 `netstat -I awdl0` 的 **Ipkts 从 0 变为非 0**（收到 AWDL 帧）；
3. `ioreg -w0 -l -p IOService` 的类计数里 **`SB80211AWDLPeer ≥ 1`**（发现了对端）；
4. `log show` 里 `version_check`/`setAWDL_*` 的 error 消失；
5. 最后才是 AirDrop 实际传输（sharingd 建立 CLink）。

> 注意 1–4 任意一条不成立都不能声称"AirDrop 修好"；`awdl0` 的 6 个 Opkts 是 IPv6 ND，不是 AWDL 业务流量。

---

## 7. 边界（不可伪造的部分）

1. **硬件/固件不是瓶颈（当前证据）**：payload1 里有完整的 AWDL 驱动栈——`wlc_awdl_*`、`awdlIfTxPacketsPending`、`wl_awdl_queued_pkt_upd`、`_AWDLsendmessagethreadfunction`、`AirPort_BrcmNIC::setAWDL_*`（30+ 个）、iovar 字符串 `"awdl"`、`AWDL LL Pool` 队列、`Interface awdl0` 的 IOReport 组。BCM43602 + 该固件在 macOS 26 上就是这套代码，因此**不能用"固件不支持 AWDL"来解释，也不能用返回 0 的假成功来掩盖**。
2. **确实存在的硬边界**：`AirPort_BrcmNIC` 是 26 时代的驱动，它的 AWDL 结构版本门禁只认 0/1。如果 27 用户态发的版本更高、或 27 新增的号（416/432/467/342）在 payload1 里没有实现，**只能明确返回不支持**；这两类不能通过"改返回值"解决。
3. **27 的 legacy(457) 表没有任何 AWDL handler**，所以不能拿 27 的 BSD ioctl 路径当"payload0 应该有"的依据；payload0 的 417 表已经是 AWDL 覆盖最全的一份。
4. **若 `Awdl*Hits` 恒为 0**：说明 27 的 AWDL 控制面根本没到驱动（wifip2pd 可能在与 27 的 IO80211Family 交互，或认为链路不可用而提前退出）。这时驱动侧任何改动都不解决问题，必须转到 wifip2pd/sharingd 侧取证。
5. **本报告未做任何部署**：以上方案均为离线候选，需在独立、可回退的 EFI/kext 配置里验证。

---

## 8. 未验证 / 待实测

1. `awdl0` 的 user client 到底是 **Skywalk 端点**、**Virtual 端点** 还是 **native（原始）客户端**——决定 G1 是否成立，用步骤 A 的 `AwdlVirtNull`/`endpoint.kind` 直接判定。
2. 27 用户态发 223/343 时的实际 `header->length`（推测为 0xea8/0xfb8，未抓包证实）。
3. 27 各 AWDL 结构的 `version` 字段实际值（0/1/2）。
4. `IO80211VirtualInterface::createPeerManager` 在 type=6 之外是否还有别的 AWDL 创建路径（例如 `IO80211P2PSupervisor`）。
5. 27 `skywalk+0x120` 指向对象的确切类型（`IO80211AWDLProtocol` 概率最高，但未反汇编其 vtable 核对）。
6. 27-only 号（149/229/262…）在 payload1 驱动表里是否按同一 type 号注册（handler 存在 ≠ 号相同），需按 `apple80211Request` 的分支表核对。

---

## 9. 复现命令（只读）

```sh
cd /Users/geek/Documents/Macintosh/simplebcm-r27

# payload0 的 AWDL 槽位与 handler
nm -arch x86_64 .research/extract/payload0.bin | grep -i awdl | head -50
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0x87c5a --stop-address=0x87d40 .research/extract/payload0.bin   # setAwdlSyncParams
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0x8d505 --stop-address=0x8d5d8 .research/extract/payload0.bin   # setAWDLUMIToPeer
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0x477b0 --stop-address=0x47890 .research/extract/payload0.bin   # AWDLPeerManager::setAWDLUMIToPeer
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0xb14fe --stop-address=0xb15b5 .research/extract/payload0.bin   # createPeerManager(type==6)

# 27 侧（先抽 Mach-O）
/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3 /tmp/sbawdl/kcextract.py
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0xffffff8001f8ad75 --stop-address=0xffffff8001f8add7 /tmp/sbawdl/IO80211Family27.macho  # 116
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0xffffff8001f8f32f --stop-address=0xffffff8001f8f390 /tmp/sbawdl/IO80211Family27.macho  # 417

# 驱动侧
nm -arch x86_64 .research/extract/payload1.bin | grep -E 'AirPort_BrcmNIC.*(set|get)AWDL'
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0x4106d --stop-address=0x41118 .research/extract/payload1.bin   # version_check
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0x4baa4 --stop-address=0x4bc40 .research/extract/payload1.bin   # setAWDL_SYNC_ENABLED

# 运行期（只读）
ioreg -rn SimpleBCM -l | grep -E 'SetHist|SetRes|UnsupportedRequests|LastRequest'
ioreg -w0 -p IO80211Plane | head -20
ifconfig awdl0; netstat -I awdl0
ioreg -w0 -l -p IOService | grep -oE '"(SB80211|IO80211)[A-Za-z]*"=[0-9]+' | grep -E 'AWDL|PeerManager|VirtualInterface'
```

---

## 10. 证据文件

- `simplebcm-r27/.research/extract/payload0.bin`（IO80211FamilyLegacy）
- `simplebcm-r27/.research/extract/payload1.bin`（AirPort_BrcmNIC）
- `/System/Library/KernelCollections/BootKernelExtensions.kc` 中的 `com.apple.iokit.IO80211Family`
- 本次临时产物（`/tmp/sbawdl/`）：`kcextract.py`、`IO80211Family27.macho`、`p0.dis`、`tables.py`、`awdl_handlers.py`
- 相关既有文档：`Docs/Reverse-Payload-SetTable-20261117.md`、`Docs/Adapt-27OnlySets-20261118.md`、`Docs/Analysis-20261117-driver-side.md`
