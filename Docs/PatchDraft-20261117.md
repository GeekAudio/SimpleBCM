# 补丁草稿：GoldenGate 请求流取证计数器（Patch A，纯诊断）

配套报告：`Docs/Analysis-20261117-driver-side.md`
状态：**草稿，未构建、未部署、未提交**。本文件只描述改动与验证方法。

约束回顾：
- 不修改 `/System`、`/Library`、EFI；不重启；不加载/卸载 kext。
- 不做"伪造成功"的行为补丁（§4 明确不推荐）。
- 所有新增属性/计数器只读，不影响现有请求语义。

---

## 0. 目的

当前能确定的只有：

- 27 airportd 每轮会发 `363/469/483/490/512/575` 六个 **Set**；
- 其中 5 个超出内嵌 `IO80211FamilyLegacy` 的 417 表，`363` 在表内但返回 0x66；
- 必需路径（`10/86/11/12/19/20/0x234`）不受这些类型影响；
- `DriverAvailabilityEvents=0` 是因为驱动从未 post 0x37，由 `GET_POWER(19)` 合成 + MonitorStart 重放替代。

还缺两个判定：

1. airportd 到底有没有发起扫描（`Set 10/86`）？
2. 六个 Set 返回 0x66 之后，airportd 是继续、还是立即退出（新实例）？

这两个问题用 ioreg 计数器即可回答，**不需要读 dmesg**（当前会话无 sudo）。

---

## 1. `SimpleBCM/WirelessABI.hpp`

在 `ScanResultRequest` 附近加入 27 请求号常量与表容量：

```diff
 constexpr uint32_t ScanResultRequest = 11;
+constexpr uint32_t ScanRequest = 10;
+constexpr uint32_t CurrentNetworkRequest = 103;
+constexpr uint32_t UsbHostNotificationRequest = 363;
+constexpr uint32_t OsFeatureFlagsRequest = 469;
+constexpr uint32_t ExternalPowerStateRequest = 483;
+constexpr uint32_t ProductInfoRequest = 490;
+constexpr uint32_t InfraEnumeratedRequest = 512;
+constexpr uint32_t OsEligibilityRequest = 575;
+// 内嵌 IO80211FamilyLegacy（payloads[0]）的 Get/Set 分发表容量。
+// 27 系统 IO80211Family 的 legacy 表为 590(Get)/457(Set)，不是同一个层。
+constexpr uint32_t LegacyHandlerTableCapacity = 417;
 constexpr uint32_t ScanMultipleRequest = 86;
```

注意 `ScanDoneEvent` 也是 10（事件号），与 `ScanRequest` 语义不同，命名不要混。

---

## 2. `SimpleBCM/Bridge.hpp`（`Counters`）

在 `powerAvailabilityEvents` 之后增加计数：

```diff
     uint64_t powerAvailabilityEvents;
+    uint64_t scanRequests;
+    uint64_t scanMultipleRequests;
+    uint64_t scanResultRequests;
+    uint64_t currentNetworkRequests;
+    uint64_t superRangeRequests;
+    uint64_t unsupportedRequests;
     uint32_t lastAssociationEventLength;
     uint32_t lastAssociationEventReadResult;
     uint32_t lastAvailabilityReadResult;
+    uint32_t lastUnsupportedRequest;
     uint64_t selectors[9];
```

`Counters` 只在内核内部使用，不构成用户态 ABI；顺序变化无兼容问题。

---

## 3. `SimpleBCM/UserClient.cpp`

### 3.1 计数（放在 `counters.commands` 自增之后，`UserClient.cpp:299` 附近）

```diff
     __atomic_fetch_add(&bcm::counters.commands, 1ULL, __ATOMIC_RELAXED);
     __atomic_store_n(&bcm::counters.lastRequest, static_cast<uint32_t>(request), __ATOMIC_RELAXED);
+    if (set && request == bcm::ScanRequest)
+        __atomic_fetch_add(&bcm::counters.scanRequests, 1ULL, __ATOMIC_RELAXED);
+    if (set && request == bcm::ScanMultipleRequest)
+        __atomic_fetch_add(&bcm::counters.scanMultipleRequests, 1ULL, __ATOMIC_RELAXED);
+    if (get && request == bcm::ScanResultRequest)
+        __atomic_fetch_add(&bcm::counters.scanResultRequests, 1ULL, __ATOMIC_RELAXED);
+    if (get && request == bcm::CurrentNetworkRequest)
+        __atomic_fetch_add(&bcm::counters.currentNetworkRequests, 1ULL, __ATOMIC_RELAXED);
+    if (static_cast<uint32_t>(request) > bcm::LegacyHandlerTableCapacity)
+        __atomic_fetch_add(&bcm::counters.superRangeRequests, 1ULL, __ATOMIC_RELAXED);
```

### 3.2 0x66 归因（`done:` 处，`UserClient.cpp:388`）

```diff
 done:
+    if (static_cast<uint32_t>(result) == 0x66U) {
+        __atomic_fetch_add(&bcm::counters.unsupportedRequests, 1ULL, __ATOMIC_RELAXED);
+        __atomic_store_n(&bcm::counters.lastUnsupportedRequest,
+                         static_cast<uint32_t>(request), __ATOMIC_RELAXED);
+    }
     if (probeRequest) {
```

### 3.3 probe 列表扩展 + 端点类型（`UserClient.cpp:290-298`）

```diff
-    const bool probeRequest = request == 10 || request == 86 || request == 11 ||
-        request == 69 || request == 103 || request == 207 || request == 15;
+    const bool probeRequest = request == bcm::ScanRequest || request == bcm::ScanMultipleRequest ||
+        request == bcm::ScanResultRequest || request == bcm::CardCapabilitiesRequest ||
+        request == 15 || request == 19 || request == 20 || request == 69 ||
+        request == bcm::CurrentNetworkRequest || request == 207 ||
+        request == bcm::UsbHostNotificationRequest || request == bcm::OsFeatureFlagsRequest ||
+        request == bcm::ExternalPowerStateRequest || request == bcm::ProductInfoRequest ||
+        request == bcm::InfraEnumeratedRequest || request == bcm::OsEligibilityRequest;
     if (probeRequest) {
-        DBGLOG("probe", "%s req=%u cmd=0x%08x len=%u out=%lu hdr=%u data=%02x ...",
-               endpoint.name, request, header->command, legacy.request.length,
+        DBGLOG("probe", "%s kind=%u req=%u cmd=0x%08x len=%u out=%lu hdr=%u data=%02x ...",
+               endpoint.name, static_cast<unsigned>(endpoint.kind), request,
+               header->command, legacy.request.length,
                static_cast<unsigned long>(outputSize), header->length,
                shadow[0], shadow[1], shadow[2], shadow[3],
                shadow[4], shadow[5], shadow[6], shadow[7]);
     }
```

`endpoint.kind` 决定请求走的是 `Classic → performCommand` 还是 `Virtual/Skywalk → apple80211_ioctl_set`（417 表路径），对定位"谁在发这些请求"很关键。

> 日志量：`CardCapabilitiesRequest(12)` 是最高频请求（实测 Commands≈65k），若日志过大，可暂时从 probe 列表去掉 12，只保留 `10/86/11/19/20/69/103/363/469/483/490/512/575`。

---

## 4. `SimpleBCM/Bridge.cpp`（发布）

### 4.1 计数器（`Bridge.cpp:805-819` 的 metrics 表）

```diff
         {"PowerAvailabilityEvents", &counters.powerAvailabilityEvents},
+        {"ScanRequests", &counters.scanRequests},
+        {"ScanMultipleRequests", &counters.scanMultipleRequests},
+        {"ScanResultRequests", &counters.scanResultRequests},
+        {"CurrentNetworkRequests", &counters.currentNetworkRequests},
+        {"SuperRangeRequests", &counters.superRangeRequests},
+        {"UnsupportedRequests", &counters.unsupportedRequests},
     };
```

### 4.2 单值属性（`Bridge.cpp:827-832` 附近）

```diff
     service->setProperty("LastAvailabilityReadResult", __atomic_load_n(&counters.lastAvailabilityReadResult, __ATOMIC_RELAXED), 32);
+    service->setProperty("LastUnsupportedRequest", __atomic_load_n(&counters.lastUnsupportedRequest, __ATOMIC_RELAXED), 32);
+    if (activeABI) {
+        service->setProperty("ScanResultSize", static_cast<uint64_t>(activeABI->scanResultSize), 32);
+        service->setProperty("CapabilitySize", static_cast<uint64_t>(activeABI->capabilitySize), 32);
+        service->setProperty("DriverAvailableSize", static_cast<uint64_t>(activeABI->driverAvailableSize), 32);
+        service->setProperty("FilterMonitorEvents", static_cast<uint64_t>(activeABI->filterMonitorEvents), 32);
+    }
```

> 注意：`activeABI` 为 `const UserABI *`（`Bridge.cpp:97`），可能为 null；上面的判空必须保留。

---

## 5. 验证步骤（需用户执行构建/部署/重启，本会话不做）

1. 用 Debug 配置构建（`DEBUG=1`，`DBGLOG` 生效；`SimpleBCM.cpp:143-147` 会在 Debug 下把 `simpleBCMDebug` 置 true）。
2. 记录产物 sha256；部署到 `EFI/OC/Kexts/SimpleBCM.kext`（父代理既有流程），重启。
3. 采集：

```sh
ioreg -rn SimpleBCM -l | grep -E 'ScanRequests|ScanMultipleRequests|ScanResultRequests|CurrentNetworkRequests|SuperRangeRequests|UnsupportedRequests|LastUnsupportedRequest|ScanResultSize|CapabilitySize|DriverAvailableSize|FilterMonitorEvents'

log show --last 5m --style compact | grep -E 'SimpleBCM: probe'
```

4. 判定矩阵：

| 观测 | 结论 |
| --- | --- |
| `ScanRequests` / `ScanMultipleRequests` 增长 | 扫描确实发起过；菜单/结果问题转向结果解析或事件 |
| 二者持续为 0，`SuperRangeRequests` 增长，且每次增长后 `Opens` 增加 | 强烈支持"airportd 在扫描前退出/重建"；下一步查 512 与崩溃 |
| 二者持续为 0，但 `Opens` 不增加 | 请求不再到达（客户端未打开或 selector 变化），另查 |
| `LastUnsupportedRequest` ∈ `{363,469,483,490,512,575}` | 0x66 归因正确；结合出现顺序看 512 是否紧邻退出 |
| `probe` 日志中 `kind` 固定为 1/2（Virtual/Skywalk） | 说明这些 Set 走 417 表路径，与 §2.2 的静态判断一致 |

5. 回归检查：`ScanRecords`、`LastResult`、`Notifications` 与改动前同一启动周期对比；改动只增加属性与计数，不应出现新的 `CommandErrors` 增长模式，也不应影响 `Selector0 == Commands` 的等式。

---

## 6. 不推荐/不纳入的改动

### 6.1 对 27-only Set 本地返回成功

```
// 不要合入
if (set && (request == 469 || request == 483 || request == 490 || request == 512 || request == 575))
    result = kIOReturnSuccess;
```

理由：伪造成功会掩盖能力缺口，且 512 `setINFRA_ENUMERATED` 的语义未验证；若 airportd 依赖真实效果，可能造成更隐蔽的状态错乱。违反"根因优先"约束。

### 6.2 把 103 再映射到 11

```
// 不要合入
if (get && request == 103) legacy.request.type = 11;
```

理由：103 = `CURRENT_NETWORK`，27 期望 `apple80211_scan_result`（0x8E8）承载"当前 BSS"；映射到 11 返回的是"最后一次扫描记录"，语义错误（`getCurrentNetwork` 在 OCLP Legacy 里还是 stub，见报告 §2.4）。

### 6.3 修改内嵌 legacy 表

扩表/加 handler 需要改内嵌镜像代码，风险最高；除非确认是必须功能，不做。

---

## 7. 真修复方向（非小改，未实施）

1. **27-only Set 转发**：解析 27 系统 `IO80211Family` 的 internal handler（`apple80211setOS_FEATURE_FLAGS`、`setEXTERNAL_POWER_STATE`、`setPRODUCT_INFO`、`setINFRA_ENUMERATED`、`setOS_ELIGIBILITY`、`setUSB_HOST_NOTIFICATION`），在 bridge 里按 27 结构转发。前提：确认这些符号可导出/可调用、接口对象类型正确、结构体布局。
2. **103 CURRENT_NETWORK**：按 27 `apple80211_scan_result`（0x8E8）布局，从驱动关联状态合成当前 BSS 记录；需要先逆向字段布局。
3. **扩展 legacy 分派**：把 417 表扩到 27 的 590/457 语义，等价于重写注入层，不建议。

上述任一项都需要先完成本文件的诊断补丁，拿到"扫描是否发起 / 512 是否紧邻退出"的证据，再决定投入。
