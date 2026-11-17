# 关联补丁草稿（macOS 27 / Golden Gate）

配套报告：`Docs/Reverse-Assoc-CodePath-20261117.md`
代码基线：`simplebcm-r27`，分支 `wifi-assoc-probe`，HEAD `93df845`
状态：**A1/A2/A3 已写入工作区源码；A2 需重新生成 payload 才生效；B1/B2 已实现且默认关闭（`-sbcmggassoc`）；未构建/未部署/未重启/未 commit。**

> 前置结论（见报告 §0/§3）：
> 1. 27 的关联 set 号仍是 **20**，get 结果号 **21**；**不要**做 254→20 映射（set 254 在所有 27 表里都是空槽）。
> 2. 27 的 associate 数据长度是 **0x290**（27 `setASSOCIATE`/`setAssociateRequest` 两处都是），
>    现有 `GoldenGateABI.associateSize=0x38C` 与 `prepareAssociate` 的 0x38C→0x224 转换不适用于它。
> 3. 实测 `AssociationRequests=0`：当前没有 type 20 到达被包装的用户客户端。
>    所以本补丁分两段：**A 先做可观测性**（现在有意义），**B 再做 0x290 转换**（以 A2 观测到驱动收到关联为前提）。
> 4. 不修改 `/System`、`/Library`、EFI；不构建/部署；不 commit/push。

## 实施状态（2026-11-17，工作区，未构建/未部署）

已写入源码（**未 commit/push**）：

- `SimpleBCM/Bridge.hpp`：新增关联/Set 历史/驱动 hook/事件 kind 计数与 `Bridge::goldenGateAssociateEnabled()`；
  0x290 样本窗口为 32 words（0x1D8..0x257）。
- `SimpleBCM/UserClient.cpp`：A1 持久计数 + 16 条 Set 历史（`AssociateLengthMismatch` 统计所有
  `length != abi.associateSize` 的 set+20，含 0x290）；B1 的 0x290 识别、32-word 样本记录与
  `prepareAssociateGoldenGate` 调用；默认路径仍拒绝 0x290，不修改缓冲。
- `SimpleBCM/Bridge.cpp`：A2 的 `countSetAssociate` 可选 route（失败不 disable bridge）；
  A3 的 `PendingEvent.kind` 与按 kind 的事件计数；新增 ioreg 属性。
- `SimpleBCM/WirelessABI.hpp`：`GoldenGateAssociateSize=0x290`、`GoldenGateNativeAssociateSize=0x38C`、
  `GoldenGateAssociateGap=0x1FC`、27 侧校验偏移常量、`prepareAssociateGoldenGate`（`-sbcmggassoc` 才启用转换）；
  增加 gap/样本窗口/偏移的编译期断言。
- `Tools/profiles.py`：把 `__ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data`
  加入 `SYMBOLS["AirPort"]`（named/`findSymbol`）与 `ROUTE_SYMBOLS["AirPort"]`（route prefix），
  使下一次 payload 生成包含 A2 所需的符号与 route。
- `Tools/verify.py`：新增 0x290→0x224 的字段级/边界向量（默认关闭不改缓冲、gap 还原、尾部清零、
  ssid/rsn/pmk/bssid/scope 越界拒绝）。

验证状态：

- `clang++ -std=c++14 -fsyntax-only -target x86_64-apple-macosx12.0 -mkernel -I .../MacKernelSDK/Headers`
  对 `UserClient.cpp`、`Bridge.cpp` 通过；`python3 -m py_compile Tools/profiles.py Tools/verify.py` 通过。
- `python3 Tools/check.py` 与 `python3 Tools/native_references.py verify` 通过。
- `Tools/verify.py` 的 HOST 校验程序在去掉 ASan（a2x 环境限制）后编译并运行通过，含新增 0x290 向量；
  UBSan-only 也通过。**这不是完整构建**：没有运行 `Tools/build.py`/`Tools/embed.py`，
  没有重新生成 payload/Profiles，没有部署/重启。
- A2 在当前已部署产物上不会生效（`DriverAssociateHookReady=0`），因为 route descriptor 只在重新生成 payload 后存在。
- B 的默认行为是“记录 0x290 样本并拒绝”，只有 boot-arg `-sbcmggassoc` 才执行 0x290→0x224 转换；
  gap 位置（0x1FC vs 0x1DC）仍未实测确认。

---

## A. 诊断补丁（A1/A3 已按草稿写入源码）

### A1. 在 `runCommand` 里加持久计数与 Set 历史

**依据**

- `AssociationRequests` 只在 `UserClient.cpp:313-314` 递增，覆盖 type 20，位于所有门禁之前；
  它不能告诉你“长度是多少”“最近一次 set 是什么”“有没有 254”。
- `ReqHist` 只有 16 项（`Bridge.cpp:846-854`），而本会话两次读取 `Commands` 4196→8160（约 4–5 条/秒），
  16 项只覆盖约 3–4 秒；单次关联尝试会被 WoW/查询流量挤出。
- 需要一个新的持久字段 `LastAssociateLength` 和“type 20 长度不匹配”计数，
  这样即使请求被 `UserClient.cpp:320` 拒绝，也能在重启后的 ioreg 里看到。

**改动 1：`SimpleBCM/Bridge.hpp`，`struct Counters` 末尾（`requestHistoryCount` 之后）追加：**

```cpp
    /* 11-17 · assoc diagnostics: the 16-entry request history only covers a few seconds at
       the observed 4-5 commands/s, and a single ASSOCIATE(20) attempt can be evicted before
       ioreg is read. These counters are persistent for the boot and are published by name. */
    uint64_t associateLengthMismatch;   // set+20, header->length != abi.associateSize
    uint32_t lastAssociateLength;       // last set+20 header->length (before any gate)
    uint64_t setHistoryCount;
    uint32_t setHistoryNext;
    uint32_t setHistory[16];            // request type of the last 16 Set commands
    uint32_t setHistoryLength[16];      // header->length for those commands
    uint32_t setHistoryResult[16];      // IOReturn for those commands
    uint32_t lastSetType;
    uint32_t lastSetLength;
    uint32_t lastSetResult;
    /* A3 · event-9 diagnostics (see §A3) */
    uint32_t lastAssociationEventKind;
    uint64_t associationEventsClassic;
    uint64_t associationEventsVirtual;
    uint64_t associationEventsSkywalk;
```

> 位置只影响结构体布局，不影响外部 ABI；`publish()` 是按名字 `setProperty` 的。

**改动 2：`SimpleBCM/UserClient.cpp`，`runCommand`。**

在 `historySlot`（第 308 行）旁边加一个局部 slot：

```cpp
    uint32_t setSlot = UINT32_MAX;
```

在 `associationRequests` 计数（第 313-314 行）之前/之后加：

```cpp
    if (set) {
        setSlot = __atomic_fetch_add(&bcm::counters.setHistoryNext, 1u, __ATOMIC_RELAXED) & 15u;
        __atomic_store_n(&bcm::counters.setHistory[setSlot], static_cast<uint32_t>(request), __ATOMIC_RELAXED);
        __atomic_store_n(&bcm::counters.setHistoryLength[setSlot], header->length, __ATOMIC_RELAXED);
        __atomic_fetch_add(&bcm::counters.setHistoryCount, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&bcm::counters.lastSetType, static_cast<uint32_t>(request), __ATOMIC_RELAXED);
        __atomic_store_n(&bcm::counters.lastSetLength, header->length, __ATOMIC_RELAXED);
    }
    if (associate) {
        __atomic_fetch_add(&bcm::counters.associationRequests, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&bcm::counters.lastAssociateLength, header->length, __ATOMIC_RELAXED);
        if (header->length != abi.associateSize)
            __atomic_fetch_add(&bcm::counters.associateLengthMismatch, 1ULL, __ATOMIC_RELAXED);
    }
```

> 注意：原来第 313-314 行的 `if (associate) associationRequests++` 要合并进上面的块，避免重复计数。
> `lastAssociationResult`/`associationAccepted` 仍在第 414-418 行，不用动。

在 `done:` 标签之后、`bzero(packet, ...)` 之前加：

```cpp
    if (setSlot != UINT32_MAX) {
        __atomic_store_n(&bcm::counters.setHistoryResult[setSlot], static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        __atomic_store_n(&bcm::counters.lastSetResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
    }
```

**改动 3：`SimpleBCM/Bridge.cpp`，`publish()`（第 815-858 行附近）追加属性。**

```cpp
    service->setProperty("AssociateLengthMismatch",
        __atomic_load_n(&counters.associateLengthMismatch, __ATOMIC_RELAXED), 64);
    service->setProperty("LastAssociateLength",
        __atomic_load_n(&counters.lastAssociateLength, __ATOMIC_RELAXED), 32);
    service->setProperty("SetCount",
        __atomic_load_n(&counters.setHistoryCount, __ATOMIC_RELAXED), 64);
    service->setProperty("LastSetType",
        __atomic_load_n(&counters.lastSetType, __ATOMIC_RELAXED), 32);
    service->setProperty("LastSetLength",
        __atomic_load_n(&counters.lastSetLength, __ATOMIC_RELAXED), 32);
    service->setProperty("LastSetResult",
        __atomic_load_n(&counters.lastSetResult, __ATOMIC_RELAXED), 32);
    for (unsigned i = 0; i < 16; ++i) {
        char name[24];
        snprintf(name, sizeof(name), "SetHist%u", i);
        service->setProperty(name, __atomic_load_n(&counters.setHistory[i], __ATOMIC_RELAXED), 32);
        snprintf(name, sizeof(name), "SetLen%u", i);
        service->setProperty(name, __atomic_load_n(&counters.setHistoryLength[i], __ATOMIC_RELAXED), 32);
        snprintf(name, sizeof(name), "SetRes%u", i);
        service->setProperty(name, __atomic_load_n(&counters.setHistoryResult[i], __ATOMIC_RELAXED), 32);
    }
```

**验收/判定（A1）**

- 一次真实“连接 Wi-Fi”后：
  - `AssociationRequests > 0` 且 `LastAssociateLength == 0x290` 且 `LastAssociationResult == 0xE00002C2`
    → 用户客户端收到 0x290，被长度门禁拒绝；B 是下一道修复。
  - `AssociationRequests == 0` 且 `LastSetType` 从未出现 20 → 用户客户端没收到关联；B 先不做。
  - `AssociateLengthMismatch > 0` 但 `AssociationRequests == 0` 不可能（同一条件）；两者应一致。
- 风险：只增加计数器和属性，不改变控制流；对扫描/事件无影响。

---

### A2. 在内嵌 `AirPort_BrcmNIC::setASSOCIATE` 入口挂钩计数（决定性）

**依据**

- 现有 `AssociationRequests` 只能证明“没有 type 20 进被包装的用户客户端”。
- `Bridge.cpp:538-560` 的 Classic 转发最终进 `apple80211RequestIoctl` → 驱动；
  但 airportd 的 legacy ifnet ioctl（`SIOCSA80211`）也能直接进同一个函数，**不经过** `BCM80211UserClient`。
- 内嵌驱动的 `setASSOCIATE` 是**所有路径的终端**：只要驱动真的收到关联，就会调用它。
  在它入口加计数，可以一次区分“没发 / 走了用户客户端 / 走了 ifnet / 驱动收了但没完成”。
- 符号已在 payload1 中确认：`__ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data`
  （`payload1.bin @0x42b8e`）。

**改动 1：`SimpleBCM/Bridge.cpp` 顶部（`using PerformCommand` 附近，第 76-81 行）加：**

```cpp
using SetAssociate = int (*)(IOService *, OSObject *, void *);
static SetAssociate originalSetAssociate;

static int countSetAssociate(IOService *self, OSObject *object, void *data) {
    __atomic_fetch_add(&counters.driverAssociateRequests, 1ULL, __ATOMIC_RELAXED);
    if (data) {
        uint32_t word = 0;
        memcpy(&word, data, sizeof(word));
        __atomic_store_n(&counters.lastDriverAssociateWord, word, __ATOMIC_RELAXED);
    }
    return originalSetAssociate ? originalSetAssociate(self, object, data) : static_cast<int>(0x66);
}
```

> 如果 `originalSetAssociate` 为空（route 失败但 hook 被调用），返回 0x66 而不是崩溃；
> 正常情况下 route 成功后才可能被调用。

**改动 2：`SimpleBCM/Bridge.cpp`，`patchImage` 的 index==1 分支（第 739-748 行）之后，追加可选 route。**

```cpp
        /* 11-17 · decisive association probe: count every association that actually reaches the
           embedded driver, regardless of whether it came from the SimpleBCM user client or from
           airportd's legacy ifnet ioctl path. Optional: a missing symbol must not disable the bridge. */
        KernelPatcher::RouteRequest associateRoute = {
            "__ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data",
            countSetAssociate, originalSetAssociate};
        if (patcher.routeMultipleLong(index, &associateRoute, 1, address, size))
            __atomic_store_n(&counters.driverAssociateHookReady, 1u, __ATOMIC_RELAXED);
        else
            patcher.clearError();
```

> `routeMultipleLong(index, RouteRequest*, size_t, address, size)` 是非模板重载（`Patcher.hpp:43`）；
> 失败时只清错误，不 `reject()`。这样即使某个 backend/版本没有该符号，也不影响既有功能。
> 如果维护者希望严格验证 hook 一定装上，可把 `driverAssociateHookReady==0` 作为 DEBUG 构建的断言，
> 但 Release 不应因它禁用整个 bridge。
>
> **重要前提（2026-11-17 复核）**：`routeMultipleLong` 只 patch `image.payload->routes` 里已有
> `RoutePrefix` 的符号（`Patcher.cpp:29-40` 用 `prefix < 14` 拒绝未列出的符号）。当前
> `Tools/profiles.py` 的 `ROUTE_SYMBOLS["AirPort"]` 只有 `getHARDWARE_VERSION`/`getLOCALE`
> （`Tools/profiles.py:128-131`），**没有 `setASSOCIATE`**。因此直接加 A2 route 会返回 false、
> `DriverAssociateHookReady=0`，不破坏 bridge，但也拿不到计数。
> 要让它生效，需要把 `__ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data`
> 同时加进 `SYMBOLS["AirPort"]`（`embed.py` 的 named 符号表/`findSymbol`）和
> `ROUTE_SYMBOLS["AirPort"]`（route prefix 表），并用完整 `.research/binaries` + Xcode 重新生成 payload/Profiles
> （本会话没有这些依赖，也没有构建）。在那之前 A2 是“代码就绪、运行期未生效”。

**改动 3：`Bridge.hpp` Counters 追加（与 A1 同一次改动）：**

```cpp
    uint64_t driverAssociateRequests;
    uint32_t driverAssociateHookReady;
    uint32_t lastDriverAssociateWord;
```

**改动 4：`Bridge.cpp::publish()`：**

```cpp
    service->setProperty("DriverAssociateRequests",
        __atomic_load_n(&counters.driverAssociateRequests, __ATOMIC_RELAXED), 64);
    service->setProperty("DriverAssociateHookReady",
        __atomic_load_n(&counters.driverAssociateHookReady, __ATOMIC_RELAXED), 32);
    service->setProperty("LastDriverAssociateWord",
        __atomic_load_n(&counters.lastDriverAssociateWord, __ATOMIC_RELAXED), 32);
```

**验收/判定（A2）**

| `DriverAssociateHookReady` | `DriverAssociateRequests` | 判定 |
| --- | --- | --- |
| 0 | — | hook 未装（符号缺失/route 失败）；先修 hook，不要把 0 当“没关联” |
| 1 | 0 | 驱动从未收到关联；§6 前置/用户态问题 |
| 1 | ≥1，`AssociationRequests=0` | 关联走了 ifnet/绕过路径；需要在控制器/驱动边界转换，而不是只改用户客户端 |
| 1 | ≥1，`AssociationRequests≥1` | 用户客户端路径到达驱动；结合 `LastAssociateLength` 决定 B |

> 风险：多一个函数入口 route；hook 是纯计数 + 透传，语义不变。
> 需要在 Debug/Release 两种构建、Tahoe/Original 两个 backend 上验证 `HookReady`（Tahoe 应 1；Original 若符号不存在应为 0 且 bridge 仍 ready）。

---

### A3. 记录事件 9 的 endpoint kind（只记录，不改变转换）

**依据**

- `captureJoinEvent` 把 endpoint 硬编码为 `InterfaceKind::Classic`（`Bridge.cpp:357`）；
- `PendingEvent` 没有 kind 字段（`Bridge.cpp:50-60`），`queueEvent` 知道 kind（参数），但 drain 时丢失；
- 27 可能通过 Virtual/Skywalk 投递事件 9（`Bridge.cpp:706-708` 三个 hook 都覆盖）。

**改动（最小）**

1. `Bridge.cpp` `struct PendingEvent` 增加 `InterfaceKind kind;`，`queueEvent` 里 `entry.kind = kind;`。
2. 在 `queueEvent` 的 `message == AssociationDoneEvent` 分支（第 469-472 行）按 kind 加三个计数器：

```cpp
    if (message == AssociationDoneEvent) {
        __atomic_fetch_add(&counters.associationEvents, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&counters.lastAssociationEventLength, static_cast<uint32_t>(length), __ATOMIC_RELAXED);
        __atomic_store_n(&counters.lastAssociationEventKind, static_cast<uint32_t>(kind), __ATOMIC_RELAXED);
        if (kind == InterfaceKind::Classic)
            __atomic_fetch_add(&counters.associationEventsClassic, 1ULL, __ATOMIC_RELAXED);
        else if (kind == InterfaceKind::Virtual)
            __atomic_fetch_add(&counters.associationEventsVirtual, 1ULL, __ATOMIC_RELAXED);
        else
            __atomic_fetch_add(&counters.associationEventsSkywalk, 1ULL, __ATOMIC_RELAXED);
    }
```

3. 发布 `LastAssociationEventKind`、`AssociationEventsClassic/Virtual/Skywalk`。

> **不要**在这一步改 `captureJoinEvent` 的转换条件；先拿到“事件 9 是否产生、从哪个 kind、payload 多长”。
> 如果实测 `AssociationEvents>0` 且 kind 不是 Classic，再按 B3 处理。

---

## B. 27 0x290 关联请求处理（以 A2 观测到关联为前提）

### B1. 长度门禁与调用点（最小改动）

**依据**：27 的 associate 数据是 0x290；现有两处门禁都要求 0x38C（`UserClient.cpp:320`、`WirelessABI.hpp:287`）。

**改动 1：`WirelessABI.hpp`，在 `LegacyAssociateSize` 附近加常量（不要改 `GoldenGateABI.associateSize`）：**

```cpp
constexpr size_t GoldenGateAssociateSize = 0x290;
```

> 为什么不动 `GoldenGateABI.associateSize`：
> ①`Tools/verify.py` 和 `Docs/Control-Codecs.json` 的现有向量是围绕 0x38C/0x384/0x358 的；
> ②0x38C 路径仍是“27 如果沿用 Tahoe 结构”的合法分支，不应被删；
> ③把 0x290 作为显式的第二分支，便于 A/B 和回滚。

**改动 2：`UserClient.cpp`，`associate` 判定之后（第 287 行）：**

```cpp
    const bool associate = set && request == bcm::AssociateRequest;
    const bool goldenGateAssociate = associate && abi.kernel == 27 &&
        header->length == bcm::GoldenGateAssociateSize;
```

**改动 3：第 320 行的门禁：**

```cpp
        (associate && !goldenGateAssociate && header->length != abi.associateSize) ||
```

**改动 4：第 347 行的调用：**

```cpp
    if (associate && goldenGateAssociate &&
        !bcm::prepareAssociateGoldenGate(legacy.request, shadow, capacity, abi))
        goto done;
    if (associate && !goldenGateAssociate &&
        !bcm::prepareAssociate(legacy.request, shadow, capacity, abi))
        goto done;
```

> 注意顺序：`prepareAssociateGoldenGate` 成功后会把 `request.length` 改成 0x224，
> 所以后面的 `Bridge::command`/`produced` 逻辑与现有路径一致。

### B2. 转换器：**不要**直接拿 0x290 跑 0x38C 的偏移

**依据**：`prepareAssociate` 的字段偏移来自 Tahoe native 0x38C（auth 8/12、ssid 0x10、key 0x3C、
rsn 0xD0、pmk 0x1D8、bssid 0x206、scope 0x244）；27 的校验点是 0x10/0xD0/0x1D8/**0x202**/**0x240**，
bssid/scope 各小 4。直接跑现有转换会读错 `buffer[0x206]` 和 `buffer[0x244]`。

**候选 1（推荐先验证）：把 27 的 0x290 还原成 Tahoe native 0x38C，再复用 `prepareAssociate`。**

假设 27 = Tahoe native 在 PMK 之后删掉 4 字节（所以 bssid 0x206→0x202、scope 0x244→0x240），
则候选插入点是 0x1FC（PMK 之后的 4 字节），或 0x1DC（PMK 之前）。
**这两个候选必须用一次真实 0x290 样本区分**：看 `[0x1D8,0x250)` 的字节，
特别是 PMK（0x1DC..0x1FB）是否整体前移 4 字节。

```cpp
// WirelessABI.hpp
// 27's associate buffer is 0x290. Its validated field offsets (0x10/0xD0/0x1D8/0x202/0x240)
// imply a 4-byte gap relative to the 0x38C Tahoe layout; the gap position is a hypothesis
// until a live 0x290 sample is captured (see PatchDraft A1/A2).
constexpr size_t GoldenGateAssociateGap = 0x1FC;   // candidate; alternative 0x1DC
constexpr size_t GoldenGateTag = 0x38C;

inline bool prepareAssociateGoldenGate(Request &request, uint8_t *buffer, size_t capacity,
                                       const UserABI &abi) {
    if (!buffer || capacity < GoldenGateAssociateSize || request.length != GoldenGateAssociateSize)
        return false;
    // 27 handler's own validation points:
    if (buffer[0x10] > 32 || readUInt32(buffer + 0x1D8) > 32 || buffer[0x202] > 3)
        return false;
    uint8_t native[GoldenGateTag] {};
    memcpy(native, buffer, GoldenGateAssociateGap);
    memcpy(native + GoldenGateAssociateGap + 4, buffer + GoldenGateAssociateGap,
           GoldenGateAssociateSize - GoldenGateAssociateGap);
    Request scratch = request;
    scratch.length = GoldenGateTag;
    if (!prepareAssociate(scratch, native, sizeof(native), abi))
        return false;
    memcpy(buffer, native, LegacyAssociateSize);
    for (size_t offset = LegacyAssociateSize; offset < GoldenGateAssociateSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyAssociateSize;
    return true;
}
```

> 这是草稿骨架。工作区的**实际实现**（`WirelessABI.hpp` 的 `prepareAssociateGoldenGate`）在此基础上：
> - 增加 `abi.kernel == 27 && abi.associateSize == 0x38C` 门禁和 `GoldenGateNativeAssociateSize` 常量；
> - 用 27 legacy handler 的五个校验点（ssid<33、rsn<258、pmk<33、bssid≤3、scope<38）预检，并在
>   `convert=false` 时直接拒绝、不修改缓冲；
> - 用编译期断言保证 gap 还原、样本窗口和偏移都在 0x290/0x38C 范围内；
> - 增加 `Tools/verify.py` 向量：0x290→0x224 的 gap 还原、尾部清零、默认关闭不改缓冲、
>   ssid/rsn/pmk/bssid/scope 越界拒绝（HOST 校验已在本地无 ASan 环境通过；ASan runtime 在 a2x 下崩溃，
>   见构建报告的环境限制）。
>
> **仍未验证**：真实 27 客户端是否按 0x290 发 set 20、gap 究竟在 0x1FC 还是别处、0x290 的完整字段布局。
> 这些只能由 A1/A2 的运行期样本回答；因此转换仍由 `-sbcmggassoc` 控制，默认关闭。

**候选 2（更保守）：不转换，只记录并返回明确的“不支持”错误。**

如果拿不到样本，或不想在未验证布局时冒险：

```cpp
inline bool prepareAssociateGoldenGate(Request &request, uint8_t *buffer, size_t capacity,
                                       const UserABI &abi) {
    (void)buffer; (void)capacity; (void)abi;
    (void)request;
    return false;   // caller returns kIOReturnBadArgument; LastAssociateLength + A2 count provide evidence
}
```

这不会改善功能，但能让失败路径与“长度门禁”区分开（A1 的 `AssociateLengthMismatch`/`LastAssociateLength` 已够）。

### B3. 事件 9 的 27 转换（仅在 A3 观测到事件后）

- 若 A3 显示 `AssociationEvents>0` 且 `lastAssociationEventKind == Classic` 且 `length==0`：
  现有 `captureJoinEvent` 路径可用；继续验证 `encodeJoinStatus` 的 0x1D4 是否被 27 用户态接受。
  不要在未验证前改 `GoldenGateABI.joinStatusSize`。
- 若 `length != 0`：先原样透传（现状），发布 `LastAssociationEventLength`；
  用 27 的 `apple80211_join_status` 消费者（用户客户端/事件 pipe）确认期望尺寸后再加转换。
- 若 `kind != Classic`：把 `PendingEvent.kind` 传给 `captureJoinEvent`（A3 已加字段），
  并在转换前确认 `readEventValue` 的端点类型；不要继续硬编码 Classic。
  `entry.interface` 目前只在 Classic 且空 payload 时设置（`Bridge.cpp:483-486`），
  非 Classic 需要先补接口指针/名称，再谈转换。

---

## C. 明确不做的改动

1. **不做 254→20 映射。** `set 254` 在 payload0、27 新表、27 legacy、27 internal 四张表里都是空槽；
   255 才是 BTCOEX/UCM。映射只会把 BTCOEX 配置误当关联。
2. **不改 `GoldenGateABI.associateSize` 为 0x290 而不改转换。** 会破坏现有 0x38C 分支/CI 向量，
   且 0x290 走 0x38C 偏移必然错位。
3. **不在用户态重试/重启服务/伪造请求。** 违反工作区根因优先约束。
4. **不修改系统文件/框架/EFI。**
5. **不用 `header->length` 强行改写为 0x38C 来“骗过”门禁。** 数据布局不会因此变对。

---

## D. 验证方法

### D.1 构建/CI（维护者执行，本会话不执行）

```sh
python3 -B Tools/check.py
python3 -B Tools/build.py build --configuration Debug
python3 -B Tools/build.py build --configuration Release
python3 -B Tools/build.py analyze --configuration Release
```

- A1/A2/A3 是加法，不改变既有 codec 向量；CI 应保持通过。
- B2 必须在 `Tools/verify.py` 增加：
  - 0x290 样本 → 0x224 的字段级断言（auth lower/upper、ssid、key、rsn、pmk、bssidCount、scope）；
  - 0x290 长度不足/超长/字段越界的拒绝断言；
  - `GoldenGateABI` 的 0x38C 旧向量仍通过（不能只测 0x290）。
- ASan/UBSan 下跑转换器（`Tools/build.py` 已对重定位/编解码做 sanitizer 验证，新增函数要进入同一套 harness）。

### D.2 运行期（重启后，由维护者决定）

```sh
ioreg -rn SimpleBCM -l | grep -E 'AssociationRequests|LastAssociateLength|AssociateLengthMismatch|GoldenGateAssociateRequests|GoldenGateWord|LastGoldenGateBssidCount|LastGoldenGateScope|DriverAssociateRequests|DriverAssociateHookReady|LastDriverAssociateWord|AssociationAccepted|LastAssociationResult|AssociationEvents|LastAssociationEventKind|LastAssociationEventLength|SetCount|LastSetType|LastSetLength|LastSetResult|SetHist|SetLen|SetRes|DroppedEvents|Rejects|LastRequest|LastResult'
```

判定树见配套报告 §8.2。关键几条：

- `DriverAssociateHookReady=1` 才相信 `DriverAssociateRequests=0` 的含义；
- `AssociationRequests>0 && LastAssociateLength=0x290 && LastAssociationResult=0xE00002C2`
  → 启用 B；
- `DriverAssociateRequests>0 && AssociationRequests=0` → ifnet 路径，B 需要放到控制器/驱动边界；
- `AssociationEvents>0` 后才验证 B3；此时看 `LastAssociationEventKind`/`Length`。

### D.3 回滚

- A1/A3 只加计数器/属性，回滚 = 删除字段与发布；无行为影响。
- A2 的 hook 是可选 route；若 `HookReady=0`，行为与现在完全一致。
  若 hook 导致问题，删除 index 1 的可选 route 即可（不影响既有 bridge ready 条件）。
- B 建议用 boot-arg 开关（例如 `-sbcmggassoc`）做 A/B：
  `PE_parse_boot_argn` 已有先例（`Bridge::initialize` 的 `-sbcmawdlcc`/`-sbcmdma`，`Bridge.cpp:759-760`）。
  默认关闭，验证通过后再默认开启。

---

## E. 代码位置索引

| 改动 | 文件:行 | 说明 |
| --- | --- | --- |
| `associate` 判定 | `UserClient.cpp:287` | 保持 20 |
| `associationRequests` 计数 | `UserClient.cpp:313-314` | A1 在这里加长度/历史 |
| 长度门禁 | `UserClient.cpp:315-323` | B1 改 320 |
| `prepareAssociate` 调用 | `UserClient.cpp:347-348` | B1 分支 |
| associate 结果/接受 | `UserClient.cpp:414-418` | 不变 |
| `prepareAssociate` | `WirelessABI.hpp:286-314` | B2 新函数在旁边 |
| `GoldenGateABI` | `WirelessABI.hpp:86-88` | 不改 0x38C；加 0x290 常量 |
| `LegacyAssociateSize` | `WirelessABI.hpp:40` | 0x224 |
| 事件计数 | `Bridge.cpp:469-472` | A3 |
| 事件转换条件 | `Bridge.cpp:483-486` | B3 前不改 |
| `captureJoinEvent` | `Bridge.cpp:355-377` | B3 改 kind |
| `PendingEvent` | `Bridge.cpp:50-60` | A3 加 kind |
| 驱动 routes | `Bridge.cpp:739-748` | A2 加可选 route |
| 指标发布 | `Bridge.cpp:815-858` | A1/A2/A3 加属性 |
| 计数结构 | `Bridge.hpp:36-82` | A1/A2/A3 加字段 |
| 驱动符号 | `payload1.bin @0x42b8e` | `AirPort_BrcmNIC::setASSOCIATE` |

---

## F. 备注：与兄弟报告的一处更正

`Docs/Reverse-Payload-SetTable-20261117.md` §0.8/§7.6 说“`Bridge::command` 的 ENXIO 早退不更新
`LastRequest/ReqHist`”。按当前源码顺序，`LastRequest`/`ReqHist` 在 `UserClient.cpp:304-312` 写入，
**在** `Bridge::command` 调用（第 359 行）之前；所以 ENXIO 不会让请求从 `LastRequest/ReqHist` 消失，
只会让 `LastAssociationResult`（若 type 20 已进 runCommand）变成 ENXIO，并增加 `Rejects`。
本会话实测 `Rejects=0`，当前不涉及这条早退。
