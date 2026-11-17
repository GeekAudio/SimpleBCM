# payload0（IO80211FamilyLegacy）set 分派表逆向 & 与 27 IO80211Family 的对照

- 日期：2026-11-17
- 机器：macOS 27.2（26B123）/ Darwin 27.2.0 / x86_64
- 对象：
  - `simplebcm-r27/.research/extract/payload0.bin`（IO80211FamilyLegacy，sha256 `4e17b8d95126516d4ce52cb48a3ffbc5f99256555e58f58bcf38f48bdac92bb7`，2,306,048 字节）
  - 本机 `/System/Library/KernelCollections/BootKernelExtensions.kc`（sha256 `4a49bffb32594d0d9287de38540dec71b6f679dbd3c3a06fb315077b624f9873`）中的 `com.apple.iokit.IO80211Family`（UUID `fcff2e2c-c353-3ed2-90ca-a7776a68e892`）
- 方法：`nm` / `otool -l` / `llvm-objdump` 定点反汇编 + `Tools/kernel_collection.py` 解码 KC chained-fixup 表项。全部只读，未加载/卸载 kext，未修改系统。

## 0. 结论摘要（先看这里）

1. **payload0 的 `apple80211_ioctl_set` 用 `apple80211req->type - 1` 索引 `_gSetHandlerTable`（8 字节函数指针，417 项，位于 `__DATA,__const`，静态已填充 187 项）。** 合法 type 是 **1..417**；type 0 或 ≥418 直接返回 `0x66`（EOPNOTSUPP）；槽位为 NULL 时打日志并返回 `0x66`。
2. **payload0 中关联相关请求号就是 20（set ASSOCIATE）与 21（get ASSOCIATE_RESULT）。** type 20（下标 19）→ `0x84430 __ZL19setAssociateRequest…`；type 21（下标 20）→ `0x79377 __ZL18getAssociateResult…`。
3. **payload0 的 set[254] 是空槽（0），不是关联。** 该表里 type 254 没有任何 set handler；type 255 才是 `setUCMCoexProfile`。
4. **27 系统 IO80211Family 同样把 type 20 映射到 ASSOCIATE**：607 项新表（用户客户端 IOUC 路径）type 20 → `setASSOCIATE @0xffffff8001f8a1fa`；457 项 legacy 表（BSD ioctl 路径）type 20 → `setAssociateRequest @0xffffff800205e8bd`；内部表 type 20 → `apple80211setASSOCIATE @0xffffff8001f6c055`。
5. **“slot 20 为空、slot 254 有 handler”是索引/方向混淆**：
   - 若“slot”指 0-based 表下标，则下标 20 空、下标 254 是 **type 255**（27 新表 = `setBTCOEX_PROFILE`，legacy 表 = `setUCMCoexProfile`），仍不是关联；
   - 若看的是 **get 表**，则 type 20（下标 19）为空、type 254（下标 253）= `getHwSupportedChannels` / `getHW_SUPPORTED_CHANNELS`，更不是关联。
6. **type 254 在 set 方向是“洞”**：payload0、27 新表、27 legacy 表、27 internal 表在下标 253（type 254）处全为 0；只有 get 方向 type 254 有 handler（`getHwSupportedChannels`）。历史 `LastRequest=254 / LastResult=0` 最合理的解释是 **GET_HW_SUPPORTED_CHANNELS 成功返回**，而不是关联。
7. **SimpleBCM 做映射时不需要给关联改号**：27 用户态与 payload0 的 ASSOCIATE 都是 **set type 20**，结果读取是 **get type 21**。需要做的是把 27 的 associate 请求结构转换成 payload0 的 **548（0x224）字节 legacy 布局**；现有 `prepareAssociate` 已按 0x38C（908）native 布局实现，但 27 kext 自身只消费 **0x290（656）**，这两个数字需要运行期实测确认（见 §7）。
8. `LastRequest` 之前还有一道 `Bridge::command` 的 ENXIO 早退，它只更新 `LastRejectType/Rejects`，不更新 `LastRequest/ReqHist`（源码 `Bridge.cpp` ENXIO 分支在计数之前）。因此“没看到 20”必须结合 `LastRejectType`、`Rejects`、`RejectInterfaceInactive`、`RejectControllerInactive` 一起判断，不能只由 `LastRequest` 推断“27 没发 20”。

---

## 1. payload0 的段布局与表位置

`file`：Mach-O 64-bit kext bundle x86_64。`__TEXT`/`__DATA` 的 `fileoff` 均等于 `vmaddr`，因此下文“文件偏移 = 虚拟地址”。

| 项 | 值 |
| --- | --- |
| `__TEXT,__text` | addr `0xeb0`，size `0xf4fa6` |
| `__TEXT,__const` | addr `0xf5e60`，size `0xb878` |
| `__DATA,__const` | addr `0x1474b0`，size `0x14040`，文件偏移 `0x1474b0` |
| `__DATA,__data` | addr `0x15b4f0`，size `0xba0` |
| `_gSetHandlerTable` | `0x14ae50`（落在 `__DATA,__const`，文件中有实际内容，**不是 BSS**） |
| `_gGetHandlerTable` | `0x14a140`（同上） |
| `_gSetHandlerTableCount` | `0xf8b00`（`__TEXT,__const`），首 4 字节 `0x1a1` = 417 |
| `_gGetHandlerTableCount` | `0xf7cd0`，u32 = 417 |

`nm`：

```
000000000014a140 S _gGetHandlerTable
00000000000f7cd0 S _gGetHandlerTableCount
000000000014ae50 S _gSetHandlerTable
00000000000f8b00 S _gSetHandlerTableCount
```

417 × 8 = 3336 = `0xd08`，表尾 `0x14bb58`，仍在 `__const`（`0x15b4f0` 结束）内。

**表项格式**：小端 8 字节，直接是 payload0 的 0-based 函数地址（例如 `0x0000000000084430`），不是相对偏移、不是编码指针。187/417 非空，230 空。

**没有任何初始化函数写这张表**：在 `__text` 中扫描 RIP-relative 引用，只有两处分派器引用表本身——

```
0x91e41  lea 0xb82f8(%rip),%rdi   -> 0x14a140  _gGetHandlerTable   (get 分派器)
0x91f0f  lea 0xb8f3a(%rip),%rsi   -> 0x14ae50  _gSetHandlerTable   (set 分派器)
```

`_gSetHandlerTableCount` / `_gGetHandlerTableCount` 在代码中**无任何引用**（分派器把上限 417 写死为立即数）。所以任务里“谁写 `_gSetHandlerTable`”的答案是：**没人写，它是链接期静态初始化在 `__const` 的表**；不存在需要反推的运行时注册函数。

---

## 2. payload0 `apple80211_ioctl_set` 分派逻辑（0x91ede）

`nm` 给出：

```
0000000000091ede T __ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv
```

### 2.1 关键指令

```
91ede: push rbp; ...; sub $0x18,%rsp
91eef: movq %r8,%rbx              ; rbx = apple80211req*
91ef2: movq %rsi,%r8              ; r8  = IO80211Interface*
91ef5: movq %rdi,%r14             ; r14 = IO80211Controller*
91ef8: movl 0x10(%rbx),%eax       ; eax = req->type
91efb: leal -0x1a2(%rax),%esi     ; esi = type - 418
91f01: cmpl $0xfffffe5f,%esi      ; 0xfffffe5f = -417
91f07: jb   0x91fd5               ; 无符号比较: type==0 或 type>=418 -> 打日志/返回 0x66
91f0d: decl %eax                  ; index = type-1
91f0f: leaq 0xb8f3a(%rip),%rsi    ; 0x14ae50 _gSetHandlerTable
91f16: movq (%rsi,%rax,8),%r15    ; h = table[type-1]
91f1a: testq %r15,%r15
91f1d: je   0x91fb4               ; NULL 槽 -> 打日志/返回 0x66
91f23: movl 0x28(%rbx),%eax       ; req->pointerSize（LegacyRequest 在 Request 0x28 之后）
91f26: movq 0x190(%r14),%rdi      ; controller->logFlags? (logIOCTL 判断)
...
91f75: xorl %r9d,%r9d
91f78: cmpl $0x8,%eax
91f7b: sete %r9b                  ; r9b = (req->pointerSize == 8)
91f7f: movq %r14,%rdi             ; arg1 = controller
91f82: movq %r8,%rsi              ; arg2 = interface（进入时的 rsi）
91f85: movq %rbx,%r8              ; arg5 = req
91f88: callq *%r15                ; arg3/arg4 = 进入时的 rdx/rcx（virtual/skywalk）
91f8b: cmpl $0x66,%eax
91f8e: je   0x91fd5               ; handler 返回 0x66 -> 再打一次日志，返回 0x66
91f90: cmpl $0x6a,%eax
91f93: jb   0x91ffb               ; <0x6a 原样返回
91f95: movq (%r14),%rcx
91f98: movq 0x788(%rcx),%rcx
...    jmpq *%rcx                 ; >=0x6a 走 IO80211Controller 虚表 +0x788，尾调用
```

等价的边界判断是 `if ((uint32_t)(type - 418) < 0xFFFFFE5F) fail;`，即合法 **type ∈ [1,417]**（type=418 也 fail）。

### 2.2 调用约定

handler 实际签名（与 `nm` 的 `__ZL…P17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb` 一致，只是第 4 参在运行期传 Skywalk）：

```
rdi = IO80211Controller*
rsi = IO80211Interface*
rdx = IO80211VirtualInterface*
rcx = IO80211SkywalkInterface*
r8  = apple80211req*
r9b = (req->pointerSize == 8)
```

### 2.3 失败路径

- **越界（type 0 / ≥418）**：`0x91fd5` 单次日志后返回 `0x66`。
- **空槽**：`0x91f1d -> 0x91fb4`，先打一遍日志，然后顺序落入 `0x91fd5` 再打一遍，返回 `0x66`（空槽会打印两次相同的 `not recognized`，越界只打印一次；做运行期统计时别把它当成两条不同请求）。
- **handler 返回 0x66**：`0x91f8e -> 0x91fd5` 打一遍，返回 `0x66`。
- 日志字符串在 `0x12783c`：`" IOCTL (from pid %d) not recognized: %d out of %d\n"`，`logDebug` = `__ZN17IO80211Controller8logDebugEPKcz` @ `0x8eb90`，`out of` 的立即数是 `0x1a1`（417）。这解释了统一日志里 `IOCTL (from pid …) not recognized: 512 out of 417` 的来源与格式。

### 2.4 get 侧对照（0x91e1a）

`apple80211_ioctl_get` 结构相同（`type-1`、`_gGetHandlerTable`、417），但越界/空槽**不打日志**，静默返回 `0x66`；handler 签名相同（也传 `r9b = (req->pointerSize == 8)`）。因此“not recognized”日志只可能来自 set 分派器或 set handler 的 0x66 返回。

### 2.5 set 表关键槽位（payload0，type 从 1 开始）

| type | 下标 | 表项 | 符号 |
| --- | --- | --- | --- |
| 1 | 0 | `0x83640` | `__ZL7setSSID…` |
| 2 | 1 | `0x83735` | `__ZL11setAuthType…` |
| 19 | 18 | `0x84235` | `__ZL8setPower…` |
| **20** | 19 | **`0x84430`** | **`__ZL19setAssociateRequest…`** |
| 21 | 20 | `0` | —（SET_ASSOCIATE 没有 21；21 是 GET 结果） |
| 22 | 21 | `0x848a7` | `__ZL15setDisassociate…` |
| 113 | 112 | `0x87c02` | `__ZL14setReassociate…` |
| 174 | 173 | `0x89b69` | `__ZL11setChainAck…` |
| 175 | 174 | `0x89c4a` | `__ZL10setDesense…` |
| 176 | 175 | `0x89d27` | `__ZL18setOffloadScanning…` |
| 177 | 176 | `0x89e32` | `__ZL13setOffloadRSN…` |
| 251 | 250 | `0x8c376` | `__ZL12setTKOParams…` |
| **254** | 253 | **`0`** | **空槽** |
| 255 | 254 | `0x8c44e` | `__ZL17setUCMCoexProfile…` |
| 256 | 255 | `0x8c535` | `__ZL23setUCMCoexProfileActive…` |
| 417 | 416 | `0x8d505` | `__ZL16setAWDLUMIToPeer…`（表尾） |

所以 **175/176 与关联无关**：175 = setDesense，176 = setOffloadScanning。

get 表同范围（用于关联结果）：

| type | 下标 | 表项 | 符号 |
| --- | --- | --- | --- |
| 20 | 19 | `0` | —（get 20 空） |
| **21** | 20 | **`0x79377`** | **`__ZL18getAssociateResult…`** |
| 254 | 253 | `0x81abd` | `__ZL22getHwSupportedChannels…` |
| 255 | 254 | `0x81bdb` | `__ZL17getUCMCoexProfile…` |

---

## 3. payload0 `setAssociateRequest`（0x84430）吃的是 legacy 548 字节

```
844c2: lea  -0x258(%rbp),%rdi      ; stack buffer
844c9: movl $0x224,%esi            ; 548
844ce: callq <import thunk>        ; __bzero(buf, 0x224)  （payload0 的 __bzero 是 import）
844d3: movl 0x18(%r15),%eax        ; req->length
844d7: movl $0x16,%ebx
844dc: testl %eax,%eax; je  exit   ; length==0 -> 0x16 (EINVAL)
844e0: cmpq $0x0,0x20(%r15); je exit ; req->data==NULL -> 0x16
84519: movl 0x18(%r15),%eax
8451d: movl $0x224,%ecx
84522: cmpl %ecx,%eax
84524: cmovbl %eax,%ecx            ; len = min(req->length, 548)
84566: movq 0x20(%r15),%rsi        ; req->data
8456c: lea -0x258(%rbp),%rdx
84573: movq %r12,%rdi
84576: callq 0x91d6c                ; __ZN17IO80211Controller6copyInEyPvm
...
84789: ... call *0xce8(%rax)        ; 之后走 controller 的 associate 虚函数
```

要点：

- 结构体大小上限写死 **0x224 = 548**，超过 548 的输入被**截断**（不是拒绝）。
- 长度 0 或 data 为空返回 `0x16`。
- 这就是 `Docs/Control-Codecs.json` 的 `associateTransfer.legacySize = 548`、`legacyCodec = 0x84430` 的来源。

---

## 4. 27 系统 IO80211Family 的 set/get 分派

### 4.1 符号与表容量

`Tools/kernel_collection.py` 读 `com.apple.iokit.IO80211Family`（image base `0xffffff8001e80000`）：

| 符号 | 地址 | 容量 |
| --- | --- | --- |
| `__ZL16gSetHandlerTable`（新/set） | `0xffffff800218d590` | 607（代码上界推断） |
| `_gSetHandlerTableLegacy` | `0xffffff80021a6b10` | **457**（`_gSetHandlerTableLegacyCount` @`0xffffff80020d8150` = `0x1c9`） |
| `__ZL16gGetHandlerTable`（新/get） | `0xffffff800218c150` | 607（代码上界推断） |
| `_gGetHandlerTableLegacy` | `0xffffff800219e6e0` | **590**（`_gGetHandlerTableLegacyCount` @`0xffffff80020cac80` = `0x24e`） |
| `__ZL24gInternalSetHandlerTable` | `0xffffff80021abf90` | 607（内部 C 函数表） |
| `__ZL24gInternalGetHandlerTable` | `0xffffff80021aac90` | 607 |

表项是 **chained fixup 编码的 8 字节指针**（例：`raw=0x0080000001e8a1fa`），解码规则与 `kernel_collection.pointer()` 一致：

```
fixup_base = 0xffffff8000100000
ptr = fixup_base + (raw & 0x3fffffff)
```

例：`0x0080000001e8a1fa -> 0xffffff8001f8a1fa`。

### 4.2 分派器：`apple80211RouteExternal`

`nm`：

```
ffffff8002074b4c T __Z23apple80211RouteExternalP23IO80211SkywalkInterfaceP20IO80211APIUserClientmP13apple80211reqbb
```

签名：`(IO80211SkywalkInterface*, IO80211APIUserClient*, unsigned long cmd, apple80211req*, bool newTables, bool flag6)`。

关键指令（地址 `0xffffff8002074b4c` 起）：

```
74b99: movl 0x10(%r9),%eax        ; req->type
74b9d: cmpl $-1,%eax
74ba0: je   special(-1)           ; type==-1 -> 虚表 +0xc98
74ba2: testb %r14b,%r14b          ; r14b = newTables
74ba5: je   0x74c06               ; false -> legacy 表
; --- newTables == true ---
74ba7: leal -0x260(%rax),%ecx     ; type - 608
74bb6: cmpq %r12(0xc02869c9),%r14 ; cmd == GET?
74bb9: jne 0x74c37
74bc9: lea 0x117580(%rip),%rcx    ; 0x218c150 gGetHandlerTable
74c37: leal -0x260(%rax),%ecx     ; type - 608
74c45: lea 0x118944(%rip),%rcx    ; 0x218d590 gSetHandlerTable
; --- legacy (newTables == false) ---
74c0f: cmpq 0xc02869c9,%r14
74c14: leal -0x24f(%rax),%ecx     ; type - 591
74c2e: lea 0x129aab(%rip),%rcx    ; 0x219e6e0 gGetHandlerTableLegacy
74c65: leal -0x1ca(%rax),%ecx     ; type - 458
74c7b: lea 0x131e8e(%rip),%rcx    ; 0x21a6b10 gSetHandlerTableLegacy
74c4c/74c82: movq (%rcx,%rax,8),%rax  ; rax 已 decl，(type-1)
74c50: testq %rax,%rax; je 0x74ca8  ; NULL -> r15d=0x66
```

伪代码：

```c
static IOReturn RouteExternal(Skywalk *sw, APIUserClient *client, uint64_t cmd,
                              apple80211req *req, bool newTables, bool flag6) {
    int32_t type = req->type;
    if (type == -1) return controller->vtable[0xc98/8](...);   // controller = sw->vtable[0xbd8]()
    const void **table; uint32_t max;
    if (newTables) {
        if (cmd == 0xc02869c9) { table = gGetHandlerTable; max = 607; }
        else                   { table = gSetHandlerTable; max = 607; }
    } else {
        if (cmd == 0xc02869c9) { table = gGetHandlerTableLegacy; max = 590; }
        else                   { table = gSetHandlerTableLegacy; max = 457; }
    }
    if (type < 1 || type > max) { log(...); return 0x66; }
    void *h = table[type - 1];
    if (!h) return 0x66;
    return h(...);   // 新表: (controller, skywalk, client, req)
                     // legacy: (controller, skywalk, req, flag6)
}
```

边界立即数：新表 `type-608` 与 `0xfffffda0(-608)` 比较、`jbe` 拒绝 → 合法 1..607；legacy set `type-458` 与 `-457` → 1..457；legacy get `type-591` 与 `-590` → 1..590。**下标一律 `type-1`**。

### 4.3 两条调用路径（很重要）

| 调用者 | 地址 | `newTables` | 使用的表 |
| --- | --- | --- | --- |
| `IO80211SkywalkInterface::performGatedCommandIOUC`（用户客户端 IOUC 路径） | `0xffffff8001ffb8d8`，`RouteExternal` 尾跳 `0xffffff8001ffb935`（`r8d=1`） | 1 | **新表 607 项** |
| `IO80211SkywalkInterface::performGatedCommandIOCTL`（BSD ioctl 路径） | `0xffffff8001ffc242`，调用点 `0xffffff8001ffc355`（`r8=0`） | 0 | legacy 表（set 457 / get 590） |
| `IO80211VirtualInterface::handleIoctlGated` | `0xffffff8002039584`，调用点 `0xffffff80020396ba`（`r8=0`） | 0 | legacy 表 |

`IO80211APIUserClient::_runDriverCommandHelper`（`0xffffff800205a6bc`）在 `0xffffff800205ac3e` 调 `performGatedCommandIOUC`，也就是说 **27 airportd/wifid 经由 user client 的请求走的是 607 项新表**，不是 457 项 legacy 表。legacy 表是给 `ioctl()`/BSD 兼容路径的。

### 4.4 27 表的关键槽位（type 从 1 开始）

| type | payload0 set | 27 legacy set（457） | 27 new set（607） | 27 internal set |
| --- | --- | --- | --- | --- |
| 1 | `setSSID @0x83640` | `setSSID @0x205e130` | `setSSID @0x1f89cc7` | `apple80211setSSID @0x1f6bca2` |
| 2 | `setAuthType @0x83735` | **NULL** | **NULL** | NULL |
| 19 | `setPower @0x84235` | `setPower @0x205e758` | `setPOWER @0x1f8a167` | … |
| **20** | **`setAssociateRequest @0x84430`** | **`setAssociateRequest @0x205e8bd`** | **`setASSOCIATE @0x1f8a1fa`** | **`apple80211setASSOCIATE @0x1f6c055`** |
| 21 | NULL | NULL | NULL | NULL |
| 22 | `setDisassociate @0x848a7` | `setDisassociate @0x205ec0c` | `setDISASSOCIATE @0x1f8a3d1` | … |
| 113 | `setReassociate @0x87c02` | **NULL** | **NULL** | NULL |
| 174 | `setChainAck @0x89b69` | **NULL** | **NULL** | NULL |
| 175 | `setDesense @0x89c4a` | **NULL** | **NULL** | NULL |
| 176 | `setOffloadScanning @0x89d27` | **NULL** | **NULL** | NULL |
| 177 | `setOffloadRSN @0x89e32` | **NULL** | **NULL** | NULL |
| 251 | `setTKOParams @0x8c376` | `setTKOParams @0x2060df1` | `setTKO_PARAMS @0x1f8c767` | … |
| **254** | **NULL** | **NULL** | **NULL** | **NULL** |
| 255 | `setUCMCoexProfile @0x8c44e` | `setUCMCoexProfile @0x2060df9` | `setBTCOEX_PROFILE @0x1f8c7d1` | `apple80211setBTCOEX_PROFILE @0x1f6dd66` |
| 256 | `setUCMCoexProfileActive @0x8c535` | `setUCMCoexProfileActive @0x2060ea0` | `setBTCOEX_PROFILE_ACTIVE @0x1f8c82f` | `…ACTIVE @0x1f6ddbb` |
| 417 | `setAWDLUMIToPeer @0x8d505` | **NULL** | `setAWDL_UMI_TX_PEER @0x1f8f32f` | `apple80211setAWDL_UMI_TX_PEER @0x1f6fd8a` |

get 方向（关联结果）：

| type | payload0 get | 27 legacy get | 27 new get |
| --- | --- | --- | --- |
| 20 | **NULL** | **NULL** | **NULL** |
| **21** | **`getAssociateResult @0x79377`** | **`getAssociateResult @0xffffff800202c9bb`** | **`getASSOCIATE_RESULT @0xffffff8001f7e9ed`** |
| 253 | NULL | NULL | NULL |
| **254** | **`getHwSupportedChannels @0x81abd`** | **`getHwSupportedChannels @0xffffff800202f36f`** | **`getHW_SUPPORTED_CHANNELS @0xffffff8001f812af`** |
| 255 | `getUCMCoexProfile @0x81bdb` | `getUCMCoexProfile @0xffffff800202f455` | `getBTCOEX_PROFILE @0xffffff8001f8130c` |

**注意 27 与 payload0 在 2、113、174–177、417 等 legacy 槽位已经不一致**：27 的 457 项 legacy 表把这些旧号清空了（迁移到新号或合并进 associate），payload0 仍有完整 handler。SimpleBCM 直接把 27 的请求喂给 payload0，对这些号反而是“能力更多”，但也意味着不能拿 27 的表当 payload0 的完整性判据。

---

## 5. `254` 到底是什么

### 5.1 三个 set 表一致：type 254 是空槽

- payload0：下标 253（type 254）`= 0`；
- 27 legacy：下标 253（type 254）`raw = 0`；
- 27 new：下标 253（type 254）`raw = 0`；
- 27 internal：下标 253（type 254）`raw = 0`。

如果 27 用户态真的发 `SET type=254`，**连 Apple 自己的 27 IO80211Family 也会返回 0x66**（新表越界检查通过，但槽位为空）。因此 254 不可能是“27 上被重命名后的 ASSOCIATE”。

### 5.2 254 在 get 方向是 HW_SUPPORTED_CHANNELS

- payload0：type 254（下标 253）`= 0x81abd __ZL22getHwSupportedChannels…`
- 27 legacy：type 254（下标 253）`= 0xffffff800202f36f getHwSupportedChannels`
- 27 new：type 254（下标 253）`= 0xffffff8001f812af getHW_SUPPORTED_CHANNELS`

`LastRequest=254 / LastResult=0` 与“一次成功的 GET_HW_SUPPORTED_CHANNELS”完全吻合：它返回 0，不产生 AssociationDone/DriverAvailable 事件，也不会 increment `AssociationRequests`。

### 5.3 “slot 20 空、slot 254 有 handler”的两种来源

1. **0-based 表下标**：下标 20（= type 21）空；下标 254（= **type 255**）是 `setBTCOEX_PROFILE` / `setUCMCoexProfile`。type 255 是 BTCOEX/UCM 共存配置，不是关联。
2. **1-based type 看 get 表**：type 20 在 get 表为空（关联是 set）；type 254 在 get 表是 `getHwSupportedChannels`。这也能解释 `LastResult=0`。

两种解释都不支持“254 = 关联”。要最终钉死，运行期只需看 `LastRequestSet`（0=get，1=set）与 `LastRequestKind`/`ReqHist*` 的 flags；现有 probe 已打印 `req/len/hdr/data`，补打 `header->command` 的 set/get 位即可。

### 5.4 如果 254 是 set 且 result=0，则与表结构矛盾

这种情况下需要怀疑 **用户客户端请求头版本/偏移**，而不是关联号：27 有 `apple80211IOUCReq`（V1）和 `validateBufferLengthV2`/`validateReqDataBoundsV2` 对应的 V2 结构（`0xffffff800205cef6`、`0xffffff800205d17f`）。V1 的 `apple80211req` 位于输入缓冲 `0x3C08`（type 在 `0x3C18`、length `0x3C20`、data `0x3C28`），与 SimpleBCM 的 `CommandHeader(8) + data(0x3C00) + Request(0x28)` 完全一致；若 27 对某些 selector 切到 V2，而 SimpleBCM 仍按 V1 解析，`type` 就会读到别的字段。**这一条目前未验证**，但它是“254 且 set 成功”唯一还能自洽的解释。

---

## 6. 结构转换：548 / 656 / 908

### 6.1 已实测的消费者

| 代码 | 地址 | 行为 |
| --- | --- | --- |
| payload0 `setAssociateRequest`（legacy 548） | `0x844c2..0x84576` | `__bzero(buf, 0x224)`；`copyIn(min(req->length, 0x224))`；之后按 legacy 布局解析 |
| 27 legacy `setAssociateRequest` | `0xffffff800205e8bd` | `bzero(buf, 0x290)`；`copyIn(min(req->length, 0x290))`（`0xffffff800205e920..0x205e934`）；随后校验 `buf+0x10 < 0x21`、`buf+0xD0 < 0x102`、`buf+0x1D8 < 0x21`、`buf+0x202 < 0xB`、`buf+0x240 < 0x26`；再 `routeIoctlToWcl(0x802869c8, 0x14, buf, 0x290)`（`0xffffff800205e9fb`） |
| 27 new `setASSOCIATE` | `0xffffff8001f8a1fa` | 直接 `routeIoctlToWcl(0x802869c8, 0x14, req->data, 0x290)`（`0xffffff8001f8a2f8`），**不检查 req->length** |
| 27 new `getASSOCIATE_RESULT` | `0xffffff8001f7e9ed` | 要求 `req->length == 4`（`cmpl $0x4,0x18(%rcx)`），再 `routeIoctlToWcl(0xc02869c9, 0x1d, …, 0x10)` / `(0xc02869c9,0x32,…,8)` |
| payload0 `getAssociateResult` | `0x79377` | 调 `getASSOCIATE_RESULT(...)`，成功把结果写到 **`req->value`（req+0x14）**，是标量 get（SimpleBCM 的 `ScalarGetRequests` 已包含 21） |

结论：

- **payload0 侧目标格式是 548 字节 legacy 布局**，超过 548 会被截断。
- **27 的 kext 在两个路径上都只把 656（0x290）字节交给 WCL**；`setASSOCIATE` 甚至不校验长度，`setAssociateRequest` 只 `copyIn(min(len,0x290))`。
- 27 的 legacy handler 在 `0x202`、`0x240` 处做 bssid 计数/尾部长度校验，而 `Docs/Control-Codecs.json` 的 native 布局写的是 `0x206`、`0x244`（正好差 4）。这说明 27 实际 associate 结构与 JSON 的 Tahoe native 布局至少有一处需要复核；JSON 的 908/548 转换规则本身（auth 8/12→6/8、ssid 0x10→0xC、key 0x3C→0x38、rsn 0xD0→0xCC、pmk 0x1D8→0x1D4、bssid 0x206→0x202、scope 0x244→0x218）与 `prepareAssociate` 的实现一致，但**偏移是否就是 27.2 实际发出的布局，未实测**。

SimpleBCM 现有 `prepareAssociate`（`WirelessABI.hpp`）已经做了上述 native→legacy 转换，并以 `request.length == abi.associateSize`（GoldenGate 为 `0x38C`）作为前置条件；如果 27.2 实际 `header->length` 是 `0x290` 或别的值，这个门禁会在进入驱动前就返回 `kIOReturnBadArgument`，这也可能造成“从来没看到 ASSOCIATE(20) 进 LastRequest”（不过注意 `lastRequest/ReqHist` 是在该门禁之前写入的，所以更可能表现为“有 20、result=BadArgument”而不是“没有 20”）。

---

## 7. 对 SimpleBCM 的映射建议

1. **关联 set 继续用 20，不要改成 254。** 20 在 payload0、27 legacy、27 new、27 internal 四张表里都是 ASSOCIATE。27 用户态与 payload0 的号段在 1..417 内是一致的。
2. **关联结果 get 用 21。** payload0 get 表 type 21（下标 20）是 `getAssociateResult`，且是标量返回（写 `req->value`，req+0x14）；SimpleBCM 的 `ScalarGetRequests` 已包含 21，保持即可。
3. **不要把 254 当关联**：set 254 是空槽（连 27 自己也不支持）；get 254 是 HW_SUPPORTED_CHANNELS。若 probe 看到 254，先看 `LastRequestSet`；若 set=1 且 result=0，优先怀疑用户客户端结构版本/偏移（V1/V2），而不是关联号。
4. **结构转换只对 type 20 做**：把 27 的 native associate 请求转换为 548 字节 legacy 布局（`prepareAssociate` 已有），但要先实测 27.2 用户态发 20 时的 `header->length` 和 `req->length`：
   - 若确为 `0x38C`（908），现有转换路径成立，再用真实字节校验 `0x202/0x206`、`0x240/0x244` 两组偏移；
   - 若为 `0x290`（656），则 `header->length != abi.associateSize` 会直接拒绝，需要把 GoldenGate 的 `associateSize` 改成实测值，并按 656 布局重做转换（不能直接套 908 的偏移）。
5. **不要用 27 的表判断 payload0 的完整性**：27 的 legacy 表已把 type 2/113/174–177/417 等旧号清空，而 payload0 仍有 handler；SimpleBCM 的能力边界应以 payload0 的 417 项为准（并单独处理 >417 的 27-only 请求）。
6. **“没看到 20”要结合拒绝计数**：`Bridge::command` 的 ENXIO 早退只更新 `LastRejectType/Rejects/RejectInterfaceInactive/RejectControllerInactive`，不更新 `LastRequest/ReqHist`；`UserClient` 的结构门禁则在 `lastRequest/ReqHist` 之后。建议把 `LastRejectType` 与 `ReqHist*` 一起发布/抓取，并给 probe 增加 `header->command` 与 `lastRequestSet`。
7. **日志噪声**：payload0 的空槽会打印两次同一条 `not recognized`，越界只打印一次；统计“未知请求”时按请求/pid 去重，别把空槽算成两条。

---

## 8. 未验证 / 待实测

1. **254 的真实来源**：方向（`LastRequestSet`）、endpoint kind、`header->command`、`req->length` 与完整 0x28 字节请求头。目前只能断言“set 254 在所有表里都是空槽；get 254 是 HW_SUPPORTED_CHANNELS”。
2. **27.2 用户态 associate 请求长度**：908（0x38C）还是 656（0x290）；以及 `req->data` 前 0x250 字节的实际字段偏移（尤其 bssidCount/scopeLength 是 0x202/0x240 还是 0x206/0x244）。
3. **27 的 V1/V2 `apple80211IOUCReq` 选择逻辑**：`validateBufferLengthV2`/`validateReqDataBoundsV2` 对应的结构布局与触发条件未逐指令核对。
4. **27 getASSOCIATE_RESULT 的返回布局**：27 new handler 要求 `req->length==4`，payload0 写 `req->value`（req+0x14）；两者是否完全等价未做端到端验证。
5. **512 `setINFRA_ENUMERATED` 等 27-only set 失败是否会让 airportd 在关联前中止**：仍无代码/日志证据（与既有分析一致）。
6. **`LastRequest=254/LastResult=0` 那一次的 `LastRequestSet`/`LastRequestKind`**：需要回看当时的 ioreg 快照；当前材料未给出。

---

## 9. 复现命令（只读）

```sh
# payload0 表与符号
nm -arch x86_64 .research/extract/payload0.bin | grep -E 'g(Set|Get)HandlerTable'
llvm-objdump -d --arch=x86_64 --start-address=0x91ede --stop-address=0x9200a \
  --no-show-raw-insn .research/extract/payload0.bin

# 27 KC 的表
/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3 - <<'EOF'
import sys; sys.path.insert(0,'Tools')
from kernel_collection import KernelCollection
kc=KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
im=kc.images['com.apple.iokit.IO80211Family']
for tab in ['__ZL16gSetHandlerTable','_gSetHandlerTableLegacy','__ZL24gInternalSetHandlerTable',
            '_gGetHandlerTableLegacy','__ZL16gGetHandlerTable']:
    base=im.symbols[tab]
    print(tab, hex(base))
    for t in (1,2,19,20,21,22,113,174,175,176,177,251,254,255,256):
        raw=int.from_bytes(im.read(base+(t-1)*8,8),'little')
        ptr=0 if raw==0 else kc.pointer(base+(t-1)*8)
        print(t, hex(raw), hex(ptr), im.name(ptr) if ptr else 'NULL')
EOF

# 反汇编 27 分派器（需要按 KC 地址取字节后包一个最小 Mach-O；脚本见本次分析临时文件）
# 关键地址：0xffffff8002074b4c apple80211RouteExternal
```

---

## 10. 证据文件

- `simplebcm-r27/.research/extract/payload0.bin`（sha256 `4e17b8d95126516d4ce52cb48a3ffbc5f99256555e58f58bcf38f48bdac92bb7`）
- `/System/Library/KernelCollections/BootKernelExtensions.kc`（sha256 `4a49bffb32594d0d9287de38540dec71b6f679dbd3c3a06fb315077b624f9873`）
- 本报告中的 27 地址均为 KC 链接后绝对地址（`0xffffff8001…/0xffffff8002…`），payload0 地址为 kext 的 0-based vmaddr。
