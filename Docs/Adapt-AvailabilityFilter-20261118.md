# 27 ABI 反汇编：DriverAvailable 0xF8 负载与 EventFilter 结构

日期：2026-11-18（Asia/Shanghai）
目标：macOS 27.2（26B123，x86_64 Intel）
证据源：
- `com.apple.iokit.IO80211Family`（`/System/Library/KernelCollections/BootKernelExtensions.kc`，UUID `fcff2e2c-c353-3ed2-90ca-a7776a68e892`）
- `com.apple.driver.AppleBCMWLANCoreMac`（同一 KC，用于排除 27 原生驱动侧生产点）
- payload0 = 内嵌 `IO80211FamilyLegacy`（`.research/extract/payload0.bin`，SHA/UUID 见 `Docs/Analysis-20261117-driver-side.md` §1.1）
- 用户态 `IO80211.framework`（从 dyld shared cache 只读提取，见 §6）
- 运行期 `ioreg` / 统一日志（只读）

> 约束：全程只读；未修改 `/System`、`/Library`、EFI；未重启、未部署。本文所有「证据地址」均为 KC 未滑动地址（unslid vmaddr）。

---

## 0. 结论（先看这里）

1. **0xF8 负载只有一个字段被 27 内核读取：`+0x08` 的 u32。** 0 = 驱动不可用，非 0 = 可用。27 还要求长度**精确等于 0xF8**（`cmpq $0xf8,%rdx`），不是「至少」。其余 0xF4 字节在 27 内核没有任何读取点。
2. **27 把 `+8 != 0` 缓存成 `IO80211ControllerMonitor` ivars `+0xb68` 的 bool**（`monitor->ivars` 在 `+0x10`；ivars 的首字段 `+0x00` 才是 controller），`IO80211ControllerMonitor::getDriverAvailable()` 返回它，`apple80211RouteExternal` 也读它。
3. **0x37 还有第二个内核消费者**：`IO80211PeerManager::reportDataPathEvents` 的 `msg==0x37` case 同样检查 `len==0xF8` 且只读 `+8`（为 0 时触发 `resetStuckDataPathCheck`）。两处消费点都是「只看 +8」。
4. **SimpleBCM 当前的 0xF8 合成在长度与 +8 语义上已经正确**；`+0x10 = 0xE0821803`（reason）不被 27 内核消费，保留无害。**不需要补字段**。最小正确填法见 §1.5。
5. **27 的 `apple80211EventFilter` = `0x21` 字节**：`+0x00` 是 `u8 all`（非 0 = 接受全部消息），`+0x01..+0x20` 是 32 字节事件位图（bit `N-1` = 事件 N，N∈1..256）。SimpleBCM 的 `struct EventFilter { uint8_t all; uint8_t bitmap[31]; }`（`0x20`）**少 1 个位图字节**。
6. 27 的 564 号 Set 处理函数对 `req->length != 0x21` 是**静默成功（返回 0、不设置 filter）**；SimpleBCM 当前用 `length != sizeof(EventFilter)` 精确比较，会把 27 的 0x21 请求判为 `kIOReturnBadArgument`。因为 `filter.all` 在构造时被置 1（`UserClient.cpp:69`），这个失败目前不会挡住 availability replay，但客户端的事件过滤被静默忽略（全部事件照发）。
7. **payload0（Tahoe legacy）没有 564 的 handler**：`_gSetHandlerTable` 只有 417 项，payload0 里也没有 `setEventFilter`/`FILTER_MONITOR` 符号或字符串。所以 EventFilter 的权威只有 27 KC + 27 用户态 framework 两处，二者一致。

---

## 1. 0xF8 可用性负载

### 1.1 `IO80211ControllerMonitor::setDriverAvailable`（27）

函数：`__ZN24IO80211ControllerMonitor18setDriverAvailableEPvm` @ **`0xffffff80020abf1e`**（长度 0x11a，完整反汇编如下关键段）。

```asm
ffffff80020abf1e  push rbp / mov rbp,rsp / push r15,r14,rbx
ffffff80020abf28  mov  rdi, rbx                  ; rbx = this (monitor)
ffffff80020abf2b  test rsi, rsi
ffffff80020abf2e  je   ...bfee                   ; payload==NULL → 日志 "bad message"（串 @0xffffff800217a21f）
ffffff80020abf34  mov  0x10(%rbx), %rax          ; rax = this->controller
ffffff80020abf38  cmpq $0xf8, %rdx                ; ★ 长度必须恰好 0xF8
ffffff80020abf3f  jne  ...bffe                    ; 否则日志 "insufficient length %zu"（串 @0xffffff800217a259）→ 返回 0
ffffff80020abf45  mov  rsi, r14                   ; r14 = payload
ffffff80020abf52  mov  0x598(%rax), %rdi          ; ivars->fDriverAvailableReporter
ffffff80020abf59  movabs $0x44724176616c6d20, %rsi
ffffff80020abf63  mov  $1, %edx
ffffff80020abf68  call IOSimpleReporter::incrementValue(...)   ; 0xffffff8000b56590
ffffff80020abf6d  cmpl $0x0, 0x8(%r14)            ; ★ 唯一负载字段：payload+8 (u32)
ffffff80020abf72  mov  0x10(%rbx), %rax
ffffff80020abf76  je   ...bf8b                    ; ==0 → 不可用路径
; 可用路径
ffffff80020abf78  mov  0x5a0(%rax), %rdi
ffffff80020abf7f  movabs $0x2020202020205570, %rdx
ffffff80020abf89  jmp  ...bfc3
ffffff80020abf8b  mov  0x598(%rax), %rdi          ; 不可用路径：另一个 reporter 计数
ffffff80020abf92  lea  -0x700(%r15), %rsi
ffffff80020abf9e  call IOSimpleReporter::incrementValue(...)
ffffff80020abfab  mov  0x5a0(%rcx), %rdi
ffffff80020abfb2  movabs $0x2020202020205570, %rdx
ffffff80020abfbc  add  $0x244f21fe, %rdx          ; → 0x20202020446f776e
ffffff80020abfc3  mov  %r15, %rsi
ffffff80020abfc6  call IOStateReporter::setChannelState(...)   ; 0xffffff8000b57aa0
ffffff80020abfcb  test %eax,%eax
ffffff80020abfcd  jne  ...c013                    ; setChannelState 失败 → 日志，返回 0
ffffff80020abfcf  cmpl $0x0, 0x8(%r14)            ; ★ 再读一次 +8
ffffff80020abfd4  mov  0x10(%rbx), %rax
ffffff80020abfd8  setne 0xb68(%rax)               ; ★ monitor ivars->fDriverAvailable = (payload+8 != 0)
ffffff80020abfdf  mov  $1, %bl
ffffff80020abfe1  mov  %ebx, %eax                 ; return 1
```

要点：
- **长度检查是 `== 0xF8`**（不是 `>=`），不满足直接返回 0，什么都不写。
- 在函数体里对 `payload` 只有两处访存，都是 `0x8(%r14)`（同一字段读两次）。
- 唯一副作用：`monitor ivars +0xb68 = (u32@payload+8 != 0)`（`this+0x10` 是 monitor ivars，`ivars+0x00` 才是 controller，反证见 §1.4 的 `getController`/`logDebug` 用法）；reporter 只是计数/状态，与负载内容无关。
- 两个 8 字节常量 `0x4472214176617320` / `0x44724176616c6d20`（后者为 `-0x700` 的基址）是 IOReport channel id，不是负载字段。

### 1.2 调用链：只有 `postMessage` 的 `msg==0x37` 会走到它

`IO80211InfraInterface::postMessage` @ `0xffffff8002069270`：

```asm
ffffff800206a2dd  cmpl $0x37, %r15d          ; r15d = msg
ffffff800206a2e1  je   ...a50f
...
ffffff800206a50f  mov  0x128(%r13), %rax
ffffff800206a516  mov  0x168(%rax), %rax
ffffff800206a51d  test %rax,%rax / je out
ffffff800206a522  mov  0x120(%rax), %rax      ; controller ivars
ffffff800206a529  mov  0x30(%rax), %rdi       ; monitor
ffffff800206a52d  test %rdi,%rdi / je out
ffffff800206a532  mov  %r12, %rsi             ; payload
ffffff800206a535  mov  %r14, %rdx             ; length
ffffff800206a538  callq 0xffffff80020abf1e    ; setDriverAvailable
```

即：驱动（或任何内核调用者）`postMessage(0x37, payload, len)` 时，只有 `len==0xF8` 才会更新可用性状态；否则只打一条 `logDebug`。

### 1.3 第二个内核消费者：`IO80211PeerManager::reportDataPathEvents` 的 0x37 case

`__ZN18IO80211PeerManager20reportDataPathEventsEjPvm` @ `0xffffff8001f50006`，switch（msg 0x31..0x3a 跳表 @ `0xffffff8001f50d84`）把 **0x37 → `0xffffff8001f50645`**：

```asm
ffffff8001f50645  cmpq $0xf8, %r15            ; len 必须 0xF8
ffffff8001f5064c  setne %al
ffffff8001f5064f  test %r14,%r14              ; payload 非空
ffffff8001f50652  sete %cl
ffffff8001f50655  orb  %al,%cl
ffffff8001f50657  movb $1,%r13b
ffffff8001f5065a  jne  ...507fd               ; 长度/指针不符 → 跳过
ffffff8001f50660  cmpl $0x0, 0x8(%r14)        ; ★ 只读 +8
ffffff8001f50665  jne  ...507fd               ; +8 != 0（可用）→ 什么都不做
ffffff8001f5066b  ...                         ; +8 == 0（不可用）→ IO80211PeerMonitor::resetStuckDataPathCheck()
ffffff8001f506a1  callq 0xffffff8002087bc2
```

即 27 把同一份 0xF8 「driver available」负载同时用于「peer monitor 的 datapath 卡死检测重置」，判定条件同样是 `+8 == 0`。**没有第二个字段参与判定。**

### 1.4 状态落地与读取

- `__ZN24IO80211ControllerMonitor18getDriverAvailableEv` @ `0xffffff80020ac32a`：
  ```asm
  mov 0x10(%rdi), %rax     ; rax = monitor ivars
  movb 0xb68(%rax), %al    ; ivars->fDriverAvailable
  andb $0x1, %al
  ```
  同一偏移关系在 `getController()`（`0xffffff80020ac33c`）里是 `mov 0x10(%rdi),%rax; mov (%rax),%rax`，即 `ivars+0x00` 才是 controller；`setDriverAvailable` 的日志调用也正是用 `movq (%rax),%rdi` 把 controller 传给 `IO80211Controller::logDebug`。
- `apple80211RouteExternal` @ `0xffffff8002074b4c` 在分发完请求后：
  ```asm
  ffffff8002074cb4  mov 0x120(%r13), %rcx     ; controller ivars
  ffffff8002074cbb  mov 0x30(%rcx), %rcx      ; monitor
  ffffff8002074cc7  mov 0x10(%rcx), %rcx      ; monitor ivars
  ffffff8002074ccb  testb $0x1, 0xb68(%rcx)    ; 直接读可用性 bool
  ```
  说明 0xb68 是 **monitor ivars** 里、被路由/日志路径读取的状态位（`0x120(controller)` → monitor → `0x10(monitor)` = ivars → `+0xb68`）。

### 1.5 payload0（Tahoe legacy）同名函数：同样的「只看 +8」，只是长度 0xB8

payload0 `__ZN24IO80211ControllerMonitor18setDriverAvailableEPvm` @ **`0xf58c2`**：

```asm
f58d8  cmpq $0xb8, %rdx        ; Tahoe 要求 0xB8
f590d  cmpl $0x0, 0x8(%rbx)    ; 同样只读 +8
f5913  movq 0x5f0(%r15), %rdi  ; 对应的 reporter（ivar 0x5e8/0x5f0）
f5924  jmp  0xf595a
f5953  addq $0x244f21fe, %rdx
f595d  callq IOStateReporter::setChannelState
...
```

与 27 的差异：
1. 长度 0xB8 → 0xF8；
2. 27 多了 `setne 0xb68(%rax)`（把可用性落到 monitor ivars），Tahoe 版没有；
3. ivar 偏移不同（0x5e8/0x5f0 vs 0x598/0x5a0）。
**字段消费逻辑相同：payload 里只有 +8 被读。**

### 1.6 字段偏移表（0xF8 负载，27 内核视角）

| 偏移 | 大小 | 27 语义 | 证据 |
| --- | --- | --- | --- |
| `+0x00` | 8 | 27 内核不读 | 函数体内无 `(%r14)` 之外的负载访存 |
| `+0x08` | u32 | **availability**：0 = 不可用；非 0 = 可用 | `0xffffff80020abf6d`、`0xffffff80020abfd8`、`0xffffff8001f50660` |
| `+0x0C` | 0xEC | 27 内核不读（含 SimpleBCM 写入的 `+0x10 reason`） | 同上 |
| 总长 | `0xF8` | 必须精确相等 | `0xffffff80020abf38` |

补充：
- SimpleBCM 在 `+0x08` 写的是「各 radio 的 0/1 值按位或」，对单 radio 就是 1；27 只判 `!= 0`，所以语义兼容。
- SimpleBCM `+0x10 = 0xE0821803`（`PowerStateAvailabilityReason`）不被 27 内核读取；在 27 用户态 `IO80211.framework` 与 `airportd` 的 x86_64 反汇编里也搜不到该立即数（`grep -c e0821803` = 0）。保留无害，但没有证据被消费。
- 若真实驱动仍发 legacy 0xB8，SimpleBCM 的 `copyEventPayload` 会补零到 0xF8（`WirelessABI.hpp:149-161`），`+8` 在 0xB8 内会被保留，符合 27 要求。

### 1.7 判定：SimpleBCM 当前合成是否足够

**足够。** 27 只在 `length == 0xF8` 且 `u32@+8 != 0` 时才认为驱动可用，没有「其他字段必须非零」的门槛，也没有任何 flags/timestamp 校验。

最小正确填法（等价于现状）：

```c
uint8_t payload[0xF8] = {0};                 // 长度必须精确 0xF8
*(uint32_t *)(payload + 0x08) = anyRadioUp;  // 非 0 即「可用」；0 表示不可用
// +0x10 写不写 0xE0821803 都不影响 27 内核判定
```

注意：
- **不要发 0xB8** 给 27（会被 `cmpq $0xf8` 拒绝并只打日志）；
- 「不可用」事件必须显式发 `+8 == 0` 且长度 0xF8，27 才会把 `monitor ivars+0xb68` 置 0 并触发 peer monitor 的 reset。

---

## 2. `apple80211EventFilter`（请求 `0x234` = 564）

### 2.1 27 分发表：type 564 → 静态 handler（要求 `req->length == 0x21`）

27 有三套 Set 表：

| 表 | 地址 | 项数/范围 | type 564 的表项 |
| --- | --- | --- | --- |
| `gSetHandlerTable`（4 参数静态 handler） | `0xffffff800218d590` | index 563 → | **`0xffffff8001f911a4` `__ZL24setFILTER_MONITOR_EVENTS`** |
| `gInternalSetHandlerTable`（2 参数 Skywalk wrapper） | `0xffffff80021abf90` | index 563 → | `0xffffff8001f71ff8` `apple80211setFILTER_MONITOR_EVENTS`（**stub**：`mov $0xE082280E,%eax; ret`） |
| `gSetHandlerTableLegacy` | `0xffffff80021a6b10` | 457 项 | 无（564 > 457） |

`apple80211RouteExternal` @ `0xffffff8002074b4c` 的选择逻辑（`r14b` 为第 5 参数，Set 路径）：

```asm
ffffff8002074b99  movl 0x10(%r9), %eax        ; req->type（+0x10）
ffffff8002074ba2  testb %r14b,%r14b
ffffff8002074ba5  je    ...4c06               ; 旧表分支
ffffff8002074c37  cmpl $0xfffffda0, %ecx
ffffff8002074c43  decl %eax
ffffff8002074c45  leaq 0x118944(%rip), %rcx   ; → 0xffffff800218d590 (gSetHandlerTable)
ffffff8002074c4c  movq (%rcx,%rax,8), %rax
ffffff8002074c61  callq *%rax                 ; 调 4 参数静态 handler
```

handler 本体（`setFILTER_MONITOR_EVENTS` @ `0xffffff8001f911a4`，参数 `(controller, iface, userClient, apple80211req*)`）：

```asm
ffffff8001f911a4  testq %rdx,%rdx
ffffff8001f911a7  je    0xffffff8001f911c5     ; userClient==NULL → 返回 0
ffffff8001f911a9  cmpl  $0x21, 0x18(%rcx)       ; ★ req->length 必须 == 0x21
ffffff8001f911ad  jne   0xffffff8001f911c5     ; 不匹配 → 返回 0（静默成功，不设置 filter）
ffffff8001f911af  movq  0x20(%rcx), %rsi        ; req->data = filter 指针
ffffff8001f911b3  testq %rsi,%rsi
ffffff8001f911b6  je    0xffffff8001f911c5
ffffff8001f911b8  push rbp / mov rbp,rsp
ffffff8001f911bc  movq  %rdx, %rdi              ; this = IO80211APIUserClient
ffffff8001f911bf  callq 0xffffff800205dca8      ; IO80211APIUserClient::setEventFilter(filter)
ffffff8001f911c4  pop rbp
ffffff8001f911c5  xorl  %eax,%eax / retq        ; 返回 0
```

`req` 布局与 SimpleBCM 的 `bcm::Request` 一致（`+0x10 type, +0x14 value, +0x18 length, +0x20 data`），payload0 的 `setSSID`（`0x83678` 读 `0x18(%r8)`、`0x83691` 读 `0x20(%r8)`）也验证了同一布局。

### 2.2 `IO80211APIUserClient::setEventFilter`：逐字节拷贝 0x21

`__ZN20IO80211APIUserClient14setEventFilterEP21apple80211EventFilter` @ **`0xffffff800205dca8`**：

```asm
ffffff800205dca8  testq %rsi,%rsi
ffffff800205dcab  je    ...dced                 ; NULL → os_log_error + 0xE0000001
ffffff800205dcad  movq  0xd8(%rdi), %rax        ; rax = this->ivars
ffffff800205dcb4  movq  (%rsi), %rcx            ; filter+0x00 (8B)
ffffff800205dcb7  movq  0x8(%rsi), %rdx         ; filter+0x08
ffffff800205dcbb  movq  0x10(%rsi), %rdi        ; filter+0x10
ffffff800205dcbf  movq  0x18(%rsi), %r8         ; filter+0x18
ffffff800205dcc3  movb  0x20(%rsi), %sil        ; filter+0x20 (1B)
ffffff800205dcc7  movb  %sil, 0x1c0(%rax)       ; ivars+0x1c0
ffffff800205dcce  movq  %r8,  0x1b8(%rax)
ffffff800205dcd5  movq  %rdi, 0x1b0(%rax)
ffffff800205dcdc  movq  %rdx, 0x1a8(%rax)
ffffff800205dce3  movq  %rcx, 0x1a0(%rax)       ; ivars+0x1a0 .. 0x1c0 = 33 字节
ffffff800205dcea  xorl  %eax,%eax / retq
```

即 **结构总长 = 4×8 + 1 = 0x21**，没有任何别的字段。

### 2.3 位图语义：`isSubscribedToMsg`

`__ZN20IO80211APIUserClient17isSubscribedToMsgEj` @ **`0xffffff800205d908`**：

```asm
ffffff800205d90c  movq 0xd8(%rdi), %rcx
ffffff800205d913  movb $0x1, %al
ffffff800205d915  cmpb $0x0, 0x1a0(%rcx)       ; ★ filter+0x00 = all
ffffff800205d91c  jne  0xffffff800205d94d      ; all != 0 → 订阅一切
ffffff800205d91e  leal -0x1(%rsi), %edx         ; bit = event-1
ffffff800205d926  subl %eax, %esi / addl $0x7   ; 字节边界检查（编译器惯用）
ffffff800205d930  cmpl $0x107, %esi / ja out
ffffff800205d938  shrl $0x3, %edx
ffffff800205d93b  movzbl 0x1a1(%rcx,%rdx), %ecx ; ★ 位图从 ivars+0x1a1 开始
ffffff800205d943  btl  %eax, %ecx
ffffff800205d946  setb %al
```

结论：
- `filter+0x00` = **all**（非 0 时接受所有消息）；
- `filter+0x01..0x20` = **32 字节位图**，bit `(event-1)`，覆盖事件 1..256；
- 边界检查允许到 bit 0x100（事件 257），会读到 `ivars+0x1c1`——比 `setEventFilter` 拷入的 0x21 字节多 1 字节，属于 27 自身的 off-by-one，不影响结构尺寸结论（SimpleBCM 只需支持到 256）。

### 2.4 用户态交叉验证：`Apple80211FilterMonitoringEvent`（IO80211.framework）

从 dyld shared cache 提取 `IO80211.framework` 的 `__TEXT`（见 §6），函数 `Apple80211FilterMonitoringEvent` @ **`0x7ff924b77369`**：

```asm
; ref = Apple80211Ref
0x7ff924b773ac  movb 0x35(%rbx), %al
0x7ff924b773b3  movb %al, (%rcx)          ; buf[0] = ref+0x35     → all
0x7ff924b773b5  movups 0x14(%rbx), %xmm0
0x7ff924b773b9  movups 0x24(%rbx), %xmm1
0x7ff924b773bd  movups %xmm0, 0x1(%rcx)   ; buf[1..0x10]  = ref+0x14..0x23
0x7ff924b773c1  movups %xmm1, 0x11(%rcx)  ; buf[0x11..0x20] = ref+0x24..0x33
...
0x7ff924b773cb  movl $0x234, %esi         ; type = 0x234
0x7ff924b773d0  xorl %edx, %edx
0x7ff924b773d2  movl $0x21, %r8d          ; ★ size = 0x21
0x7ff924b773d8  callq Apple80211Set(...)
```

即用户态构造的正是 **all(1B) + bitmap(32B) = 33B**，与本报告 §2.2/§2.3 的内核布局逐字节吻合。这是「0x21 而非 0x20」的独立第二证据。

### 2.5 结构偏移表（27 `apple80211EventFilter`）

| 偏移 | 大小 | 语义 | 证据 |
| --- | --- | --- | --- |
| `+0x00` | u8 | `all`：非 0 = 接受所有事件；0 = 按位图 | `0xffffff800205d915` |
| `+0x01` | 32B | 事件位图，bit `N-1` = 事件 N（N=1..256） | `0xffffff800205d93b`；用户态 `0x7ff924b773bd/c1` |
| 合计 | **0x21** | 线缆/内核结构尺寸 | `0xffffff8001f911a9`（`cmp 0x21`）、`0xffffff800205dca8..dce3`（拷 33B）、`0x7ff924b773d2`（发 0x21） |

### 2.6 SimpleBCM 现状对照

`SimpleBCM/WirelessABI.hpp:446-453`：

```cpp
struct EventFilter {
    uint8_t all;
    uint8_t bitmap[31];          // ← 27 是 32
    bool accepts(uint32_t event) const {
        return all || (event && event <= sizeof(bitmap) * 8 &&   // ← 248，27 是 256
                       (bitmap[(event - 1) / 8] & (1U << ((event - 1) % 8))));
    }
};
```
`SimpleBCM/WirelessABI.hpp:532`：`static_assert(sizeof(EventFilter) == 0x20, ...)`。

逐字节对比：

| 字节 | 27 | SimpleBCM |
| --- | --- | --- |
| `+0x00` | `all` | `all` ✅ |
| `+0x01..+0x1F` | bitmap[0..30] | bitmap[0..30] ✅ |
| `+0x20` | bitmap[31] | **不存在** ❌ |
| 长度 | 0x21 | 0x20 ❌ |

行为后果（`SimpleBCM/UserClient.cpp:413-418`）：

```cpp
if (set && abi.filterMonitorEvents && request == abi.filterMonitorEvents) {
    if (legacy.request.length != sizeof(bcm::EventFilter) || header->length < sizeof(bcm::EventFilter))
        goto done;                                  // result 仍是 kIOReturnBadArgument
    memcpy(&filter, shadow, sizeof(filter));        // 只拷 0x20
    result = kIOReturnSuccess;
}
```

- 27 客户端（按 §2.4 发 `header->length = 0x21`，`legacy.request.length` 在 Set 路径被赋为 `header->length`，见 `UserClient.cpp:389`）→ `0x21 != 0x20` → **goto done，返回 bad argument，filter 不更新**。
- 因为 `BCM80211UserClient::start()` 把 `filter.all` 置 1（`UserClient.cpp:69`），失败后 filter 仍是「全接受」：
  - `receive()`（`UserClient.cpp:617`）继续把**所有**事件投递给该客户端；
  - `startMonitor()` 的 replay 判断（`UserClient.cpp:565`）也因为 `all==1` 继续成立。
  - 这与运行期观测一致：`DriverAvailabilityReplays` 仍在增长（见 §5），所以**当前没有可观测的硬故障**；问题是客户端的过滤请求被静默忽略（事件超集），且 `bitmap[31]`（事件 249..256）即使被设置也永远不生效。
- 27 自身对长度不符是**返回 0（成功 no-op）**，SimpleBCM 返回 bad argument 更严格；机场/客户端可能把该错误当作过滤失败处理。

---

## 3. payload0 侧（`IO80211FamilyLegacy`）一致性

结论：**payload0 没有 564 的对应 handler，无法做 legacy 侧对照。**

- `_gSetHandlerTable` 只有 417 项（`Tools/profiles.py` 与 `Docs/Analysis-20261117-driver-side.md` §1.2 已核实），564 远超范围；`apple80211_ioctl_set`（payload0 `0x91ede`）对 `type>417` 直接返回 0x66。
- `nm payload0.bin | grep -iE 'FILTER_MONITOR|EventFilter|setEventFilter'` → 空；`strings payload0.bin | grep FILTER_MONITOR` → 空。
- `apple80211setFILTER_MONITOR_EVENTS` 只存在于 27 KC 的 `gInternalSetHandlerTable`，而且是 stub（返回 `0xE082280E`），真正实现只在 27 的 `gSetHandlerTable` 静态 handler + `IO80211APIUserClient::setEventFilter`。
- 因此 SimpleBCM 的 `0x20`/`0x234` 常量更可能来自 Tahoe 时代 `IO80211Family` 的（非 legacy）实现或头文件，而不是 payload0；本次无法从 payload0 得到交叉证据。

---

## 4. SimpleBCM 最小改动清单（只描述，未改代码）

1. **`SimpleBCM/WirelessABI.hpp:446-453`：`EventFilter` 扩到 0x21**
   - `uint8_t bitmap[31]` → `uint8_t bitmap[32]`；
   - `accepts()` 的上界自动变成 256（`sizeof(bitmap) * 8`），无需改表达式；
   - `WirelessABI.hpp:532` 的 `static_assert` 改为 `== 0x21`。

2. **`SimpleBCM/UserClient.cpp:413-418`：本地拦截同时接受 0x21 与 0x20（并归一化）**
   ```cpp
   const auto n = header->length;               // Set 路径 legacy.request.length == header->length
   if (n == 0x21) {                             // 27
       memcpy(&filter, shadow, 0x21);
   } else if (n == 0x20) {                      // 旧 ABI（Tahoe 时代）
       memcpy(&filter, shadow, 0x20);
       filter.bitmap[31] = 0;                   // 高位不存在 → 事件 249..256 视为未订阅
   } else {
       // 27 语义：长度不符是静默成功 no-op（建议加计数/DBGLOG，便于取证）
   }
   result = kIOReturnSuccess;
   ```
   - 不再用 `sizeof(bcm::EventFilter)`（0x21）做唯一判据，否则旧 0x20 客户端会被误拒；
   - `header->length < sizeof(...)` 这条冗余判断可一并移除。

3. **`SimpleBCM/UserClient.cpp:69` 的默认 `filter.all = 1`：保持或按需调整**
   - 现状保证「filter 未设置前事件全投递」，是安全的；
   - 但修改 1/2 后，27 的 filter 会真正生效：若 27 airportd 下发的位图**不含 0x37**，`startMonitor` 的 availability replay 会被 `accepts()` 挡住（现在被 `all=1` 掩盖）。
   - 建议先加一条 DBGLOG（`all`、`bitmap[6]` 的 bit6、`accepts(0x37)` 结果、收到的 length），在一次 `MonitorStart` 后确认再决定是否保留 `all=1`。

4. **0xF8 负载：不需要改**
   - 长度 0xF8、`+8` 非 0 已经符合 27；`+0x10` reason 保留即可（无内核消费者）；
   - 可选：在 `startMonitor`/`refreshAvailability` 处加断言或属性，确认 `abi.driverAvailableSize == 0xF8`（27）且 `+8` 非 0。

5. **（可选）与 27 的错误语义对齐**
   - 对未知长度的 0x234 返回成功（no-op）而非 `kIOReturnBadArgument`，避免客户端把「过滤请求失败」当致命错误；若担心掩盖问题，用 boot-arg 门控或仅加日志。

6. **无需改动 payload0 内嵌镜像/分发表**：564 在 legacy 表中不存在，本地拦截本来就是唯一实现。

---

## 5. 证据地址总表

| 主题 | 地址 | 说明 |
| --- | --- | --- |
| 0xF8 | `0xffffff80020abf1e` | `IO80211ControllerMonitor::setDriverAvailable` |
| 0xF8 | `0xffffff80020abf38` | `cmpq $0xf8,%rdx`（精确长度） |
| 0xF8 | `0xffffff80020abf6d` | `cmpl $0,0x8(%r14)` |
| 0xF8 | `0xffffff80020abfd8` | `setne 0xb68(%rax)`（monitor ivars 可用性 bool） |
| 0xF8 | `0xffffff80020ac32a` | `getDriverAvailable()` 读 ivars `+0xb68 & 1` |
| 0xF8 | `0xffffff8002069270` | `IO80211InfraInterface::postMessage` |
| 0xF8 | `0xffffff800206a2dd` / `0xffffff800206a538` | `cmp $0x37` → `call setDriverAvailable` |
| 0xF8 | `0xffffff8001f50006` / `0xffffff8001f50645` | `IO80211PeerManager::reportDataPathEvents` 的 0x37 case |
| 0xF8 | `0xffffff8002074ccb` | `apple80211RouteExternal` 读 `0xb68` |
| 0xF8 | payload0 `0xf58c2` / `0xf58d8` | Tahoe legacy `setDriverAvailable`，`cmp $0xb8` |
| Filter | `0xffffff8001f911a4` | `setFILTER_MONITOR_EVENTS` 静态 handler |
| Filter | `0xffffff8001f911a9` | `cmpl $0x21,0x18(%rcx)` |
| Filter | `0xffffff8001f911bf` | `call IO80211APIUserClient::setEventFilter` |
| Filter | `0xffffff800205dca8` | `setEventFilter` 拷贝 0x21 字节 |
| Filter | `0xffffff800205d908` | `isSubscribedToMsg`（all + 位图） |
| Filter | `0xffffff800218d590` | `gSetHandlerTable`（index 563 → 0x1f911a4） |
| Filter | `0xffffff80021abf90` | `gInternalSetHandlerTable`（index 563 → 0x1f71ff8 stub） |
| Filter | `0xffffff80021a6b10` | `gSetHandlerTableLegacy`（457 项） |
| Filter | `0xffffff8002074b4c` | `apple80211RouteExternal`（表选择 + `req->type@+0x10`） |
| Filter（用户态） | `0x7ff924b77369` / `0x7ff924b773d2` | `Apple80211FilterMonitoringEvent`，size=0x21 |
| SimpleBCM | `UserClient.cpp:69` | `filter.all = 1` 默认 |
| SimpleBCM | `UserClient.cpp:413-418` | 0x20 精确比较 + memcpy 0x20 |
| SimpleBCM | `UserClient.cpp:565` / `:617` | replay / receive 的 `filter.accepts` 门控 |
| SimpleBCM | `WirelessABI.hpp:446-453` / `:532` | `EventFilter{all, bitmap[31]}`，`sizeof==0x20` |

运行期证据（2026-11-18T05:2x，`ioreg -rn SimpleBCM -l`）：

```
DriverAvailabilityEvents    = 0
PowerAvailabilityEvents    = 1
DriverAvailabilityReplays  = 464      (采样时在增长；另一轮快照 400)
DroppedEvents              = 0
LastAvailabilityReadResult = 0
ActiveABI                  = "GoldenGate"
```

统一日志（`log show --last 20m`，只读）：

```
... (Embedded) IOCTL (from pid 217) not recognized: 483 out of 417   （每 ~10s 一组）
... (IO80211) Apple80211BindToInterfaceWithService: <private> useIOUCWhenPossible TRUE ...
```

- 说明 27 客户端仍在持续向 legacy 路径下发 483（被 payload0 表拒绝，返回 0x66）；
- 该日志里**没有** 564 的记录，与「564 被 SimpleBCM 本地拦截、不进入 payload0 表」一致；
- 由于 483 每 10 秒刷一次 `setHistory`，最近 16 条 Set 历史里看不到 564 不能证明 0x234 未发送。

---

## 6. 复现命令（只读）

```sh
# 1) KC 反汇编（把 KC 的某个区间包成合成 Mach-O 再交给 llvm-objdump；只写 /tmp）
#    /tmp/kcdis.py <start> <stop> [image]     —— 本会话复用了该 helper
/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3 /tmp/kcdis.py \
  0xffffff80020abf1e 0xffffff80020ac038

# 2) 解码 27 的 Set 表项（type 564）
python3 - <<'EOF'
import sys; sys.path.insert(0,'simplebcm-r27/Tools')
from kernel_collection import KernelCollection
kc=KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
im=kc.images['com.apple.iokit.IO80211Family']
base=im.symbols['__ZL16gSetHandlerTable'] if '__ZL16gSetHandlerTable' in im.symbols else 0xffffff800218d590
print(hex(kc.pointer(base + 563*8)))
EOF

# 3) 用户态 IO80211.framework（dyld shared cache 子缓存 .01，unslid 0x7ff924b52000）
python3 - <<'EOF'
import struct
p='/System/Library/dyld/dyld_shared_cache_x86_64.01'
off=0x7ff924b52000-0x7ff900000000
with open(p,'rb') as f: f.seek(off); d=f.read(0x6b000)
open('/tmp/io80211_fw.bin','wb').write(d)
EOF
# 再用单段 Mach-O 包装（__TEXT vmaddr=0x7ff924b52000，__text @0x7ff924b52c20）后：
llvm-objdump -d --arch=x86_64 --start-address=0x7ff924b77369 --stop-address=0x7ff924b77470 /tmp/fw.macho

# 4) 运行期（只读）
ioreg -rn SimpleBCM -l | grep -E 'DriverAvailabilityEvents|PowerAvailabilityEvents|DriverAvailabilityReplays|DroppedEvents|LastAvailabilityReadResult'
log show --last 2m --style compact | grep -E 'not recognized|iouc|SimpleBCM'
```

---

## 7. 未验证 / 不确定项

1. **0xF8 负载在用户态的消费**：27 内核只读 `+8`，但 airportd/其他用户态库是否解析其余字段（flags/timestamp/reason）本次未能确认。`IO80211.framework` 的 `__TEXT` 中既没有 `0xF8` 长度常量，也没有 `0xE0821803` 立即数；事件 0x37 的解析可能在未提取的库里。**结论「SimpleBCM 合成足够」只对 27 内核成立。**
2. **27 airportd 是否在每次 monitor 启动时下发 0x234**：setHistory 被 483 轮询快速冲刷，未直接观测到；只能确认 27 的 handler 与用户态 constructor 都按 0x21 工作。
3. **`header->length` 是否恒等于 `req->length`**：由 SimpleBCM 的扫描/关联尺寸校验路径反推（`header->length` 被用于 0x8E8/0x290 比较），未逐指令核对 framework 的 legacy 命令头赋值。若两者不等，§2.6 的「0x21 被拒」结论需要重新验证。
4. **`gSetHandlerTable` vs `gInternalSetHandlerTable` 的运行时选择**：本报告依据 `apple80211RouteExternal` 的 `r14b==true` 分支（`gSetHandlerTable`）与「stub 表项不可能承载线上过滤 API」判断静态 handler 是实际路径；未在运行期打点确认。
5. **`isSubscribedToMsg` 的 0x107 边界**：允许事件 257 读到 `ivars+0x1c1`（超出拷贝的 0x21 字节），是 27 的 off-by-one；SimpleBCM 按 256 位实现是安全子集。
6. **`0xE0821803` 的语义**：未找到定义/消费者，仅知 SimpleBCM 将其写在 `+0x10`。
7. **`0x21` 与 `0x20` 的 Tahoe 版本归属**：payload0 无此 handler，无法证明 Tahoe 用户态曾发 0x20；SimpleBCM 的 0x20 可能来自 Tahoe 非 legacy 实现或头文件，未验证。

---

## 附：27 `setDriverAvailable` 伪代码

```c
bool IO80211ControllerMonitor::setDriverAvailable(void *msg, size_t len) {
    if (!msg) { logDebug("IO80211ControllerMonitor::setDriverAvailable bad message\n"); return false; }
    if (len != 0xF8) { logDebug("...insufficient length %zu\n", len); return false; }
    IOSimpleReporter::incrementValue(fDriverAvailableReporter, 0x44724176616c6d20, 1);
    uint32_t available = *(uint32_t *)((uint8_t *)msg + 8);
    if (available) {
        if (IOStateReporter::setChannelState(fDriverAvailableStateReporter, 0x4472214176617320, 0x2020202020205570) != 0) {
            logDebug("...setChannelState\n"); return false; }
    } else {
        if (IOSimpleReporter::incrementValue(fDriverNotAvailableReporter, 0x4472214176616c20, 1) != 0) {
            logDebug("...incrementValue failed\n"); return false; }
        if (IOStateReporter::setChannelState(..., 0x20202020446f776e) != 0) { ... return false; }
    }
    ivars->fDriverAvailable = (available != 0);   // monitor ivars +0xb68
    return true;
}
```
