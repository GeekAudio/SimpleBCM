# SimpleBCM 链路状态、`IOLinkActiveCount` 与 GET 103 `-3903` 逆向报告

日期：2026-11-18（Asia/Shanghai）
机器：macOS 27.2（26B123 / Darwin 27.2.0，x86_64 Intel），BCM43602，`AirPort_BrcmNIC_Interface`
代码：`simplebcm-r27`，分支 `wifi-assoc-probe`，取证基线 HEAD `84348ff`
只读取证：未改 `/System`、`/Library`、EFI，未构建/部署/重启。所有实验仅在 `/tmp` 与工作区文档。

> 版本注记：本报告取证时 HEAD 为 `84348ff`。写作后父代理已提交 `211c167`、`a5dc5ed`、`13587a2`；
> 其中 `13587a2` 已按本报告 §6.1 的方向在 `UserClient.cpp` 中加入“re-join 保留 current-network 记录、
> 仅在显式 disassociate 时清除”。因此 §5.3 的 103 时间窗口分析对 `84348ff` 成立；新 HEAD 下
> re-join 窗口已收窄，但**首次关联/冷启动**在首次匹配扫描结果到达前仍可能返回 `0x66`，需按新 HEAD 复验。

---

## 0. 结论摘要（先看这里）

1. **`Apple80211GetWithIOCTL` 不在内核里。** `log show` 的进程是 `a2xhost-mac`，子系统标签是 `(IO80211)`；该函数位于用户态
   `/System/Library/PrivateFrameworks/IO80211.framework/Versions/A/IO80211`（dyld shared cache x86_64），
   符号 `_Apple80211GetWithIOCTL` @ `0x7FF924B6119D`。payload0、payload1、27 的 `BootKernelExtensions.kc`
   都没有这个符号或字符串。因此那条 `-3903` 是**用户态函数返回值**，不是内核 IO80211 的日志。
2. **用户态 103 分支不检查 `linkState()` / `isAssociated()` / `IOLinkActiveCount`。** 它把 103 包成 0x8E8 的
   `apple80211_scan_result` 请求，调用 `Apple80211IOCTLGetWrapper`；失败时把内核错误码映射成负的 Apple80211 错误：
   `errno 0x66 (EOPNOTSUPP)` 或 `6 (ENXIO)` → `-3903/0xfffff0c1`，`errno 0x16 (EINVAL)` → `-3900/0xfffff0c4`。
   证据：`0x7FF924B63109`（103 分支）→ `0x7FF924B6314E`（wrapper）→ `0x7FF924B63C99`（错误路径）。
3. **内核侧 103 有三套 handler，都会在“未实现/无 skywalk 接口”时返回 `0x66`，再被用户态映射成 `-3903`：**
   - payload0 的 legacy get 表 103 槽位是**三指令桩** `getCurrentNetwork` @ `0x7c80f`：
     `push rbp; mov rsp,rbp; mov $0x66,eax; pop rbp; ret`（`0x7c813` 为 `mov $0x66,%eax`）。
   - 27 新 get 表 103 槽位 → `getCURRENT_NETWORK` @ `0xffffff8001f7f7d0`：`rsi`（skywalk 接口）为空时在
     `0x1f7f827` 返回 `0x66`；它只检查 `req->length == 0x8E8`、`req->data != NULL`，然后
     `IO80211SkywalkInterface::routeIoctlToWcl` @ `0xffffff8001ffe712`；没有 WCL 时返回 `0xE082280F` 并回退到
     `apple80211getCURRENT_NETWORK` @ `0xffffff8001f6794e`。
   - 27 legacy get 表 103 槽位 → `getCurrentNetwork` @ `0xffffff800202e1b9`，同样是 `rsi == NULL` → `0x66`
     （`0x202e2f9`）。
4. **`IOLinkActiveCount` 在本机 27 的 BootKernelExtensions + payload0/1 静态代码中没有找到递增路径，`setLinkState` 不会改它。** 该属性由
   `IONetworkingFamily` 的 `IOEthernetInterface::init` @ `0xffffff8002470384` 创建：
   `OSNumber::withNumber(0, 64)`（`0x2470651` 调 `0xffffff8000a7df90`，`esi=0x40`）+ `setProperty("IOLinkActiveCount", ...)`
   （`0x2470669` 取字符串 `0xffffff8002481660`，`0x2470676` 调 vtable+0x268）。对象保存在
   `[interface+0x140]+0x20`；之后只有 `IOEthernetInterface::inputEvent` @ `0x2472054` 把它当 `unsigned32BitValue`
   **读**一次，以及 `free` @ `0x24708b8` 释放；整个 BootKernelExtensions 里**没有**任何
   `OSNumber::setValue/addValue` 的调用（直接调用扫描为 0），也没有第二个 `IOLinkActiveCount` 字符串引用。
   **它是 27 上一个只写一次的 0，不是 link-up 指示器。**
5. **`IO80211Interface::setLinkState` 的语义已确定：** 枚举 `0 = Undefined`、`1 = Down`、`2 = Up`
   （MacKernelSDK `IO80211Interface.h:30-36` 与反汇编一致）。真正干活的是二参数重载
   `setLinkState(IO80211LinkState, unsigned)` @ payload0 `0x9859c`；三参数重载 @ `0x9857c` 只是经
   vtable+0xAB0 转发到二参数（`0x9857c`：`movq 0xAB0(%rax),%rax; movl %ecx,%edx; jmp *%rax`）。
   `linkState()` @ `0x98eb6` 只是 `movl 0x208(%rdi),%eax; ret`。
6. **link up 需要调用：`setLinkState(interface, 2, reason)`**；它会自己完成配套的 controller 调用
   （controller vtable+0x980，up 时 `esi=3, rdx=primaryInterface, r8=0`）以及 `startOutputQueues`、
   `updateLinkSpeed`、peer manager enable、link-changed event 4/2/3；**不需要**再单独调 controller。
   down 用 `setLinkState(interface, 1, reason)`。但**它不会把 `IOLinkActiveCount` 变 1**。
7. **103 与 `IOLinkActiveCount` 无关，当前 103 实际已经在工作。** 本会话 05:00 左右读到
   `Legacy103Patched=1`、`CurrentNetworkValid=1`、`Last103OutputSize=2280`、`C103Hits` 3 秒内
   1875 → 1882（约 2.3 次/秒），且 `log show --last 90m` 里 `type 103` 的最后一条错误停在
   **04:39:46**，之后没有新的 103 错误。`C103Hits` 同时被 legacy handler 和 user client 分支递增，
   所以它只能证明“至少有一条 103 路由在应答”，不能区分路由。
8. **04:37–04:39 的 103 `-3903` 最可能的剩余原因是“已关联但 `CurrentNetworkValid` 还没置 1”**：
   `legacyGetCurrentNetwork` 在 `Bridge.cpp:64` 对 `currentNetworkValid == 0` 直接 `return 0x66`；
   `UserClient.cpp:401-412` 在 `CurrentNetworkValid == 0` 时也不本地应答，而是转发给驱动。
   `CurrentNetworkValid` 只在一次包含关联 SSID 的扫描结果到达后才置 1（`UserClient.cpp:485`），
   所以关联成功到下一次匹配扫描结果之间，103 仍会返回 `0x66` → `-3903`。
9. **最小可行补丁分两件事，不要混为一谈：**
   - 103：保留现有 legacy 表 + user client 拦截即可；若要去掉“关联后、首次匹配扫描前”的窗口，
     应在关联成功时用关联结果/定向扫描填充 `currentNetworkBuffer` 并置 `currentNetworkValid=1`，
     而不是调用 `setLinkState`。
   - link 状态：若确实要把 `IO80211Interface::linkState()` 推到 2，可解析
     `__ZN16IO80211Interface12setLinkStateE16IO80211LinkStatej` 并在关联完成时
     `setLinkState(interface, 2, 0)`；断开时 `setLinkState(interface, 1, reason)`。这是**独立的正确性补丁**，
     对 103 和 `IOLinkActiveCount` 都没有直接作用。
10. **`IOLinkActiveCount` 不要伪造。** 它不参与 link/103 判定，手工 `setProperty(..., 1)` 只会改变 ioreg 显示，
    属于掩盖症状；若需要可观测的 link 状态，应新增诊断属性读取 `linkState()`（`0x98eb6`）或
    `getPrimaryInterfaceLinkState()`（`0x90020`）。

---

## 1. 观测面纠正：`Apple80211GetWithIOCTL` 是用户态函数

### 1.1 `log show` 证据

```text
2026-11-18 04:37:21.514777+0800 ... 217 ... a2xhost-mac: (IO80211) Apple80211GetWithIOCTL:14560
  @[86.957743] ifname['en1'] IOCTL type 96/'APPLE80211_IOC_VIRTUAL_IF_ROLE' return -3903/0xfffff0c1
```

进程是 `a2xhost-mac`（airportd 的 a2x 宿主），不是 kernel。`(IO80211)` 是用户态 os_log 的 subsystem/category，
不是 `IO80211Family.kext` 的内核日志前缀。

### 1.2 符号与位置

```text
$ /usr/bin/dyld_info -arch x86_64 -function_starts \
    /System/Library/PrivateFrameworks/IO80211.framework/Versions/A/IO80211
 0x7FF924B6119D  _Apple80211GetWithIOCTL
 0x7FF924B6DBF4  _Apple80211IOCTLGetWrapper
```

```text
$ /usr/bin/dyld_info -arch x86_64 -section __TEXT __cstring ...
0x7FF924BABBC4 "Apple80211GetWithIOCTL"
0x7FF924BABB16 "/AppleInternal/.../Sources/IO80211/IO80211API/Apple80211API.c"
```

- 函数总长到下一个函数 `_Apple80211IOCTLGetWrapper`（`0x7FF924B6DBF4`）之前，即约 `0xC4xx` 字节。
- 函数内构造日志时把 **行号 0x38E0 = 14560** 写入 os_log 结构：
  `0x7FF924B6D595: movl $0x38e0, 0xe(%r8)`，与日志中的 `:14560` 完全对应。
- 27 KC 的 `com.apple.iokit.IO80211Family`、payload0、payload1 都没有
  `GetWithIOCTL` 字符串，也没有 `_Apple80211GetWithIOCTL` 符号。

**结论：这条日志是用户态 IO80211.framework 在调用 IOCTL 后打印的返回值，不是内核 IO80211 直接打印的。**

---

## 2. 用户态 103 分支：`-3903` 从哪来

### 2.1 类型分发

`_Apple80211GetWithIOCTL` 入口把第二个参数（type）放到 `0x10(%r15)`，然后：

```asm
7ff924b6127d:  movl 0x10(%r15), %eax
7ff924b61281:  cmpl $0x150, %eax
7ff924b61286:  jg   0x7ff924b61301
7ff924b61288:  leal 0x1(%rax), %ecx
7ff924b6128b:  cmpl $0x10a, %ecx
7ff924b61291:  ja   0x7ff924b61b8c
7ff924b61297:  leaq 0xc4f2(%rip), %rax     ; jump table @0x7ff924b6d790
7ff924b6129e:  movslq (%rax,%rcx,4), %rcx
7ff924b612a2:  addq %rax, %rcx
7ff924b612ac:  jmpq *%rcx
```

索引是 `type + 1`；表项是相对 `0x7FF924B6D790` 的 32 位偏移。解出 **type 103（0x67）的目标是
`0x7FF924B63109`**。

### 2.2 103 分支做了什么

```asm
7ff924b63109:  movl $0xfffff0c4, %r14d       ; 默认 -3900
7ff924b6310f:  testl %r13d, %r13d
7ff924b63112:  je    0x7ff924b6d4db           ; 长度为 0 -> -3900
7ff924b63118:  leaq  -0x8070(%rbp), %rbx
7ff924b6311f:  movl  $0x8e8, %esi
7ff924b63124:  movq  %rbx, %rdi
7ff924b63127:  callq 0x7ff924bbd2aa           ; bzero(buf, 0x8E8)
7ff924b6312c:  movw  $0x800, 0x8a(%rbx)       ; scan_result IE length 字段
7ff924b63139:  movl  $0x8e8, 0x18(%rsi)       ; req->length = 0x8E8
7ff924b63140:  movq  %rbx, 0x20(%rsi)         ; req->data = buf
7ff924b6314e:  callq 0x7ff924b6dbf4           ; _Apple80211IOCTLGetWrapper
7ff924b63153:  testl %eax, %eax
7ff924b63155:  jne   0x7ff924b63c99           ; 错误路径
```

即：**103 被当作 0x8E8 的 `apple80211_scan_result` 请求发下去**；用户态函数本身没有
`linkState`/`isAssociated`/`IOLinkActiveCount` 检查。

### 2.3 错误映射：0x66/6 → `-3903`，0x16 → `-3900`

```asm
7ff924b63c99:  callq 0x7ff924bbd2b6           ; ___error (stub)
7ff924b63c9e:  movl  $0xfffff0c1, %r14d       ; 默认 -3903 / 0xfffff0c1
7ff924b63ca4:  cmpl  $0x66, (%rax)            ; EOPNOTSUPP
7ff924b63ca7:  je    0x7ff924b6d4d2           ; 返回 -3903
7ff924b63cad:  callq 0x7ff924bbd2b6
7ff924b63cb2:  cmpl  $0x6, (%rax)             ; ENXIO
7ff924b63cb5:  je    0x7ff924b6d4d2           ; 返回 -3903
7ff924b63cbb:  callq 0x7ff924bbd2b6
7ff924b63cc0:  movl  $0xfffff0c4, %r14d       ; -3900
7ff924b63cc6:  cmpl  $0x16, (%rax)            ; EINVAL
7ff924b63cc9:  je    0x7ff924b6d4d2
7ff924b63ccf:  callq 0x7ff924bbd2b6
7ff924b63cd4:  movl  (%rax), %eax             ; 其他 errno
7ff924b63cd6:  jmp   0x7ff924b6cc53
```

`0xfffff0c1` 的有符号值就是 `-3903`。所以日志里的 `-3903` 等价于：
**内核/IOCTL 层返回了 `0x66` (EOPNOTSUPP) 或 `6` (ENXIO)**。

### 2.4 wrapper 的两条路由

`_Apple80211IOCTLGetWrapper` @ `0x7FF924B6DBF4`：

```asm
7ff924b6dc34:  cmpb $0x0, 0x6f(%rbx)
7ff924b6dc38:  je   0x7ff924b6dc72
...                                       ; 0x6f != 0：走 _Apple80211AWDLCompatibilityCall
                                          ;   （AWDL 兼容路径，@0x7FF924B9DBC0）
7ff924b6dc72:  cmpb $0x0, 0x179(%rbx)
7ff924b6dc79:  je   0x7ff924b6dd5e
...                                       ; 0x179 != 0：走 0x3C30 用户客户端命令路径
7ff924b6dd5e:  ...                        ; 否则走 BSD ifnet ioctl 路径
7ff924b6dd9e:  movl $0xc0206911, %esi     ; SIOCGIFMEDIA（只用于链路/介质查询日志）
```

日志里有 `Apple80211BindToInterfaceWithService ... useIOUCWhenPossible TRUE`，所以 airportd 正常情况下
优先走 **IOUC/用户客户端**；但 `Apple80211GetWithIOCTL` 也保留 BSD ioctl 路由，不能只按一个路由解释所有调用。

### 2.5 内核侧 103 的三条实现

| 路由 | 表/槽位 | 目标 | 返回 `0x66` 的条件 |
| --- | --- | --- | --- |
| payload0 legacy get 表（BSD ioctl） | 表 `0x14a140`，index 102 | `getCurrentNetwork` @ `0x7c80f` | **无条件**：`0x7c813: movl $0x66,%eax` |
| 27 新 get 表（IOUC） | `gGetHandlerTable` `0xffffff800218c150`，index 102 | `getCURRENT_NETWORK` @ `0xffffff8001f7f7d0` | `rsi`（skywalk 接口）为空：`0x1f7f7da je 0x1f7f827`，`0x1f7f827: movl $0x66,%eax` |
| 27 legacy get 表（BSD ioctl） | `_gGetHandlerTableLegacy` `0xffffff800219e6e0`，index 102 | `getCurrentNetwork` @ `0xffffff800202e1b9` | `rsi` 为空：`0x202e1fc je 0x202e2f9`，`0x202e2f9: movl $0x66,%eax` |

27 的两个 handler 都**没有**调用 `IO80211Interface::linkState()` 或 `IOLinkActiveCount`：

- `0x1f7f7d0`：只检查 `rsi != 0`、`req->length == 0x8E8`、`req->data != 0`，然后
  `call 0xffffff8001ffe712`（`routeIoctlToWcl`）；若返回 `0xE082280F` 才回退到
  `apple80211getCURRENT_NETWORK` @ `0xffffff8001f6794e`。
- `0x202e1b9`：同样的空 skywalk 检查，然后同样 `routeIoctlToWcl` + 回退。
- `apple80211getCURRENT_NETWORK` @ `0x1f6794e` 也是先调 controller vtable+0xCF8；失败才查属性并调
  vtable+0x778，没查到返回 `0xE082280E`。它不看 `IOLinkActiveCount`。

**因此 103 的 `-3903` 根因是“103 handler 返回 0x66/ENXIO”，不是链路计数为 0。** 具体到这份代码，
还有第三种来源：我们自己新加的 handler 在 `currentNetworkValid == 0` 时也会主动 `return 0x66`
（见 §4.1）。

---

## 3. `IO80211Interface::setLinkState` / `linkState()` 逐指令

### 3.1 枚举（头文件 + 反汇编一致）

`MacKernelSDK/Headers/IOKit/80211/IO80211Interface.h:30-36`：

```c
enum IO80211LinkState {
    kIO80211NetworkLinkUndefined,   // 0: 创建时的初始状态
    kIO80211NetworkLinkDown,        // 1: 不能发送
    kIO80211NetworkLinkUp,          // 2: 可以发送
};
```

`IO80211Interface.h:102-103` 声明两个重载：

```c
virtual bool setLinkState(IO80211LinkState, unsigned int);
virtual bool setLinkState(IO80211LinkState, int, unsigned int);
```

### 3.2 二参数重载 `setLinkState(IO80211LinkState, unsigned)` @ `0x9859c`

关键指令：

```asm
09859c:  push rbp; mov rsp,rbp; ... sub $0x48,%rsp
0985bd:  cmpl %esi, 0x208(%rdi)        ; 与当前 linkState 比较
0985c3:  je   0x98a94                 ; 相同 -> 直接返回 true
0985c9:  movl %edx, %r14d             ; r14d = reason
0985cc:  movl %esi, %r15d             ; r15d = state
0985cf:  movq %rdi, %r12              ; this
0985d2:  movq (%rdi), %rax
0985d5:  callq *0x688(%rax)           ; getController()
0985e1:  callq *0x138(%rcx)           ; controller/workloop 前置检查
0985e7:  testb %al,%al
0985e9:  je   0x986c1                 ; 失败 -> 打日志并返回 false
...
09861b:  movq 0x290(%r12), %rdi       ; controller
098623:  movl $0xc03069c9, %esi       ; GetCommand
098628:  movl $0x9c, %edx             ; type 156: link-changed event data
098633:  callq 0x8ee5c               ; IO80211Controller::apple80211RequestIoctl
...
09866b:  movl %r15d, 0x208(%r12)      ; 真正写入 linkState
098673:  cmpl $0x2, %r15d
098677:  je   0x986e9                 ; state == 2 -> up 路径
098679:  cmpl $0x1, %r15d
09867d:  jne  0x98839                 ; 其他值 -> 返回 false，不改状态
```

**state == 2（Up）路径**（`0x986e9` 起）：

```asm
0986e9:  movq %r12,%rdi
0986ec:  callq 0x96086               ; getBSDName()
0986f1:  leaq 0x128f69,%rdi          ; "AirPort: Link Up on %s"
...
098705:  callq 0x98d38               ; startOutputQueues()
09870a:  movq 0x2d0(%r12),%rbx       ; interface monitor
...
098712-09876c: ...                    ; monitor 活动/记录
0987cd:  movq 0x290(%r12),%rdi       ; controller
0987d5:  callq <relocated>           ; getPrimaryInterface()
0987dd:  je   0x98839                ; 没有 primary interface -> false
0987e5:  callq 0x9814a               ; updateLinkSpeed()
0987ea:  movb $1,0x20c(%r12)
098811:  callq *0x980(%rax)           ; controller 配套调用: (3, primary, 0)
098817:  ...                          ; peer manager enable
09899b:  callq 0x9012c               ; calculateInterfacesAvaiability()
0989ab:  callq 0x97a70               ; reportDataTransferRates()
```

**state == 1（Down）路径**（`0x98683` 起）：

```asm
098683:  callq 0x96086               ; getBSDName()
0986a3..0986bc: 遍历 reasonDescList 找 reason 字符串
098845:  leaq 0x128eda,%rdi          ; "AirPort: Link Down on %s. Reason %u (%s)."
...
0988b7:  movb $1,0x20c(%r12)
0988d7:  callq *0x980(%rax)           ; controller 配套调用: (1, 0, 0)
0988dd:  ...                          ; reason == 0 且事件数据有标志 -> 0x20d=0
098918:  callq 0x98bfc               ; stopOutputQueues()
098971:  callq 0xca902               ; RSNSupplicant::linkDown()
09898a:  callq 0x63a3c               ; peer manager disable
09898f:  movq $0,0x210(%r12)
```

**两种状态最后都走 `0x9899b` 的共同收尾**：

```asm
09899b:  callq 0x9012c               ; calculateInterfacesAvaiability()
0989ab:  callq 0x97a70               ; reportDataTransferRates()
0989e4:  movl $0x28,%edi; call ...   ; 分配 0x28 事件数据
098a09:  movabs $0x200000000e,%rax   ; event type/字段
...
098a3e:  movl $4,%esi
098a46:  callq 0x96a36               ; postMessage(4, event, 0x28)  link-changed
098a4e:  movl $2,%esi
098a57:  callq 0x96a36               ; postMessage(2, 0, 0)
098a5f:  movl $3,%esi
098a68:  callq 0x96a36               ; postMessage(3, 0, 0)
```

返回值：`0x98a85 testq %rbx,%rbx; setne %bl`，即**事件缓冲区分配成功才返回 true**；
同状态提前返回 true（`0x98588`）。

### 3.3 三参数重载 `setLinkState(IO80211LinkState, int, unsigned)` @ `0x9857c`

```asm
09857c:  push rbp; mov rsp,rbp
098580:  cmpl %esi, 0x208(%rdi)
098586:  jne  0x9858c
098588:  movb $1,%al; ret
09858c:  movq (%rdi),%rax
09858f:  movq 0xab0(%rax),%rax       ; vtable+0xAB0 = 二参数 setLinkState
098596:  movl %ecx,%edx              ; 第四个参数（unsigned）作为 reason
098599:  jmpq *%rax
```

vtable 校验：`__ZTV16IO80211Interface` @ `0x14cbe8`，address point 为 `+0x10`；
`+0xAB0` = `0x9859c`，`+0xAB8` = `0x9857c`。因此三参数重载不做实际工作，最终仍进二参数重载。
`AirPort_BrcmNIC::setLinkState` @ payload1 `0x2f504` 正是这样调用：
`0x2f5b8: movq 0xab0(%rax),%rax; ... jmp *%rax`，并在前面按 state==2 调
`setLinkQualityMetric(100)`（`0x2f596-0x2f5ae`）。

### 3.4 `linkState()` / `getPrimaryInterfaceLinkState()`

```asm
098eb6 <__ZN16IO80211Interface9linkStateEv>:
098eb6:  push rbp; mov rsp,rbp
098eba:  movl 0x208(%rdi), %eax
098ec0:  pop rbp; ret
```

```asm
090020 <__ZN17IO80211Controller28getPrimaryInterfaceLinkStateEv>:
090027:  movq 0x200(%rdi), %rax   ; controller->primaryInterface
09002e:  testq %rax,%rax
090031:  je   0x90042
090033:  movl 0x208(%rax), %r14d  ; interface->linkState
09003a:  movl %r14d,%eax
...
090042:  ...                     ; 没有 primary -> 调 *0xc90 再取
```

### 3.5 配套 controller 调用

`setLinkState` 内部已经做了，不需要额外调用：

- Up：`controller vtable+0x980(controller, 3, primaryInterface, 0)` @ `0x98811`。
- Down：`controller vtable+0x980(controller, 1, 0, 0)` @ `0x988d7`。

payload0 的 `IO80211Controller` 基类 vtable 槽 `+0x980` 在文件里是 0（`0x14bb60+0x10+0x980`），
由子类/加载期 relocation 填充；实际调用前应确认当前 controller 实现了该槽，否则会跳空。
`AirPort_BrcmNIC` 的 vtable 文件里该槽也是 0，说明它同样依赖加载期修复；
这也解释了为什么必须用真实加载后的 payload 地址，不能拿静态文件里的 0 当结论。

**结论：`setLinkState` 不更新 `IOLinkActiveCount`；它只更新 interface `+0x208`、队列、速率、peer manager、
controller 配套回调和 link-changed 事件。**

---

## 4. `IOLinkActiveCount`：谁创建、谁递增

### 4.1 创建（唯一字符串引用）

```asm
ffffff8002470666:  movq (%rbx), %rcx
ffffff8002470669:  leaq 0x10ff0(%rip), %rsi   ; 0xffffff8002481660 = "IOLinkActiveCount"
ffffff8002470670:  movq %rbx, %rdi
ffffff8002470673:  movq %rax, %rdx
ffffff8002470676:  callq *0x268(%rcx)          ; setProperty(key, value)
ffffff800247067c:  movb $1, %r14b
```

前面在 `0x247064a-0x2470664`：

```asm
ffffff800247064a:  xorl %edi,%edi
ffffff800247064c:  movl $0x40,%esi
ffffff8002470651:  callq 0xffffff8000a7df90    ; OSNumber::withNumber(0, 64)   (esi=0x40)
ffffff8002470656:  movq 0x140(%rbx),%rcx
ffffff800247065d:  movq %rax,0x20(%rcx)        ; 保存 OSNumber 指针
```

`0xffffff8000a7df90` 是 `__ZN8OSNumber10withNumberEyj`，即 `OSNumber::withNumber(unsigned long long, unsigned int)`。
`IOLinkActiveCount` 是 `IOEthernetInterface::init` 给每个以太网接口创建的 **OSNumber(0, 64)** 属性。

### 4.2 读取与释放，没有写入

- 读：`IOEthernetInterface::inputEvent` @ `0x2471f84`：

```asm
ffffff800247204d:  movq 0x140(%r15),%rax
ffffff8002472054:  movq 0x20(%rax),%rdi       ; OSNumber
ffffff8002472058:  movq (%rdi),%rax
ffffff800247205b:  movl $1,%esi
ffffff8002472060:  callq *0x158(%rax)         ; OSNumber vtable+0x158 = unsigned32BitValue()
```

- 释放：`IOEthernetInterface::free` @ `0x24707e4`：

```asm
ffffff80024708b8:  movq 0x20(%rsi),%rdi
ffffff80024708c1:  movq (%rdi),%rax
ffffff80024708c4:  callq *0x28(%rax)          ; release()
ffffff80024708d0:  movq %rax,0x20(%rsi)
```

### 4.3 全 KC 扫描：没有 setter

对 `BootKernelExtensions.kc` 的所有 `__text` 扫描 `call rel32` 到：

- `OSNumber::setValue` @ `0xffffff8000a7d9d0`
- `OSNumber::addValue` @ `0xffffff8000a7d990`

结果均为 **0 次**。

同时，整个 BootKernelExtensions 只有 **一个** `"IOLinkActiveCount"` 字符串引用（上表 `0x2470669`），
没有第二个 `setProperty("IOLinkActiveCount", ...)` 的地方。OSNumber vtable 里
`+0x158` 是 `unsigned32BitValue()`（读），`+0x170` 才是 `setValue()`；`inputEvent` 调的是 `+0x158`。

**结论：27 的 `IOLinkActiveCount` 创建后从未被递增。`setLinkState` 不会把它变 1；它也不是
link-up/association 的指示器。** 当前 en0/en1 两个 `IOEthernetInterface` 上都显示 0，与此一致。

如果业务上必须让 ioreg 显示 1，只能显式 `setProperty("IOLinkActiveCount", OSNumber::withNumber(1, 64))`；
但这是**伪造显示**，不改变任何内核行为，不建议作为根因修复。

---

## 5. 当前运行期证据（2026-11-18 05:00 左右）

### 5.1 计数器

```text
$ ioreg -rn SimpleBCM -l | grep -E 'C103Hits|Legacy103Patched|CurrentNetworkValid|Last103OutputSize|Association'
"Last103OutputSize" = 2280
"AssociationRequests" = 4
"AssociationAccepted" = 4
"AssociationEvents" = 4
"Legacy103Patched" = 1
"C103Hits" = 1875
"CurrentNetworkValid" = 1
```

3 秒后再读：`C103Hits = 1882`，即 103 仍在被应答（约 2.3 次/秒）。

### 5.2 接口状态

```text
IO80211SSID = "401"
IO80211BSSID = <004f1a66ad98>
IO80211RSNDone = Yes
en1: inet 192.168.1.25
IOLinkActiveCount = 0
```

### 5.3 103 错误日志的时间边界

```text
$ log show --last 90m --info --debug --predicate 'processID == 217 AND eventMessage CONTAINS "type 103"'
... 最后一条 2026-11-18 04:39:46.973610+0800 ... return -3903/0xfffff0c1
```

04:39:46 之后没有新的 `type 103` 日志；`C103Hits` 仍在增长。说明 103 的失败不是持续状态，
而是**时间窗口/路由相关**的。最可能是：

1. 04:37–04:39 时 `CurrentNetworkValid == 0`（关联刚完成，还没有匹配 SSID 的扫描结果），
   我们的 handler 按 `Bridge.cpp:64` 返回 `0x66`；
2. 之后一次扫描结果命中 SSID，`UserClient.cpp:485` 置 `CurrentNetworkValid=1`，103 开始返回 0；
3. 如果调用走 legacy 表，handler 的 `legacyCopyIn` 失败也会返回 `0x66`（见 §2.5 / §4.1），
   但当前 `C103Hits` 增长无法区分是 legacy 还是 user client 分支。

### 5.4 仍存在的 96/69 错误

- `type 96 / APPLE80211_IOC_VIRTUAL_IF_ROLE → -3903`：payload0 的 `getVirtualIfRole` @ `0x7c5bc`
  在 `rdx`（virtual interface）为空时直接 `movl $0x6,%eax`（`0x7c5d3`），`6` 被用户态映射成 `-3903`。
  这不是链路状态问题，是“en1 是 primary interface，没有 virtual interface”。
- `type 69 / APPLE80211_IOC_WOW_PARAMETERS → -3900`：payload0 `getWoWParameters` @ `0x7b414`
  在长度/参数不匹配时返回 `0x16`（`0x7b489: movl $0x16,%r13d`），映射成 `-3900`。
  这也是独立 handler 问题，不是 `setLinkState` 能修的。

---

## 6. 在 SimpleBCM 内的最小补丁建议

### 6.1 103：现有补丁已经覆盖，不需要 `setLinkState`

现有两条路径：

1. **legacy get 表 103**：`Bridge::prepareImage` 把表 `0x14a140` 的 index 102 替换成
   `legacyGetCurrentNetwork`（`Bridge.cpp:800-804`）。
2. **user client 103**：`UserClient::runCommand` 在 `get && request == 103` 且
   `CurrentNetworkValid && outputSize >= LegacyScanResultSize (0x48C)` 时，从 `currentNetworkBuffer`
   直接回填 0x48C 字节并把 `length` 设为 `outputSize`（`UserClient.cpp:399-411`）。

这两条已经在当前启动中生效（`Legacy103Patched=1`、`C103Hits` 增长、无 103 错误）。

**唯一建议的 103 增量修复**：去掉“关联后、首次匹配扫描结果前”的 `-3903` 窗口。

- 现状：`currentNetworkValid` 只在扫描结果包含关联 SSID 时置 1（`UserClient.cpp:480-487`）。
  关联成功但扫描结果未到时，legacy handler `return 0x66`（`Bridge.cpp:64`），user client 分支
  转发给驱动，最终也是 `0x66`。
- 最小改法（仍需验证 0x8E8 字段）：在 `Bridge::command` 的 `associate && result == kIOReturnSuccess`
  分支里，用关联请求里的 SSID/BSSID/通道先合成一条最小 `apple80211_scan_result` 到
  `currentNetworkBuffer`，并置 `currentNetworkValid=1`；或者关联成功后立即发一次 type 11
  的 scan result 请求并按 SSID 匹配。**不要**用 `setLinkState` 来触发 103。

### 6.2 link 状态：可选的独立补丁

如果目标是把 `IO80211Interface::linkState()` 从 0/1 推到 2、并让 27 侧收到 link-changed 事件，
可以在 SimpleBCM 内解析并调用：

```cpp
using SetLinkState = bool (*)(void *interface, uint32_t state, uint32_t reason);
static SetLinkState setLinkState;

// Bridge::prepareImage，和 classicController/classicName 一起解析
setLinkState = reinterpret_cast<SetLinkState>(patcher.solveSymbol(index,
    "__ZN16IO80211Interface12setLinkStateE16IO80211LinkStatej"));
if (!setLinkState && 0x9859c + 0x20 <= size) {
    // 与 103 表/ copyIn 相同的偏移回退；0x9859c 已在 payload0 中按 nm 校验
    setLinkState = reinterpret_cast<SetLinkState>(address + 0x9859c);
}
if (!setLinkState) {
    reject("LinkStateSymbolMissing");
    return;
}
```

调用点（建议）：

```cpp
// 关联完成：二选一，推荐 event 9，但要注意上下文锁
if (setLinkState)
    setLinkState(endpoint.interface, 2 /* kIO80211NetworkLinkUp */, 0);

// 断开/链路丢失
if (setLinkState)
    setLinkState(endpoint.interface, 1 /* kIO80211NetworkLinkDown */, reason);
```

参数：

- `interface`：`Endpoint.interface`（`IOService*`，实际是 `IO80211Interface*` / `AirPort_BrcmNIC_Interface*`）。
- `state`：`2` = up，`1` = down；`0` 是 Undefined，传到二参数重载会走 `jne 0x98839` 返回 false，不要用。
- `reason`：up 传 `0` 即可（reason 只进日志/事件数据 `0x989cd movl %r14d,0x14(%rbx)`）；down 传实际的
  断开原因（没有把握时传 0，日志会显示 0/未知）。
- 不需要额外调 controller：`setLinkState` 内部已经调用 controller vtable+0x980。
- 如果希望完全复制 `AirPort_BrcmNIC::setLinkState` 的行为，可额外调
  `setLinkQualityMetric(100)`（up）或 `-2`（down），见 payload1 `0x2f596-0x2f5ae`；但这不是 link 状态必需。

**风险/边界：**

- `setLinkState` 会 `startOutputQueues`、`updateLinkSpeed`、peer manager、`postMessage`、controller
  vtable+0x980；不要在持有 `IO80211Interface`/controller 锁的路径里直接调用。推荐在
  `IO80211Controller::getWorkLoop()->runAction(...)` 或 `thread_call` 里执行。
- 同一个 state 重复调用是幂等的（`0x985bd` 比较后直接返回 true）。
- 如果 controller vtable+0x980 在加载后仍为空，调用会跳空 panic；必须先在目标机上确认该槽
  （或先只在 event 9 路径调用并观察）。
- 驱动 `AirPort_BrcmNIC::setLinkState` 已经在 `enable`/`setPOWER`/`wlEvent` 中调用
  （payload1 `0x2f504`，调用点 `0x2f193`、`0x31d1b`、`0x5529e`）；如果 `wlEvent` 的 link-up
  分支已经正常执行，当前 `linkState()` 可能已经是 2。**先加诊断确认，不要盲改。**

### 6.3 `IOLinkActiveCount`：不要伪造

- 它不参与 link/103 判定；把它设为 1 只会让 ioreg 好看，不改变行为，也掩盖真正的 link 状态。
- 若需要可观测 link 状态，建议新增诊断属性，例如：

```cpp
using GetLinkState = uint32_t (*)(void *);
static GetLinkState getLinkState; // __ZN16IO80211Interface9linkStateEv @0x98eb6
...
service->setProperty("SimpleBCMLinkState", getLinkState(interface), 32);
```

这样能在 ioreg 里直接看到 `0/1/2`，而不是依赖一个永远为 0 的 Apple 遗留属性。

---

## 7. 未验证项

1. **当前 `linkState()` 实际值**：ioreg 没有该属性；没有在运行期调用 `linkState()`。
   不能断言现在是 0 还是 2。`IOLinkActiveCount=0` 不能作为反证。
2. **`C103Hits` 的路由归属**：该计数同时被 `legacyGetCurrentNetwork` 和 `UserClient.cpp` 的 103
   分支递增，无法区分“legacy handler 成功”还是“user client 成功”。`Last103OutputSize=2280`
   只能证明至少有一次 user client 103 请求到达。
3. **04:37–04:39 的 `-3903` 精确原因**：是 `currentNetworkValid=0`、`legacyCopyIn` 失败、
   还是 pre-handler 的 stub/转发返回 0x66，没有逐请求计数器；只能从时间线和代码路径推断。
4. **`setLinkState` 从 SimpleBCM 用户客户端/事件上下文调用的锁安全性**：未构建、未运行；
   `startOutputQueues`/controller vtable/peer manager 可能需要工作环或 gate。
5. **controller vtable+0x980 的加载期内容**：payload0/payload1 静态文件里该槽为 0；
   SimpleBCM 的 relocation 是否会填充、何时填充、失败时是否为空，未在运行期验证。
6. **27 新 get 表 103 是否能被未包装客户端命中**：当前所有 `IO80211APIUserClient` 都被
   SimpleBCM 包装（10/10），但没有检查所有可能的 ifnet/IOUC 客户端；如果出现未包装客户端，
   103 会走 27 `getCURRENT_NETWORK` 并在无 skywalk 接口时返回 0x66。
7. **27 新表/legacy 表的运行期可写性**：27 KC 内存通常只读；从 kext 改 27 表需要 KC 基址扫描 +
   写保护处理，当前 `KernelPatcher` 的符号解析只覆盖 payload0/payload1，不覆盖 27 的 local 表。
8. **down 的 reason 枚举**：头文件只定义了 `IO80211LinkState`，没有定义 reason 值；报告中的
   `reason=0` 是安全占位，不是从符号表验证的 `APPLE80211_LINK_CHANGE_REASON_*`。
9. **`IOLinkActiveCount` 在 macOS 26 / 其他机型上的行为**：本报告只针对本机 27.2 的
   `BootKernelExtensions.kc` 和 payload0/1；不能外推到 26 或其他 IONetworkingFamily 版本。
10. **`currentNetworkValid` 的时序**：没有记录它在本次启动中何时从 0 变 1；04:39 的失败窗口
    与“关联后首次匹配扫描结果”之间的因果是推断，不是逐事件日志。

---

## 8. 复现命令（只读）

```bash
# 用户态函数
/usr/bin/dyld_info -arch x86_64 -function_starts \
  /System/Library/PrivateFrameworks/IO80211.framework/Versions/A/IO80211 | grep Apple80211GetWithIOCTL
/usr/bin/dyld_info -arch x86_64 -section __TEXT __cstring \
  /System/Library/PrivateFrameworks/IO80211.framework/Versions/A/IO80211 | grep Apple80211GetWithIOCTL

# payload0
nm -arch x86_64 .research/extract/payload0.bin | grep -E 'setLinkState|linkState|getCurrentNetwork'
/Library/Developer/CommandLineTools/usr/bin/llvm-objdump -d --arch=x86_64 \
  --start-address=0x9859c --stop-address=0x98b00 --no-show-raw-insn .research/extract/payload0.bin

# 27 KC（Tools/kernel_collection.py；系统 python3 不可用）
/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3 - <<'PY'
import sys; sys.path.insert(0,'Tools')
from kernel_collection import KernelCollection
kc=KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
im=kc.images['com.apple.iokit.IO80211Family']
print(hex(im.symbols['__ZL18getCURRENT_NETWORKP17IO80211ControllerP23IO80211SkywalkInterfaceP20IO80211APIUserClientP13apple80211req']))
print(hex(im.symbols['__ZL17getCurrentNetworkP17IO80211ControllerP23IO80211SkywalkInterfaceP13apple80211reqb']))
PY

# 运行期
ioreg -rn SimpleBCM -l | grep -E 'C103Hits|Legacy103Patched|CurrentNetworkValid|Last103OutputSize'
/usr/bin/log show --last 30m --info --debug --predicate 'processID == 217 AND eventMessage CONTAINS "type 103"'
```

---

## 9. 对父代理的直答

- **103 为什么 `-3903`**：用户态 `_Apple80211GetWithIOCTL` 把 103 发下去，内核/IOCTL 返回
  `0x66` 或 `6`，用户态在 `0x7FF924B63C9E` 把它映射成 `0xFFFFF0C1`。内核侧返回 `0x66` 的来源是
  payload0 的 103 桩（`0x7c80f`）或 27 `getCURRENT_NETWORK` 的“skywalk 接口为空”分支
  （`0x1f7f827`/`0x202e2f9`），**不是** `linkState()`/`IOLinkActiveCount`。
- **103 现在是否还坏**：当前 05:00 的计数器/日志显示 103 已在应答（`C103Hits` 增长、04:39 后无
  103 错误）；只在“关联后、首次匹配扫描结果前”的窗口还会返回 0x66。
- **`IOLinkActiveCount` 谁递增**：本机 27 的静态代码中没有找到递增路径；它由 `IOEthernetInterface::init` 创建为
  `OSNumber(0)`，之后只读/释放。`setLinkState` 不会改它。
- **link up 调什么**：`IO80211Interface::setLinkState(interface, 2, reason)` @ payload0 `0x9859c`；
  down 用 `1`。controller 配套调用已内置（vtable+0x980）。
- **最小补丁**：103 保留现有两条拦截；若要去掉关联后窗口，在关联成功时填充
  `currentNetworkBuffer` 并置 `currentNetworkValid`。link 状态补丁是独立的，调用
  `setLinkState(...,2,0)`，但它不解决 103，也不改变 `IOLinkActiveCount`。
