# AirDrop / sharingd 异步返回栈诊断：guest sp = -16 时 x86 rsp 应当怎么变

- 日期：2026-11-18
- 机器：Mac15,14，macOS 27.2（26B123，Darwin 27.2.0 x86_64）
- 对象：`/usr/local/libexec/sharingd`（x86_64 = a2x host，arm64e = guest sharingd）
- 相关源码：`liberator-devkit/src/interpreter/candidate/interp/host.c`（`recover_guest_call`，1656 行起）
- 结论一句话：**guest arm64 栈在返回时下移 -16 是正常的尾部调用/参数区调整，它不构成 x86 栈的“负数弹出量”。x86 侧的正确变化是固定的 `+16`（8 返回地址 + 8 `swiftasynccall` 的 `retq $8`），而不是当前的 `+8`、也不是 lab 里试过的 `+24`。**
- 一句话修复候选：`A2X_ASYNC_NEG_AREA=8`（lab）；ship 版把负 gdelta 分支固定为 `area = 8`。

---

## 0. 证据摘要（先看这一段）

| # | 证据 | 位置 / 字节 |
|---|---|---|
| E1 | guest 函数 0x1001be678 的返回 sp 比入口低 0x10 | 反汇编：`0x1001be790 add sp,sp,#0x70`，帧是 `sub sp,sp,#0x80`，故 `sp = S-0x10` |
| E2 | 它是 async 函数指针 thunk：`pacibsp; orr x29,x29,#0x1000000000000000`，`bl swift_task_alloc`，最后 `b <stub>` | 0x1001be678 / 0x1001be6e4 / 0x1001be7a8 |
| E3 | 它**没有** `bl swift_task_switch`；不是“挂起后被 continuation 恢复”的函数 | 全函数体 0x1001be678–0x1001be7a8，见 §3 |
| E4 | 它的尾调用目标是 x86_64 Sharing.framework 里的 `...invoke...YaKF` witness（导出 trie 中存在） | x86_64 Sharing `__TEXT` 0x7ff8214b1000，符号地址 0x7ff82175bbf0 |
| E5 | 运行时调用 job 的 ResumeTask：`mov 0x40(%r15),%r14; callq *0x38(%r15); subq $8,%rsp` | libswift_Concurrency 0x7ff8079faa7f：`4d 8b 77 40  41 ff 57 38  48 83 ec 08` |
| E6 | `swift_task_switchImpl` 的收尾是 `addq $0x10,%rsp; popq %rbp; btrq $0x3c,%rbp; retq $0x8` | 0x7ff8079fd001：`48 83 c4 10 5d 48 0f ba f5 3c c2 08 00` |
| E7 | 崩溃时 `[rsp]=0`、`rip=0`，而 `swift_job_runImpl+0x8c` 的返回地址在 `[rsp+16]` | `/tmp/sharingd-sweep.err` 的 4 次 SIGSEGV |
| E8 | 崩溃前有 `aligned SSE operand at unaligned ...`（native `objc_autoreleasePoolPush+0x74`） | 同上；栈 8 字节错位的直接症状 |
| E9 | lab 试过 extra=0（原版）与 extra=16，均崩；extra=8 的 sweep 在写本报告时尚未产出 `-16` 记录 | `/tmp/sharingd-sweep.err` 7 条 `-16` 全是 `extra 16` |

> E5 + E6 是本次推导的关键：**调用点 `subq $8,%rsp` 与 `retq $8` 是同一对 ABI 的两半**。调用者在 `call` 之后减 8，只有当被调用者用 `retq $8` 多弹 8 时整套才配平。

---

## 1. 方法与可复现命令

### 1.1 x86_64 侧：从 dyld shared cache 取 libswift_Concurrency

`/usr/lib/swift/libswift_Concurrency.dylib` 在磁盘上不存在（只在 shared cache 中）。本次用 cache 头 + `.map` 直接切割：

- `/System/Library/dyld/dyld_shared_cache_x86_64` 头：magic `dyld_v1  x86_64`，`mappingOffset=0x238`，`mappingCount=4`。
- mapping 1：`addr=0x7ff800000000, size=0x27f74000, fileOffset=0`（EX）。
- `.map` 中 `/usr/lib/swift/libswift_Concurrency.dylib` 的 `__TEXT`：`0x7FF8079F8000 -> 0x7FF807A6819A`。
- LC_SYMTAB（从 cache 内的 Mach-O 头读出）：`symoff=0x2dad1390, nsyms=5880, stroff=0x2f4ee040`。
- 由 symtab 得到：`__ZL17swift_job_runImplPN5swift3JobENS_17SerialExecutorRefE = 0x7ff8079fc580`。
- 崩溃日志里的 `0x7ff808675580`（函数起点）− `0x7ff8079fc580` = `0xC7B000`，即当次 cache slide；`0x7ff80867560c` 正好是 `swift_job_runImpl+0x8c`，与日志一致。

为了反汇编，构造了一个只保留 `__TEXT` 的合成 Mach-O（把 `__TEXT` 的 fileoff 置 0、各 section 的 offset 减去 `0x79f8000` 再加上新头部长度），`llvm-objdump --start-address/--stop-address` 即可按 unslid 地址反汇编。原始字节另用 Python 直接从 cache 取，见 §0 的 E5/E6。

### 1.2 arm64e 侧：guest sharingd

- `lipo -thin arm64e -output /tmp/a2xdiag/sharingd.arm64e /usr/local/libexec/sharingd`
- `otool -arch arm64e -tv /usr/local/libexec/sharingd > otool_arm64e.txt`（`llvm-objdump` 对这份 arm64e 镜像会把两条指令的地址算错，`otool` 正常；本文所有 guest 地址均以 `otool` 输出为准）。
- arm64e 切片是 strip 过的：`nm` 只有 undefined 符号；0x1001be678、0x1001bf09c 没有本地符号名，靠字面池里引用的 Swift 符号和函数体形状识别。
- 字面池引用（`otool` 注释）：
  - 0x1001be678：`[0x1006ed1a0] = _$s7Sharing20SFAirDropInvocationsO23BecomeTransferPresenterCMa`，afp 在 `[0x1006ed340]`，符号是 `_$s7Sharing31_AnySFXPCAsyncInvocableProtocolPA2A01_cdE0RzrlE6invoke...YaKFTu`。
  - 0x1001bf09c：`[0x1006ed070] = _$s7Sharing20SFAirDropInvocationsO16TransfersMonitorCMa`，afp 同一个 `[0x1006ed340]`。

### 1.3 现场

`vmmap 22234`（当时仍在运行的 lab sharingd）显示：

- guest 映像只有 `/usr/local/libexec/sharingd` 映射在 `__ARMRSV 0x100000000` 起的保留区，**没有**任何 arm64e 的 Sharing.framework guest 映像；
- `__TEXT 0x7ff82212a000 /System/Library/PrivateFrameworks/Sharing.framework/Versions/A/Sharing` 是 **x86_64 原生** shared-cache 映像（SM=COW）。

所以尾调用 `b <stub for ...YaKF>` 在 binder 里解析到的是**原生 x86_64 实现**（见 §3.4 的导出 trie 证据），不是 guest 代码。

---

## 2. ABI 推导：`retq $8` 与 `-16` 各管各的

### 2.1 x86-64 的 Swift async frame record

LLVM 的 X86 async context 支持（commit `747e5cfb`，作者 Tim Northover）写得很清楚：

> "The context frame is identical to AArch64 ... the new frame record is [AsyncCtx, %rbp, ReturnAddr], and its presence is signalled by bit 60 of the stored %rbp being set to 1."

即 x86_64 上，带 `swiftasync` 参数的函数：

```
[rbp-8] = AsyncCtx        ; llvm.swift.async.context.addr() == rbp-8
[rbp]   = 保存的 rbp（内存里 bit 60 = 1）
[rbp+8] = 返回地址
```

对应的序言/尾声（同一 commit 的 `swift-async.ll`）：

```
btsq $60, %rbp
pushq %rbp
pushq %r14              ; 把 r14 里的 async context 存到 [rbp-8]
leaq 8(%rsp), %rbp
...
addq $16, %rsp
popq %rbp
btrq $60, %rbp
retq
```

这次在**真实运行库**里量到了同一套：

- 原生 `...YaKF`（Sharing.framework，x86_64，地址 0x7ff82175bbf0）序言：
  `btsq $0x3c,%rbp; pushq %rbp; pushq %r14; leaq 0x8(%rsp),%rbp; subq $0x8,%rsp; pushq %r15; pushq %r12; pushq %rbx; subq $0x18,%rsp`
  随后 `movaps 0x10(%rbp),%xmm0; movq 0x20(%rbp),%r15; movq 0x30(%rbp),%r12` —— 它确实从返回地址之上读栈参数。
- `swift_task_switchImpl`（0x7ff8079fcf10）尾声（0x7ff8079fd001）：
  `48 83 c4 10` = `addq $0x10,%rsp`；`5d` = `popq %rbp`；`48 0f ba f5 3c` = `btrq $0x3c,%rbp`；`c2 08 00` = **`retq $0x8`**。

### 2.2 `swiftasynccall` 的调用方契约

先区分两种 CC，别混：

- 普通 `swiftcc`/带 `swiftasync` 参数的 async 函数（例如原生 `...YaKF`）：尾声是普通 `retq`（§2.1 的 LLVM 测试就是这么 CHECK 的）；
- `swiftasynccall`（运行库给 resume 函数 / `Job::ResumeTask` / `swift_task_switch` 用的 CC）：尾声是 **`retq $8`**。运行库自己的符号表就写着这个 CC：
  `__ZL21swift_task_switchImplPN5swift12AsyncContextEPU14swiftasynccallFvU19swift_async_contextS1_ENS_17SerialExecutorRefE`
  （`U14swiftasynccall` 即 `swiftasynccall` 函数指针类型）。

libswift_Concurrency 里 `runJobInEstablishedExecutorContext`（0x7ff8079fa9f0）调用 job 的 ResumeTask：

```
7ff8079faa7f: 4d 8b 77 40        movq 0x40(%r15), %r14     ; r14 = job 的 async context
7ff8079faa83: 41 ff 57 38        callq *0x38(%r15)         ; 调 ResumeTask（swiftasynccall）
7ff8079faa87: 48 83 ec 08        subq $8, %rsp             ; 调用方配平被调用者多弹的 8
```

把这个序列按 rsp 算一遍（C = `call` 前的 rsp，C 是 16 对齐的；函数序言后 C = rbp−0x70）：

```
call 之前                 rsp = C
call 压返回地址           rsp = C-8
被调用者 retq $8          rsp = C            （弹返回地址）
                          rsp = C+8          （再弹 8，即 async word）
调用方 subq $8            rsp = C            ← 配平
```

- 只可能是 `retq $8`：若被调用者是普通 `ret`（比如普通 `swiftcc` async 函数），则 `subq $8` 会把 rsp 变成 C−8，函数尾声的 `addq $0x48; pop rbx; pop r14; pop r15; pop rbp; ret` 就会整体错一格，最终 ret 到 0 —— 这正是崩溃的形态（§4）。
- 这个“多弹的 8”在 x86-64 Swift 里就是 async context word（`[rsp]` 处、返回地址之上的那一格）；调用方在 `call` 之后 `subq $8` 是它的标准配平动作，不是可选项。

### 2.3 公式

设：

- `R` = 进入 trampoline 时 x86 的 rsp（`[R]` = 返回地址；`[R+8]` = async word / 第 7 个参数）；
- `M` = 被调用者在 x86 上按 swiftcc/swifttailcc 弹出的**栈参数个数**（8 字节/个；不含 async word，不含返回地址）。

则原生被调用者返回后：

```
rsp_after = R + 8 (返回地址) + 8 (swiftasynccall 的 retq $8) + 8*M
          = R + 16 + 8*M
```

对本次的 job ResumeTask：它只通过 r14 拿 async context，x86 上没有栈参数，**M = 0**，所以：

```
rsp_after = R + 16          （不是 R+8，也不是 R+24）
```

`swift_job_runImpl+0x8c` 的调用（`call 0x7ff8079fa9f0`）是普通 swiftcc，返回点是普通 `ret`，不在这个公式里；崩溃日志里 `stack[2]=+0x8c` 只是 runJob 的返回地址，不是 async 调用的返回地址。

### 2.4 arm64e 侧：`-16` 是什么

guest 0x1001be678 的序言/尾声（原样）：

```
1001be678: d503237f  pacibsp
1001be67c: b24403bd  orr  x29, x29, #0x1000000000000000   ; async frame bit 60
1001be680: d10203ff  sub  sp, sp, #0x80
1001be684: a901effc  stp  x28, x27, [sp, #0x18]
1001be688: a902e7fa  stp  x26, x25, [sp, #0x28]
1001be68c: a903dff8  stp  x24, x23, [sp, #0x38]
1001be690: a904cff5  stp  x21, x19, [sp, #0x48]
1001be694: a9067bfd  stp  x29, x30, [sp, #0x60]
1001be698: 910163f0  add  x16, sp, #0x58
1001be69c: f2f86350  movk x16, #0xc31a, lsl #48
1001be6a0: aa1603f1  mov  x17, x22
1001be6a4: dac10e11  pacdb x17, x16
1001be6a8: f9002ff1  str  x17, [sp, #0x58]      ; [x29-8] = 签名后的 async context
1001be6ac: 910183fd  add  x29, sp, #0x60
...
1001be790: 9101c3ff  add  sp, sp, #0x70         ; S-0x80 → S-0x10
1001be794: 910043f0  add  x16, sp, #0x10         ; = S，autib 用
1001be798: dac1161e  autib x30, x16
1001be79c: ca1e07d0  eor  x16, x30, x30, lsl #1
1001be7a0: b6f00050  tbz  x16, #0x3e, 0x1001be7a8
1001be7a4: d4388e20  brk  #0xc471
1001be7a8: 140e9a93  b    0x1005651f4             ; stub for ...YaKF
```

- `x29` 的 bit 60（`orr x29,x29,#0x1000000000000000`）就是 AArch64 的 async frame 标志，和 x86 的 `btsq $60,%rbp` 是同一约定；async context 在 **`[x29,#-8]`**（这里 x29 = sp+0x60，故 `str x17,[sp,#0x58]` 正是 `[x29-8]`）。
- 尾声从 `S-0x80` 只加回 `0x70`，留下 **0x10**。这是 swifttailcc 尾部调用在 arm64 上的参数区：被尾调用的函数（`...YaKF`）负责在它 `ret` 前用 `add sp,sp,#N` 把这段弹掉。`autib x30, sp+0x10` 用 `S` 认证 x30，也证明此时 sp 就是 `S-0x10`。
- 它不是“任务挂起后由 continuation 恢复”的状态：能证明“挂起”的指令是 `bl swift_task_switch`（或 `b swift_task_switch`），这个函数体里没有；它只 `bl swift_task_alloc`（0x1001be6e4）和 `bl 0x1001d0320`（witness table cache）。

### 2.5 两者不是一回事

guest 的 `asp` 是解释器自己的 **arm64 栈**（`__arm_sp`），和 x86 的 `rsp` 是两套栈。两者的唯一耦合是：

1. 进入时把 x86 的 `[rsp+8..]` 拷进 guest 栈参数窗（host.c:1680、1723–1728）；
2. 返回时用 `gdelta` 猜测 guest 弹掉了多少 **arm64 栈参数**，再折算成 x86 栈参数（host.c:1751/1800）。

因此：

- `gdelta > 0`：可以理解为“guest 确实弹了 arm64 栈参数”，折算成 x86 的 `M = gdelta/8 + 2`（+2 是 x86 上位于栈上的第 7/8 个参数；arm64 在 x6/x7），然后 `rsp_after = R + 16 + 8M`。
- `gdelta == 0`：`M = 0`，`rsp_after = R + 16`（当前代码 area=8，是对的，日志 `x86 area 0x8`）。
- `gdelta < 0`：**这不是“负数个栈参数”**，而是 guest 为了尾部调用把自己的帧下移了。它对 x86 的 `M` 没有信息量；`M` 仍按真实签名算。对本次两个 thunk（以及被它们尾调的 `...YaKF` 入口）x86 侧 `M = 0`，所以 `rsp_after = R + 16`。

**一句话：`-16` 应当被忽略，但“忽略”不等于“把 async word 也省掉”；8 字节的 async word 是 x86 调用约定强制的，和 guest sp 无关。**

---

## 3. 两个 guest 函数是什么

### 3.1 0x1001be678（BecomeTransferPresenter 的 witness thunk）

完整形状（节选；地址均为 unslid guest 地址）：

```
1001be678  pacibsp; orr x29,x29,#bit60; sub sp,#0x80        ; async 序言
1001be684  stp x28,x27 / x26,x25 / x24,x23 / x21,x19 / x29,x30
1001be698  add x16,sp,#0x58; movk x16,#0xc31a,lsl#48
1001be6a0  mov x17,x22; pacdb x17,x16; str x17,[sp,#0x58]   ; async ctx 存 [x29-8]，签名
1001be6b0  stp x6,x7,[sp,#8]; str x5,[sp]                   ; 保存入参 6/7/8
1001be6b8  mov x24,x4 ... x28,x0                            ; 保存 x0-x4
1001be6cc  mov x21,x22                                      ; x21 = 父 async context
1001be6d0  ldp x19,x23,[x29,#0x20]; ldr x20,[x20]           ; 读调用者栈上的两个词 + swiftself
1001be6d8  adrp/ldr x8,[0x1006ed340]; ldr w0,[x8,#4]        ; afp->allocSize
1001be6e4  bl 0x10056b754 <_swift_task_alloc>               ; 新 async context
1001be6e8  mov x22,x0
1001be6ec  str x0,[x21,#0x10]                               ; 挂到父 context
1001be6f0  x0=&0x10073f0a28; x1=BecomeTransferPresenterCMa; x2=witness
1001be720  bl 0x1001d0320                                   ; witness table cache（非挂起）
1001be724  pacda x21 -> [x22]                               ; ctx->parent = 父
1001be738  pacia 0x1001d0388 -> [x22,#8]                    ; ctx->resume = 0x1001d0388
1001be754  stp x23,x0,[x29,#0x18]; str x19,[x29,#0x10]
1001be770  ldp x5,x6,[sp]; ldr x7,[sp,#0x10]                ; 恢复 x5-x7
1001be778  ldp x29,x30,[sp,#0x60] ...                       ; 恢复 callee-saved
1001be790  add sp,sp,#0x70                                  ; S-0x10，给尾调用留 0x10
1001be7a8  b 0x1005651f4                                    ; stub for ...YaKF
```

判定：

- **是** async 函数（`pacibsp` + bit60 + `[x29-8]` 的 async context 槽）。
- **有** `bl swift_task_alloc`（0x1001be6e4）。
- **没有** `bl/b swift_task_switch`，也没有任何 `ldr x1,[x22,...]; b swift_task_switch` 的 resume thunk 形状。
- 它是“async function pointer thunk”：为 `...YaKF` 分配 task context，填 parent + resume，把参数恢复后**尾调用**真正的实现。0x1001d0320 是 witness table cache（`ldr x0,[x0]; cbnz; blraa x1; swift_getWitnessTable; stlr x0,[x19]`），不是挂起。
- `[x22+8] = 0x1001d0388`，而 `0x1001d0388` 本身是 `b 0x1001bff54` 的跳板，即 task 的 resume 入口；这是“新建任务”的数据，不是本函数挂起后恢复的现场。

### 3.2 0x1001bf09c（TransfersMonitor 的 witness thunk）

逐指令同构，只有三处常量不同：

| 位置 | 0x1001be678 | 0x1001bf09c |
|---|---|---|
| 元数据访问器 | `[0x1006ed1a0] = BecomeTransferPresenterCMa` | `[0x1006ed070] = TransfersMonitorCMa` |
| witness cache 指针 | `0x10073f0a28` | `0x10073f0a18` |
| 尾调用 | `b 0x1005651f4` @0x1001be7a8 | `b 0x1005651f4` @0x1001bf1cc |

同样：`pacibsp; orr x29…; sub sp,#0x80`、`bl swift_task_alloc`、`add sp,sp,#0x70`、`b <stub>`，**没有** `swift_task_switch`。

### 3.3 返回时的 -16 是否“正常”

**正常，但含义不是“挂起恢复”。** 它是：

1. thunk 为 swifttailcc 尾调用预留 0x10 参数区（`add sp,sp,#0x70`）；
2. 尾调用目标是原生 x86_64 `...YaKF`，经 interpreter 的 native-tail-call 路径执行后，控制流直接回到 `x30` 的 sentinel，**guest 不再执行尾被调者的 `add sp,sp,#0x10`**；
3. 因此 `__arm2x86_interp_run` 返回时 `xs[31] = S-0x10`。

这正是“guest 在 native 尾调用点结束”的正常形态（a64_rt.c 的 native target 注释：`a b or br x16 is a TAIL call ... its result is this frame's result and we return to whatever x30 held`）。它不是 guest 栈被写坏，也不是任务挂起。

### 3.4 尾调用目标确实是原生 x86_64

- x86_64 Sharing.framework（`/System/Library/dyld/dyld_shared_cache_x86_64.map` 第 1754 条，`__TEXT 0x7FF8214B1000`）的 **export trie**（`LC_DYLD_EXPORTS_TRIE`，cache 偏移 `0x2d67dc40`，大小 `0x33008`）里可以找到两个同名符号：
  - `_$s7Sharing31_AnySFXPCAsyncInvocableProtocolPA2A01_cdE0RzrlE6invoke...YaKF` → trie offset **0x2aabf0**，VM `0x7ff82175bbf0`（在 `__text` 0x7ff8214b3830–0x7ff8217c0b00 内），是真正的 witness 函数；
  - `...YaKFTu` → trie offset **0x37d198**，VM `0x7ff82182e198`，在 `__const`，是 async function pointer（afp）数据对象。
- 现场 `vmmap` 显示这个 x86_64 Sharing 映像确实被映射（`__TEXT 0x7ff82212a000`，带 slide），guest 侧没有 arm64e Sharing 映像。
- 原生 `...YaKF` 的序言就是 §2.1 的 swiftasync frame record；它入口处 `movaps 0x10(%rbp)`、`movq 0x20(%rbp)`、`movq 0x30(%rbp)` 读栈参数，说明它是带栈参数的 async witness 实现，由 door 负责把 guest 的 x6/x7 + guest 栈参数铺成 x86 栈（**推断**：guest thunk 在尾调用前留出的 0x10 正是为这两个来自 x6/x7 的 x86 栈槽准备的；这一点尚未逐参数实测，见 §8.4/§8.9）。

因此：**guest 的 -16 是“尾调用到 native 时的正常 arm64 帧状态”，对 x86 rsp 没有直接含义。**

---

## 4. 为什么现在会崩：+8 与 +24 都不对

当前 `recover_guest_call` 在负 gdelta 分支里：

```c
ss->__rsp += 8;              /* host.c:1765，只弹了返回地址 */
...
} else {                     /* a2x_gdelta < 0 */
    long long extra = 0;     /* host.c:1810，默认 0 */
    ...
    if (extra) ss->__rsp += extra;
}
```

对 `R`、`C=R+8`：

| 分支 | trampoline 返回时 rsp | 之后 `subq $8` | runJob 帧基 | 结果 |
|---|---|---|---|---|
| 正确（retq $8 仿真） | `R+16` = C+8 | `C` | `rbp-0x70` | 配平 |
| 当前（extra=0） | `R+8` = C | `C-8` | `rbp-0x78` | 低 8，尾声全部错位 → ret 到 0 |
| extra=16（lab 试过） | `R+24` = C+16 | `C+8` | `rbp-0x68` | 高 8，同样错位 → 仍崩 |
| extra=8（本次建议） | `R+16` = C+8 | `C` | `rbp-0x70` | 配平 |

崩溃日志与这个模型一致：

- `[rsp]=0`，`rip=0`：错位后的 `ret` 从错误的槽取到 0；
- `stack[2]=swift_job_runImpl+0x8c`：真正的 runJob 返回地址还在更高的槽里（`[rsp+16]`）；
- `aligned SSE operand at unaligned 0x...d08`（native `objc_autoreleasePoolPush+0x74`）：栈已经 8 字节错位，`movaps` 访问落在 `...8` 的地址上；
- `swift_job_runImpl+0x8c` 只是 `call runJobInEstablishedExecutorContext` 的返回点，不是 async 调用的返回点；真正的 async 调用在 runJob 内部（E5）。

### 4.1 最强的经验对照：同一调用点、gdelta=0 的站点用 area=8 不崩

同一份日志里：

```
[tramp] async 0x100475ddc popped 0 guest stack bytes: x86 area 0x8
```

这一行意味着 **同一类 async 返回**（`swiftasynccall` 的 `retq $8` 契约）当 guest 返回 `gdelta=0` 时，当前代码弹 `+16`（`+8` 返回地址 + `area=8`），这些调用是正常的、没有崩。`0x1001be678` / `0x1001bf09c` 只是同一契约下的另一批 callee，唯一区别是它们的 arm64 sp 少了 0x10。x86 调用者的契约不会因为 guest 内部帧形状不同而改变——所以它们也必须得到 `area=8`。**"gdelta<0 → area=0" 让同一契约下的两类 callee 得到不同的 x86 弹出量，这本身就是不自洽的。**

### 4.2 与既有结论的差异（为什么"负值不加 area"是反的）

`simplebcm-r27/Docs/AirDrop-Sharingd-Crash-20261118.md` §5.1 的推荐是"负值时保留 +8（仅 return address），不要凭空再弹"。那个结论缺了调用点的另一半证据：

- 运行时在 `call *0x38(%r15)` **之后**紧接着 `subq $8,%rsp`（E5，实测字节 `48 83 ec 08`）；
- 如果被调用者只弹返回地址（普通 `ret`），调用者的 `sub $8` 会把 rsp 再压低 8，runJob 的帧基就变成 `rbp-0x78`，尾声必然错位；
- 只有被调用者执行 `retq $8`（返回地址 + async word），`sub $8` 才把 rsp 恢复到 `rbp-0x70`。

`swift_task_switchImpl` 的尾声是 `retq $8`（E6），`swiftasynccall` 的返回就是这个形状。因此"仅 return address"不是保守，而是少 8；上一版"负值不加 area"的改动只是把"无符号巨大值 → 清零 → area=8"改成了"有符号负值 → area=0"，方向反了。**正确的保守值是与 gdelta=0 相同的 area=8。**

> 注意：`extra=16`（总 +24）也不是"更精确的布局"；它让调用者变为 `rbp-0x68`，同样错位。只有 `extra=8`（总 +16）落在 `rbp-0x70`。

---

## 5. 诊断采集方案（任务 2）

目标：不盲扫，把每一次 async 返回的“现场 + 判定 + 结果”按调用点聚合，直接用数据回答“负 gdelta 该加多少”。

### 5.1 记录字段

```c
struct a2x_aret {
    unsigned long site;      /* x86 返回地址 ret（调用点+5 等） */
    unsigned long tgt;       /* guest 入口 */
    unsigned long n;         /* 该 (site,tgt) 的次数 */
    long long     gd_min, gd_max, gd_last;
    unsigned long rsp_in;    /* 进入 trampoline 时的 ss->__rsp（[rsp]=ret） */
    unsigned long rsp_out;   /* 本次调整后的 ss->__rsp */
    unsigned long r14_in;    /* 进入时的 ss->__r14（x86 async context） */
    unsigned long x22_in;    /* 进入时的 xs[22]（guest async context） */
    unsigned long x22_out;   /* 返回时的 xs[22] */
    unsigned long x29_out;   /* 返回时的 xs[29]（bit60 可判 async 帧） */
    unsigned long x30_out;   /* 返回时的 xs[30]（应为 0xdead5a2cbeef sentinel） */
    unsigned char kind;      /* 1=async 序言 2=callee 读 x22 3=task-resume 4=仅 ret site */
    unsigned char sub8;      /* ret 处前 4 字节 == 48 83 ec 08 */
    unsigned char async;     /* 最终 a2x_async */
    unsigned char area;      /* 本次实际加的字节（不含 1765 的 +8） */
    unsigned char neg_extra; /* 负分支实际用的 extra */
};
```

按 `(site, tgt)` 聚合（open addressing，512 槽即可；同 site 不同 tgt 不合并）。只在 `!A2X_SHIP` 且 `A2X_TRACE_ASYNC_RET` 打开时记录；每首次见到一个 `(site,tgt)` 打一行，之后只更新 min/max/计数。

### 5.2 最小实现位置（行号以当前 host.c 为准）

1. **表与函数**：放在 `recover_guest_call` 之前，`a2x_ret_is_task_resume`（约 1649–1655）之后，新增：

```c
#if !A2X_SHIP
struct a2x_aret { ... };
static struct a2x_aret g_aret[512];
static int g_aret_on = -1;
static void a2x_aret_note(unsigned long tgt, unsigned long site,
                          long long gd, unsigned long rsp_in, unsigned long rsp_out,
                          unsigned long r14_in, unsigned long x22_in, unsigned long x22_out,
                          unsigned long x29_out, unsigned long x30_out,
                          int async, int sub8, int taskresume, int kind, unsigned area, long long neg_extra);
void a2x_aret_dump(int fd);
#endif
```

2. **入口捕获**：host.c:1666 之后（`if (!ret) return 0;` 之后）加：

```c
unsigned long a2x_entry_rsp = ss->__rsp;
unsigned long a2x_entry_r14 = ss->__r14;
```

3. **返回后记录**：在 async 块结束处 host.c:1824（`}` 之后、`/* THE ERROR ... */` 之前）加：

```c
#if !A2X_SHIP
a2x_aret_note(tgt, ret, a2x_gdelta, a2x_entry_rsp, ss->__rsp,
              a2x_entry_r14, xs[22] /* 若想区分入口/出口，另存一份入口 x22 */,
              xs[22], xs[29], xs[30], a2x_async, asyncsite, taskresume,
              kind, a2x_area, a2x_neg_extra);
#endif
```

需要把 `a2x_area`、`a2x_neg_extra`、`kind` 提到块外声明（当前 1801 的 `area` 是块内局部）。

4. **崩溃时 dump**：在 host.c:2456（`write(g_errfd, b, n)` 之后、guest caller 打印之前）加：

```c
#if !A2X_SHIP
a2x_aret_dump(g_errfd);
#endif
```

这样每次 SIGSEGV/SIGBUS 报告都自带“最近/最多调用点”的聚合，不依赖崩溃前最后一行。

### 5.3 输出格式（建议）

```
[aret] site=0x7ff8079faa87 tgt=0x1001be678 n=3 gd=[-16,-16] last=-16 kind=3 sub8=1 async=1 area=0x0 extra=0
       rsp_in=0x1b5780e70(out 0x1b5780e78, delta 8, in%16=0) r14=0x1b1c0a900 x22in=0x1b1c0a900 x22out=0x1b1c0a900 x29=0x... x30=0xdead5a2cbeef
[aret] site=0x... tgt=0x100475ddc n=57 gd=[0,0] last=0 kind=1 sub8=1 async=1 area=0x8 extra=0
       rsp_in=0x... (out 0x..., delta 16, in%16=8) ...
```

关键不变量（现场就能判）：

- 进入 trampoline 的 `rsp_in & 15` 应恒为 **8**（`call` 压了 8，调用者 rsp 16 对齐）；若变成 0，说明上一次返回把栈弹错/少弹了；
- `rsp_out - rsp_in` 应恒为 `16 + 8*M`（本次 M=0 → 16）；
- `sub8=1` + `kind=3` 的组合就是“调用点是 `call *0x38(%r15); sub $8`”，这时 **必须** 加 async word；
- `x30_out` 应恒为 `0xdead5a2cbeef`（sentinel）；不是则说明 run 不是在顶层返回，不能用同样的公式。

---

## 6. 候选修正算法（任务 4）

### 6.1 分区间处理

| gdelta 区间 | 含义 | x86 动作 |
|---|---|---|
| `< 0`（本次 -16/-32…） | guest 为 tail call 调整了自己的帧；**不是**栈参数弹出量 | `area = 8`（async word）；`M=0`。**不得**用 `gdelta` 折成负数或 0 |
| `== 0` | 没有弹 arm64 栈参数 | `area = 8`（现状，正确） |
| `> 0` 且 8 的倍数、≤64 | 弹了 arm64 栈参数 | `M = gdelta/8 + 2`；`total = 16 + 8M`；按 16 对齐取整 |
| `>64` / 非 8 的倍数 | 不可信（栈已坏或分类错） | 记录并回退到 `area = 8`（不要静默清零后按 0 处理） |
| 非 async 调用点 | 没有 `retq $8` 契约 | 保持现状：正的 gpop 留给调用方；不额外加 |

### 6.2 代码草图（替换 host.c:1796–1823）

```c
/* x86 调用约定强制的两个字：返回地址(调用方 call 压的) + swiftasynccall 的 retq $8。
   这两者与 guest 的 arm64 sp 无关。guest 的正 gdelta 只用来折算 x86 栈参数。 */
a2x_async = async_prologue || asyncsite || taskresume || a2x_callee_uses_async_ctx(tgt);
if (a2x_async) {
    unsigned long x86_stack_bytes = 0;
    if (a2x_gdelta > 0 && !(a2x_gdelta & 7) && a2x_gdelta <= 64)
        x86_stack_bytes = (unsigned long)a2x_gdelta + 16;   /* arm64 弹的 N 字节 + x86 的 x6/x7 两格 */
    else if (a2x_gdelta < 0)
        x86_stack_bytes = 0;                               /* 尾部调用的帧调整，不是参数 */

    unsigned long total = 8 /*ret*/ + 8 /*retq $8*/ + x86_stack_bytes;
    total = (total + 15) & ~15UL;                          /* x86 栈参数区按 16 对齐 */
    unsigned long want = a2x_entry_rsp + total;
    unsigned long area = want - ss->__rsp;                 /* ss->__rsp 此时 = entry+8 */
    ss->__rsp = want;
    ...
}
```

对本次：`total = 16`，`area = 8`。等价的“一行实验”就是 `A2X_ASYNC_NEG_AREA=8`。

### 6.3 ship 版

- 删除负分支里的 `getenv`（当前 `#if !A2X_SHIP` 已经只在 lab 生效）；
- 负 gdelta 与 0 走同一路径：`area = 8`；
- 在 `a2x_gdelta` 的合法性检查（1752）里，**负数不应被“忽略并清零”后当成 0 处理**，而应保留符号用于诊断；清零只影响 `a2x_gpop` 的计算，不影响 async word。

---

## 7. 验证判据

### 7.1 崩溃消失（主判据）

1. 用同一 lab 构建、同一 `/usr/local/libexec/sharingd`，分别跑：
   - A：`A2X_ASYNC_NEG_AREA=0`（复现）；
   - B：`A2X_ASYNC_NEG_AREA=8`（候选）；
   - C：`A2X_ASYNC_NEG_AREA=16`（反例，仍应崩）。
2. 触发：`killall ControlCenter` 或 `open "airdrop://"`（与既有复现手法一致），每个配置至少 3 次。
3. A 应在 1–2 s 内 SIGSEGV（rip=0，`swift_job_runImpl+0x8c`），C 同样崩；**B 不应出现该 rip=0**，进程存活 ≥ 10 分钟。
4. 崩溃记录里不再出现 `aligned SSE operand at unaligned ...`（或显著减少）——栈恢复 16 对齐的直接旁证。

### 7.2 栈配平（机制判据）

在 B 上开 `A2X_TRACE_ASYNC_RET`，确认：

- 对 `(site=0x7ff8079faa87, tgt=0x1001be678/0x1001bf09c)`，`area=0x8`，`rsp_out-rsp_in=16`；
- 该线程下一次进入 trampoline 时 `rsp_in & 15 == 8`；
- `x30_out == 0xdead5a2cbeef`；
- `sub8=1`、`kind=3`（调用点确为 `call *0x38(%r15); sub $8`）。

### 7.3 回归（不能被修负 gdelta 改坏）

- `0x100475ddc` 等 `gdelta==0` 的站点必须仍然 `area=0x8`（日志原样）；
- 正 gdelta 的站点（历史上 Sharing 的 `N=16 -> area=0x28`）不得改变；
- 其他 app 的 sweep（至少既有 65 app 基线）不得出现**新增**崩溃。

### 7.4 功能

- ControlCenter 的 AirDrop 可发现性查询返回正常（不再 `exit 139`）；
- AirDrop 面板能显示/被发现（不是只看进程活着）。

---

## 8. 未验证项与风险

1. **extra=8 尚未完成真实触发验证。** 写本报告时看到的 pid 22234 是 `A2X_ASYNC_NEG_AREA=8` 的 lab 进程（18:38:46 启动，18:39:17 仍在，18:42 已不在），但它的 stderr 文件在 18:38 后没有新增 `-16` 记录，也没有后续 `-16 extra 8` 行；**不能据此宣称已通过**。真正的判据是 §7.1 的 ControlCenter 触发。
2. **尾调用目标没有在运行时逐次确认。** 我们证明了 x86_64 Sharing 的导出 trie 有 `...YaKF`、现场映射了该 x86_64 映像，但没有在 `braa` 处打印 slot 值。若 binder 因版本/符号差异把它绑定到别的地址，§3.4 的“native 尾调用”结论需要重验；诊断表里的 `tgt`/`rsp_out` 可以补上这一环。
3. **`[x22+8]=0x1001d0388` 的 resume 路径未验证。** 该 guest 跳板（`b 0x1001bff54`）在任务真正挂起后由谁、以什么 ABI 调用（guest 还是 native）没有实测；本次只覆盖“首次运行—尾调用 native—返回”的路径。若后续出现 `swift_task_switch` 挂起再恢复的崩溃，需要单独分析。
4. **负 gdelta 的“M=0”是就这两个 thunk 及其 `...YaKF` 入口而言。** 若别的函数以负 gdelta 返回但 x86 侧确实有栈参数（例如 swifttailcc 同时弹参数又把 sp 降下去），固定 `area=8` 会少弹。诊断表按 `(site,tgt)` 聚合后可逐站点核对；出现新站点时应先看 `rsp_in%16`/`x30` 再决定是否给该站点单独规则。
5. **正 gdelta 的 `+16`（x6/x7）仍是历史启发式。** 本次没有重验；`gdelta=8` 时现有公式会取整到 32 而不是 40，是否会在某个新站点出错未知（ARM64 栈参数通常 16 对齐，故常见 gdelta 是 16 的倍数）。
6. **回调门没有同样的修正。** `cb_host.c` 的 `__arm2x86_cb_door` 只把 `xs[0]`/`d0` 返回，完全没有 `gdelta`/`retq $8` 逻辑；如果某个 async 函数是经 callback slot 被调用的（例如 job resume 指针被当作 block 传回），同样会在门处少弹 8。本次崩溃走的是 `recover_guest_call`，不是门；但这是同族风险，建议在门里也复用同一个“async 返回”判定。
7. **`asyncsite` 启发式可能误判。** `48 83 ec 08` 也可能是普通对齐；当前代码用 `taskresume`/callee 读 x22 来二次确认。若将来某个同步调用点恰好以该 4 字节开头，且 callee 又像 async，就会多弹 8。诊断表的 `sub8`+`kind`+`rsp_in%16` 可以用来发现这种站点。
8. **A2X_SHIP 下无法用环境变量做 A/B。** 修正必须在 ship 编译里固定成 `area=8`，否则 lab 通过、ship 仍旧。
9. **栈参数窗口固定 8 个字的边界未变。** `recover_guest_call` 仍只从 `[rsp+8..]` 拷 8 个字到 `asp`（host.c:1723–1728）；如果 `...YaKF` 需要更多栈参数（它入口读了 `[rbp+0x10]/[rbp+0x20]/[rbp+0x30]`），多出的部分靠 door 的 `a2x_swift_stack_prepare` 处理，本次未逐参数核对。

---

## 附录 A：关键地址与字节

### A.1 x86_64 libswift_Concurrency（unslid）

```
__TEXT                     0x7ff8079f8000 .. 0x7ff807a6819a
__ZL17swift_job_runImpl... 0x7ff8079fc580   （prologue: 55 48 89 e5 41 57 41 56 53 48 83 ec 48）
call runJob @+0x87         0x7ff8079fc607   （返回点 +0x8c = 0x7ff8079fc60c）
runJobInEstablished...     0x7ff8079fa9f0
  mov 0x40(%r15),%r14      0x7ff8079faa7f   4d 8b 77 40
  callq *0x38(%r15)        0x7ff8079faa83   41 ff 57 38
  subq $8,%rsp             0x7ff8079faa87   48 83 ec 08
swift_task_switch          0x7ff8079fceb0
swift_task_switchImpl      0x7ff8079fcf10
  epilogue                 0x7ff8079fd001   48 83 c4 10 5d 48 0f ba f5 3c c2 08 00
```

### A.2 guest arm64e sharingd（unslid）

```
0x1001be678  pacibsp; orr x29,#bit60; sub sp,#0x80
0x1001be6e4  bl 0x10056b754  swift_task_alloc
0x1001be720  bl 0x1001d0320  witness table cache
0x1001be790  add sp,sp,#0x70
0x1001be7a8  b 0x1005651f4   stub for ...YaKF
0x1001bf09c  (TransfersMonitor 同构)
0x1001bf1cc  b 0x1005651f4
0x1001d0320  witness table cache（ldr x0,[x0]; cbnz; blraa x1; swift_getWitnessTable; stlr）
0x1001d0388  b 0x1001bff54   task resume 跳板
字面池：
  0x1006ed340 -> ...yaKFTu afp（0x1001be6d8 / 0x1001bf100）
  0x1006ed1a0 -> BecomeTransferPresenterCMa
  0x1006ed070 -> TransfersMonitorCMa
```

### A.3 x86_64 Sharing.framework（unslid）

```
__TEXT                    0x7ff8214b1000 .. 0x7ff821870e72
export trie               cache 0x2d67dc40, size 0x33008
...YaKF (witness)         0x7ff82175bbf0
...YaKFTu (afp data)      0x7ff82182e198
原生序言：
  btsq $0x3c,%rbp; pushq %rbp; pushq %r14; leaq 8(%rsp),%rbp; subq $8,%rsp;
  pushq %r15; pushq %r12; pushq %rbx; subq $0x18,%rsp
  movaps 0x10(%rbp),%xmm0; movq 0x20(%rbp),%r15; movq 0x30(%rbp),%r12
```

### A.4 host.c 行号锚点

```
1656  recover_guest_call 入口
1665  ret = [rsp]
1680  xs[6],xs[7] = [rsp+8],[rsp+16]
1723-1728  guest 栈参数窗（8 个字）
1741-1744  __arm2x86_interp_run
1751  a2x_gdelta = xs[31]-asp
1756  a2x_gpop
1765  ss->__rsp += 8          ← 只弹返回地址
1796  a2x_async 判定
1798-1805  gdelta>=0 的 area 计算
1806-1820  gdelta<0 分支（本次要改的地方）
1824  async 块结束（诊断记录插入点）
1839  ss->__rip = ret
2438  a2x_stop_record（崩溃报告）
2456  报告正文写出后（dump 插入点）
```

---

## 附录 B：复现用命令

```sh
# 1. 反汇编 guest
lipo -thin arm64e -output /tmp/sharingd.arm64e /usr/local/libexec/sharingd
otool -arch arm64e -tv /usr/local/libexec/sharingd > /tmp/otool_arm64e.txt
grep -A140 '^00000001001be678' /tmp/otool_arm64e.txt

# 2. 反汇编 x86 运行库（见 §1.1 的切割脚本）
#    llvm-objdump --disassemble --start-address=0x7ff8079faa7f --stop-address=0x7ff8079faaa0 libswift_Concurrency.text

# 3. A/B 触发
sudo launchctl kickstart -k gui/501/com.apple.sharingd   # 或按既有 lab 方式启动
killall ControlCenter
open 'airdrop://'
```

（实验均在 /tmp 与 lab 进程上完成；未修改 /System、/Library、EFI，未重启、未部署。）
