# Swift 运行时 × a2x 蹦床：`swift_job_runImpl` 的 async area 约定与 sharingd 崩溃根因

- 日期：2026-11-18
- 机器：Mac15,14，macOS 27.2（26B123，Darwin 27.2.0 **x86_64**）
- 只读对象：`/usr/lib/swift/libswift_Concurrency.dylib`（**磁盘上不存在该文件**，见 §1）、`/usr/libexec/sharingd`（arm64e guest 切片）
- a2x 源码：`liberator-devkit/src/interpreter/candidate/interp/host.c`（`a2x_cb_call` / `recover_guest_call`）
- 结论一句话：**x86-64 的 `swiftasync` 约定是「被调方用 `ret $8` 多弹一个字」，`swift_job_runImpl` 的 job 调用点正是这种调用（返回点紧跟 `48 83 ec 08`）；而 guest 的 sp 差值来自另一块独立 arm 栈，与 x86 栈无因果关系，无法授权蹦床少弹那 8 字节。当前代码在 `gdelta < 0` 时把 async area 置 0，使 x86 `rsp` 低一个字，运行时的 `sub $8,%rsp` 收回后整个帧错位一格（`popq %rbp` 拿到保存的 `%r15`），最终 `ret` 消费到含 0 的字 → `rip=0`。**

---

## 0. 结论摘要（先看这 5 条）

| # | 结论 | 证据强度 |
|---|---|---|
| 1 | `swift_job_runImpl` 调 job 函数前**没有** `sub $8,%rsp`：async word 就是它 `0x48` 帧底部那 8 字节；返回点 `+0x8c` 紧跟在 `callq runJobInEstablishedExecutorContext` 之后 | 反汇编，§2.2 |
| 2 | 真正的 async 调用点在 `runJobInEstablishedExecutorContext+0x93`：`movq 0x40(%r15),%r14` → `callq *0x38(%r15)` → **`subq $0x8,%rsp`**。即：被调方多弹 8，调用方补回 8 | 反汇编 + 字节，§2.3 |
| 3 | 该约定是 x86-64 独有的：clang 对 `swiftasynccall` 被调方发 **`retq $8`**（arm64 上是普通 `ret`，无 async area）；运行时自己的 `swift_task_switchImpl` 也以 **`retq $0x8`**(`c2 08 00`) 结尾 | clang 对照实验 + 反汇编，§3 |
| 4 | 所以从蹦床入口（`[rsp]` = 返回地址）算，async 返回必须弹 **16**（8 返回地址 + 8 async word）。当前 `gdelta<0` 分支只弹 8 → **少 8** → 这正是崩溃 | 算术 + 崩溃记录，§5.1 |
| 5 | guest 的 `sub sp,#0x80` **不可能写穿 x86 caller 帧**：guest 栈是 `__arm2x86_ensure_stack()` `mmap` 的**独立 8 MiB** 映射，与 x86 栈无重叠。负 gdelta（−16）来自该 guest 函数自己的尾调用记账（释放 `0x70`/`0x80` 后 `b <stub>`） | 源码 + 反汇编，§6 |

---

## 1. 取证前置：live 地址与静态地址差一个 **cache slide 0x17289000**

这一点决定了整份报告的地址能不能对上，必须先说清楚。

- `/usr/lib/swift/libswift_Concurrency.dylib` **在磁盘上不存在**（`ls` 报 No such file）。它只存在于 x86_64 dyld shared cache：`/System/Library/dyld/dyld_shared_cache_x86_64{,.01..06}`。arm64e 那份在 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e{,...}`。
- 崩溃记录里的 `stack[3] 0x7ff81ec8560c _ZL17swift_job_runImplPN5swift3JobENS_17SerialExecutorRefE+0x8c` 与**静态布局对不上**：cache 里 `libswift_Concurrency` 的 `__TEXT` 在 `0x7ff8079f8000`，`swift_job_runImpl` 在 `0x7ff8079fc580`，`+0x8c` 应为 `0x7ff8079fc60c`；而 `0x7ff81ec8560c` 落在这个 cache 的 **SwiftUI** `__TEXT` 区间内。同一份崩溃记录里 `objc_autoreleasePoolPush+0x74 = 0x7ff81a761b01`，而 `libobjc.A.dylib` 的 `__TEXT` 在 `0x7ff8034d0000`——也对不上。
- 用两个**不同 image** 的符号反解同一个常数，得到同一个 slide：
  ```
  objc:  claim - sym(_objc_autoreleasePoolPush 0x7ff8034d8a8d) = 0x17289000
  swift: claim - sym(swift_job_runImpl          0x7ff8079fc580) = 0x17289000
  ```
  → **a2x 进程把 x86_64 shared cache 整体映射在 slide = 0x17289000**。于是
  ```
  live(swift_job_runImpl)            = 0x7ff8079fc580 + 0x17289000 = 0x7ff81ec85580
  live(swift_job_runImpl + 0x8c)     = 0x7ff81ec8560c   ← 与崩溃记录逐位一致
  ```
  a2x 的符号化（`dladdr` + image base）是**正确**的：崩溃确实发生在 **x86_64 宿主** `swift_job_runImpl` 的 `+0x8c`，不是 guest、不是 SwiftUI。
- 复现方式（无需 root）：解析 `dyld_cache_header`（magic 16 字节，`mappingOffset` 在 `+0x10`，条目 **0x20** 字节：addr/size/fileOffset/maxProt/initProt），按 vmaddr→文件偏移重建 Mach-O 的 `__TEXT`。本报告所有反汇编均来自这样重建出的 thin x86_64 文件。

> 统计口径提醒：直接用 `/System/Library/dyld/dyld_shared_cache_x86_64` 的**静态**地址去核对 live 崩溃记录，会得出结论「符号名错了」。差的就是这 0x17289000。

---

## 2. `swift_job_runImpl`：调用点、栈与 async context

### 2.1 符号表（cache 里的本地符号没被剥掉）

```
0x7ff8079fa9f0  __ZN5swift34runJobInEstablishedExecutorContextEPNS_3JobENS_17SerialExecutorRefENS_15TaskExecutorRefE
0x7ff8079fc550  _swift_job_run
0x7ff8079fc580  __ZL17swift_job_runImplPN5swift3JobENS_17SerialExecutorRefE      ← 崩溃帧
0x7ff8079fc690  __ZL17swift_job_runSlow...
0x7ff8079fceb0  _swift_task_switch
0x7ff8079fcf10  __ZL21swift_task_switchImpl...
0x7ff807a011c0  __ZL18non_future_adapterPN5swift12AsyncContextE
```

### 2.2 `swift_job_runImpl` 全文（静态地址，`+N` = 相对 0x7ff8079fc580）

```asm
+0     pushq %rbp
+1     movq  %rsp, %rbp
+4     pushq %r15                 ; rbp-0x08
+6     pushq %r14                 ; rbp-0x10   ← 保存调用方的 swiftasync(r14)
+8     pushq %rbx                 ; rbp-0x18
+9     subq  $0x48, %rsp          ; rsp = rbp-0x60（帧底）
+13    movb  $0x1, -0x38(%rbp)    ; 三个状态字节：0x1 / 0x0 / 0x0
+17    movb  $0x0, -0x30(%rbp)
+21    movb  $0x0, -0x28(%rbp)
+25    testq %rsi, %rsi           ; executor 是否通用
...
+93    movq  %rsi, -0x58(%rbp)    ; 构造一个本地 context 记录在 rbp-0x58
+97    movq  %rdx, -0x50(%rbp)
+101   movq  %rcx, -0x48(%rbp)
+105   movq  %r8,  -0x40(%rbp)
+109   movq  %gs:0x340, %rax      ; 保存 TLS 里的 current-async-context
+118   movq  %rax, -0x20(%rbp)
+122   leaq  -0x58(%rbp), %rax
+126   movq  %rax, %gs:0x340      ; 发布新的 current-async-context
+135   callq 0x7ff8079fa9f0       ; runJobInEstablishedExecutorContext(job, executor, taskExecutor)
+140   cmpb  $0x1, -0x28(%rbp)    ; ←←← 崩溃地址 = 0x7ff8079fc60c（+0x8c）
...
+233   addq  $0x48, %rsp
+237   popq  %rbx
+238   popq  %r14
+240   popq  %r15
+242   popq  %rbp
+243   retq
```

关于任务 1 的三个问题，逐条回答：

1. **调用点是否 `sub $8,%rsp`？——不是。** `swift_job_runImpl` 自己不是 async 函数（它 `pushq %r14` 保存、从不设置 r14），它对 `runJobInEstablishedExecutorContext` 是**普通调用**，返回点 `+0x8c` 后面也没有 `sub $8`。真正需要 async area 的是**下一层**。
2. **r14 怎么设？** 不在 `swift_job_runImpl` 里设。`swift_job_runImpl` 只把 TLS `%gs:0x340`（current async context）换成自己 `rbp-0x58` 的记录。
3. **返回值/异常寄存器：** `rax:rdx` 双字返回；swift 的 error 走 `r12`（`swifterror`），async context 走 `r14`。`+216..+228` 的 `cmpq $0x0,-0x50(%rbp)` / `callq 0x7ff8079fe3d0` 是 job 释放路径，与本次崩溃无关。

### 2.3 真正的 async 调用点：`runJobInEstablishedExecutorContext`

```asm
+143  movq 0x40(%r15), %r14        ; ★ r14(swiftasync) = job->0x40（任务的 AsyncContext）
+147  callq *0x38(%r15)            ; ★ 调 job->0x38 = Job::Run / ResumeTask（swiftasync 调用）
+151  subq $0x8, %rsp              ; ★★ 补回被调方 ret $8 弹掉的 async word
+155  cmpq $-0x1, %r12
...
+404  addq $0x48, %rsp             ; 帧底 = rbp-0x70（5 push + 0x48）
+408  popq %rbx
+409  popq %r12
+411  popq %r13
+413  popq %r14
+415  popq %r15
+417  popq %rbp
+418  retq
```

帧算术（`R` = rbp）：

```
rsp(调用时) = R-0x70          ← [R-0x70, R-0x68) 就是 async word（未初始化，属本帧）
callq 之后   rsp = R-0x78     ；[R-0x78] = 返回地址 0x7ff8079faa87
ret $8 之后  rsp = R-0x78+16 = R-0x68
sub $8 之后  rsp = R-0x70     ← 回到帧底，+404 的 addq $0x48 才对得上
```

**只要少弹那 8 字节，`+151` 之后 rsp 就是 R-0x78（比帧底低 8）**，于是 `addq $0x48` 把 rsp 送到 R-0x30，6 次 pop 全部前移一格：

```
rbx←[R-0x30]  r12←[R-0x28]  r13←[R-0x20]  r14←[R-0x18]  r15←[R-0x10]  rbp←[R-0x08]=保存的 %r15
```

**`popq %rbp` 拿到的正是函数开头 `pushq %r15` 存下的 Job 指针**，而 `rsp` 最终停在 R 而不是 R-0x28。lab 记录提供了这条推断的判别性证据：

```
[host] rax f00ffffffffffff rbx 62 rbp 7f91edb3a600 ... r15 7f91edb3a600
```

**`rbp == r15 == 0x7f91edb3a600`（一个堆指针，不是栈）**——`popq %rbp` 只可能在 rsp 整体低一格时读到保存的 `%r15`。此后 `swift_job_runImpl` 自己的 `-0x28(%rbp)`、`-0x20(%rbp)` 全部改读堆内存，`%gs:0x340` 被写成垃圾，它的尾声再从错位一格的栈上 `pop`/`ret`，最终 `ret` 消费到含 0 的字 → **`rip = 0`、`[rsp] = 0`、`trapno 14 err 0x14`（取指页错）**，与 lab 的 `[rsp]=0x0 / exc err 0x14 / faultvaddr 0x0` 一致，也与「栈上仍能扫到 `swift_job_runImpl+0x8c` 这个返回地址」一致（帧链是错位，不是被抹掉）。

同一个函数里还有第二个 job 调用点 `+0x183: movq %r15,%rdi; callq *0x38(%r15); subq $0x8,%rsp`，形态相同。

---

## 3. 约定推导：`swiftasync` 的 async area 是 x86-64 独有的一字

用 clang（CLT 27.2 的 `clang -target {x86_64,arm64}-apple-macosx27.0 -O2 -S`）做双向对照。探针：

```c
typedef void (*async_fn)(void *) __attribute__((swiftasynccall));
void call_it(async_fn f, void *ctx) { f(ctx); }
int g;
void __attribute__((swiftasynccall)) my_async(void *ctx) { g = 1; }
```

**x86_64：**
```asm
_call_it:
	pushq %rbp
	movq  %rsp, %rbp
	pushq %r14
	pushq %r13
	subq  $16, %rsp        ; 8 = async word，8 = 对齐
	movq  %rdi, %rax
	movq  %rsi, %rdi
	callq *%rax
	addq  $8, %rsp         ; 补回被调方多弹的那一个字
	popq  %r13
	popq  %r14
	popq  %rbp
	retq
_my_async:
	pushq %rbp
	movq  %rsp, %rbp
	movl  $1, (%rax)
	popq  %rbp
	retq  $8               ; ★★ 被调方弹「返回地址 + 8」
```

**arm64：**
```asm
_outer:                            ; outer 本身也是 swiftasynccall
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	bl   _inner
	...
	ldp  x29, x30, [sp], #16
	ret                        ; ★ 普通 ret，没有 async area
```

**运行时自己的证据**（同一 ABI 的另一处实例）：
```asm
swift_task_switchImpl (0x7ff8079fcf10):
+13   subq  $0x8, %rsp         ; 给自己的 async 调用留 async word
+194  movq  %r14, 0x40(%rdi)   ; ★ 把「续体用的 async context」存进 task+0x40
+198  movq  %r15, 0x38(%rdi)   ; ★ 把「续体函数」存进 task+0x38
+251  retq  $0x8               ; 字节 c2 08 00
```

三条结论：

1. **`ret $8` / `sub $8,%rsp` 是同一个约定的两半**：调用方在 `[rsp]`（调用那一刻）留一个未初始化的 8 字节 async word；被调方 `ret $8` 连返回地址一起把它弹掉；调用方随后 `sub $8`（或改用等效的尾声）把帧收回。
2. **arm64 上没有这个字**：guest 的异步函数以普通 `ret`/`retab` 返回，sp 归位即可。
3. 因此「x86 调 arm64 guest async 函数」时，**这 8 字节必须由 a2x 伪造**——guest 永远不会弹它，因为它自己的 ABI 里没有这个东西。这正是 `a2x_async` 分支存在的理由。

**并且 job 的两条字段是同一对**：`swift_task_switchImpl` 把 `r14→task+0x40`、`r15→task+0x38`；`runJobInEstablishedExecutorContext` 正好 `r14 = *(job+0x40)`、`call *(job+0x38)`。即挂起时写进去的 (续体函数, async context)，恢复时由 job 运行器原样取出来调用。

---

## 4. guest 挂起（`swift_task_switch`）时运行时期望什么

`swift_task_switchImpl` 有两条出口，二者都**不由 a2x 的蹦床收回栈**：

**(a) 直接 handoff（同执行器还有活）** — `+313..+338`：
```asm
+313  movq %r15, %rax
+316  addq $0x88, %rsp
+323  popq %rbx
+324  popq %r12
+326  popq %r15
+328  addq $0x10, %rsp       ; 丢掉自己的 async word + 保存的 r14
+332  popq %rbp
+333  btrq $0x3c, %rbp
+338  jmpq *%rax             ; ★ 尾跳进下一个 job 的续体
```
此时 `rsp` 恰好停在「返回地址槽」上，**没有执行 `ret $8`**：async word 原地保留，由接手的那条续体最终 `ret $8` 一起弹掉。栈深度守恒，这是 Swift 的「接力」设计。

**(b) 入队后返回** — `+211..+251`：`callq 0x7ff8079febf0`（把任务交给执行器）后 `addq $0x88 / pops / addq $0x10 / popq %rbp / retq $0x8`，**正常返回给调用方**（即那个 async 函数），async 函数再自行收帧返回。

对 a2x 的直接含义（任务 2 的答案）：

- **挂起不是「返回」，但也不是「栈被谁修好」**：`swift_job_runImpl` / `runJobInEstablishedExecutorContext` 那一层在 (a) 里被**原地复用**（深度不变，地址还在），在 (b) 里被**正常 return 收回**。两种情况都不需要 a2x 替它调整。
- **恢复一定是一次全新的调用**：任务恢复时，某个线程上的 `swift_job_run` → `swift_job_runImpl` → `runJobInEstablishedExecutorContext` 重新读 `job+0x38` / `job+0x40`，用**新的 async area** 再 `call *0x38(%r15)`。那条 `call` 的返回点仍然是同一个 `+0x8c`（`48 83 ec 08` 紧跟其后）。
  → **每一次 resume 都是一次 swiftasync 调用，都必须多弹 8。**「第一次对、后来错」这种半吊子修正在这里不存在；反过来，`gdelta<0` 的分支会在**每一次 resume** 上重复少弹 8。
- (a) 还有个推论：handoff 之后新的续体仍以 `[rsp] = 上一个 job 的返回地址` 进场。如果那条续体也是 guest 函数，a2x 蹦床会拿到一个**属于别人的、陈旧的返回地址**——这正是运行时的本意（深度守恒），a2x 不需要、也不应该「修正」它。

---

## 5. a2x 应该怎么做（指令级依据）

### 5.1 现状与偏差

`a2x_cb_call`（host.c，`recover_guest_call` 之后的返回段）现在的形状：

```c
long long a2x_gdelta = (long long)(xs[31] - asp);          /* 有符号，已修过无符号的坑 */
if (a2x_gdelta > 64 || a2x_gdelta < -64 || (a2x_gdelta & 7)) { ...; a2x_gdelta = 0; }
unsigned long a2x_gpop = a2x_gdelta > 0 ? (unsigned long)a2x_gdelta : 0;
...
ss->__rsp += 8;                     /* 弹返回地址 */
...
a2x_async = asyncsite || prologue-marker;
if (a2x_async) {
    if (a2x_gdelta >= 0) { argb = gpop ? gpop+16 : 0; area = ((argb+8+15)&~15)-8; rsp += area; }  /* gdelta==0 → area 8 */
    else { extra = 0（ship）; rsp += extra; }                                                     /* ← 少 8 */
}
```

把这次崩溃的参数代进去：

| 量 | 值 | 依据 |
|---|---|---|
| 返回地址 `ret` | `0x7ff81ec83a87`（静态 `0x7ff8079faa87`） | `+147` 的 call 之后 |
| `asyncsite`（`ret` 处 `48 83 ec 08`） | **true** | 实测字节 `48 83 ec 08 49 83 fc ff` |
| `a2x_ret_is_task_resume`（`ret-3..ret-1 = ff 57 38` + `dladdr` 命中 `libswiftConcurrency`） | **true** | 实测字节 `ff 57 38`，`callq *0x38(%r15)` = `41 ff 57 38` |
| `a2x_gdelta` | **−16** | 日志 `returned with sp -16` |
| 实际追加 | **0** | 负分支，ship |
| ABI 要求 | **8** | §2.3 / §3 |

→ 净效果：`rsp` 少弹 8。**这不是「guest 返回值不合规」的次要问题，而是 x86 侧唯一该看的量被一个和 x86 栈无关的量否决了。**

关键论证（这是根因层面的，不是经验拟合）：

> `xs[31]` 指向 `__arm2x86_ensure_stack()` 分配的**独立 8 MiB arm 栈**；`ss->__rsp` 是 x86 线程栈。**guest 无论怎么动 sp，都不可能改变 x86 栈上那 8 字节是否存在。** 因此 `gdelta` 只能用来推断「guest 自己弹掉了多少它的栈参数」（swifttailcc 的 callee-pop），**不能用来决定 x86 的 async word 弹不弹**。而本次调用点是 job resume：`Run(Job*, SerialExecutorRef)` 的参数全在寄存器里（`41 ff 57 38` 前没有任何 `mov ... (%rsp)` 形式的出栈参数），x86 侧压根没有栈参数，所以答案恒为 **8**。

`gdelta = −16` 的来源（与 x86 无关，见 §6.2）：guest 函数 `0x1001be678` 的尾声
```asm
0x1001be778  ldp  x29, x30, [sp, #0x60]
0x1001be78c  and  x29, x29, #0xefffffffffffffff   ; 清 async 帧位
0x1001be790  add  sp, sp, #0x70                   ; 只释放 0x80 帧里的 0x70
0x1001be794  add  x16, sp, #0x10
0x1001be798  autib x30, x16                       ; 用 sp+0x10 复算原始 sp 做认证
0x1001be7a8  b    0x1005651f4                     ; 尾跳到通用实现（stub）
```
它在尾跳前先把 `x5/x6/x7` 从自己帧里重装（`ldp x5,x6,[sp]` / `ldr x7,[sp,#0x10]`），并把最后 `0x10` 字节留在 sp 之下交给尾调用的被调方，所以 a2x 看到的净位移是 −0x10。这是 **guest 内部、在 guest 自己那块栈上**的记账：`autib x30, x16` 用 `sp+0x10` 复算的正是入口 sp，说明「少收 0x10」是这段代码的**设计**，不是跑偏。

### 5.2 最小改动（一行）

```c
            } else {
                /* ⛔ 负 gdelta 是 guest 自己的尾调用记账（0x1001be678 释放 0x70/0x80 后 b <stub>），它发生在
                   __arm2x86_ensure_stack() 的独立 arm 栈上，推不出 x86 栈该弹多少。job resume 的 x86
                   调用点没有栈参数，async word 恒为 8——与 gdelta == 0 完全一致。 */
                long long extra = 8;                      /* was: 0 */
#if !A2X_SHIP
                const char *e = getenv("A2X_ASYNC_NEG_AREA");
                if (e) extra = strtoll(e, 0, 0);
#endif
                ss->__rsp += (unsigned long)extra;
```

要点：
- **只把「负分支」改成和「零分支」同值（8）**，不动正分支里那套 `N+16 → 0x28` 的经验映射（那是给 swifttailcc 栈参数用的，另一条路）。
- 现有 `A2X_ASYNC_NEG_AREA` 环境变量正好是这个改动的开关，**因此不重编也能验证**（见 §7）。
- 该分支的日志已经会打印实际追加量（`... no async area extra 8`），修完自带可观测性。

### 5.3 更彻底（建议随后做，不是本次必须）

对**确认是 task-resume 的**调用点（`asyncsite && a2x_ret_is_task_resume(ret)`），把 area 直接定为常量 8，不再看 `gdelta`：

```c
if (a2x_async) {
    unsigned long area = 8;                    /* job->Run: 无栈参数，恒一个 async word */
    if (!taskresume && a2x_gdelta > 0) { ...原有 N+16 映射... }
    ss->__rsp += area;
}
```

理由：`taskresume` 的语义（`41 ff 57 38` + `48 83 ec 08` + 在 `libswiftConcurrency` 内）已经唯一确定了 x86 面积，`gdelta` 在这个点上没有信息量。风险面也比现在的「按符号分支」小。

---

## 6. 是否需要给 async 函数单独一块 arm 栈？

### 6.1 现状：**已经是独立的**，`sub sp,#0x80` 不可能写穿 x86 caller 帧

```c
/* host_doors.c */
void __arm2x86_ensure_stack(void) {
    if (__arm_sp) return;
    size_t sz = 8u << 20;
    void *p = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    __arm_sp = ((unsigned long)p + sz - 4096) & ~15UL;   /* 每线程 8 MiB，留 4 KiB 余量 */
}
```
```c
/* host.c, a2x_cb_call */
__arm2x86_ensure_stack();
unsigned long asp = (__arm_sp - 64) & ~15UL;                 /* 在当前 arm sp 下开 64 字节窗口 */
{ const unsigned long *sa = (const unsigned long *)(ss->__rsp + 8);
  for (int k = 0; k < 8; k++) ((unsigned long *)asp)[k] = sa[2+k]; }   /* x86 栈参数 → arm 栈 */
xs[31] = asp;
...
__arm_sp = a2x_sp0;                                          /* 返回后复位 */
```

所以：
- guest 的 `sub sp, sp, #0x80` 写在 `[asp-0x80, asp)`，`str x5,[sp]` / `stp x6,x7,[sp,#8]` 写在 `[asp, asp+0x18)`——**全部在独立 mmap 内**，与 x86 返回地址、x86 帧、x86 red zone 都没有重叠。
- 结论：**不需要**为了「别写穿 caller 帧」而另建 async 栈；现有设计已经隔离。本次崩溃与栈空间无关，纯粹是 `rsp` 记账。

### 6.2 但有两处真实风险（与本次崩溃无关，建议单独跟进）

1. **`__arm_sp` 是「顶」，不是「当前」**：`a2x_cb_call` 每次都从同一个 `__arm_sp` 算 `asp`，返回后复位。因此同一线程上**嵌套**的 native→guest 入口（guest → native → guest，正是 `job resume` 的形状）会算出**同一个 asp**，后者的 64 字节窗口 + 帧会覆盖前者仍然活着的帧。这不会写坏 x86 栈，但会写坏 guest 自己的外层帧。
   - 验证方法（很便宜）：在 `a2x_cb_call` 入口打印 `gettid(), asp, __arm_sp, tgt`，抓一次 ControlCenter 触发；若同一 tid 上出现两条 `asp` 相同且前者尚未返回的记录，即命中。
2. **64 字节窗口只做 host→guest 单向拷贝**：`for k in 0..7 asp[k] = sa[2+k]`，没有回写。x86 的 async word 语义是「被调方可能往里写续体要用的 context」；guest 侧的对应字在 arm 栈上，**不会回到 x86 的 `[rsp+8]`**。本次崩溃路径里 x86 那个字本来就是未初始化的（`+147` 前没人写它），所以不影响；但如果哪条路径依赖「guest 写入 → 原生读取」，这里就是缺口。建议在 `g_trace_tramp` 下把 `[rsp+8]` 前后值打出来确认。
3. 另外一个理论风险：guest 帧在 `asp` 之下，而 a2x 的蹦床是**信号处理器**入口（`recover_guest_call`），信号帧由内核压在**当前 rsp 之下**。若在处理 guest 期间再来一个同步信号且没有 `sigaltstack`，内核会压帧到 guest 正在使用的区域。这条我没有实测证据，仅作为结构性提示列出。

---

## 7. 最小可验证实验

### 7.1 用现有开关验证（**不重编、不改系统**）

`A2X_ASYNC_NEG_AREA` 只在 `!A2X_SHIP`（lab）构建里生效，语义就是「负 gdelta 时额外追加多少字节」。**预测值 = 8**。

```bash
cd /Users/geek/Documents/Macintosh/liberator-devkit/src/interpreter/candidate/interp

# 0) 从 guest 切片取出 sharingd 的 entitlements（上一次会话用的是 /tmp/sharingd.entitlements，已被清理，需重建）
codesign -d --entitlements :- /usr/libexec/sharingd > /tmp/sharingd.entitlements.plist

# 1) lab 宿主（不带 A2X_SHIP）
PATH=/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin:$PATH \
HOST_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX27.2.sdk \
HOST_LD_DIR=/Library/Developer/CommandLineTools/usr/bin \
HOST_MINOS=27.2 \
ARM2X86_LLVM=/Users/geek/Documents/Macintosh/a2x-work/llvmbin \
bash mkhost-mac3.sh /tmp/a2xlab/a2xhost-lab
codesign -f -s - --entitlements /tmp/sharingd.entitlements.plist /tmp/a2xlab/a2xhost-lab

# 2) 同 Label、同 15 个 MachServices、StandardErrorPath 的临时 agent（换 Label 会因端口被别人占用而假阴性）
launchctl bootout gui/501/com.apple.sharingd
launchctl bootstrap gui/501 /tmp/diag-sd-syslabel.plist
launchctl print gui/501/com.apple.sharingd | grep -E 'state|runs|active'   # 必须每个 endpoint active=1

# 3) A/B 两次，只差一个环境变量
#    A（对照，复现）：不设
#    B（验证）：在 plist 里加 <key>A2X_ASYNC_NEG_AREA</key><string>8</string>
killall ControlCenter
open "airdrop://"
```

同时打开蹦床追踪（`host.c:2787`，`A2X_DBGENV("ARM2X86_TRACE_TRAMP")`）：

```bash
ARM2X86_TRACE_TRAMP=1          # 增加 [tramp] 0x.. ret=0x.. site=.. task_resume=..
```

**判据（B 组通过）**
- stderr 里出现 `[tramp] async 0x1001be678 returned with sp -16: no async area extra 8`（`extra` 打印 8），
- 且**不再**出现 `FATAL: SIGSEGV` / `a2x-stop: signal SIGSEGV fault 0x0`，
- 且 `launchctl print` 的 `runs` 不增长（`state = running`，`last exit code` 不刷新），
- `log show --last 2m --predicate 'process == "sharingd"'` 里 `AvailableDiscoverability` 的 START/END 成对且进程不退出。

**反证（若 8 是错的，会看到什么）**
- 会变成「多弹 8」→ `rsp` 高 8 → `+0x8c` 之后帧底高 8 → 尾部 pop 反向错位 → 崩溃签名**改变**：不再是 `rip=0 / [rsp]=0 / swift_job_runImpl+0x8c`，而是 `ret` 跳进一个**已映射但无意义**的地址（堆指针或栈地址），`[host] stack[k]` 里也不会再出现 `+0x8c`。
- 因此「崩溃消失」和「崩溃签名变化」是可区分的：前者支持根因，后者说明常数仍不对（下一步扫 `A2X_ASYNC_NEG_AREA` ∈ {0,8,16,24}，看哪一档同时满足「不崩」+「startup/回归正常」）。

### 7.2 不依赖 sharingd 的最小自检（纯静态、可进 CI）

把 §2.3/§3 的三条判据做成断言，不需要跑 guest：

1. `ret = 0x7ff8079faa87` 处字节必须是 `48 83 ec 08`（`sub $8,%rsp`）；
2. `ret-3..ret-1` 必须是 `ff 57 38`（`callq *0x38(%r15)`），且 `dladdr(ret)` 命中 `libswiftConcurrency`；
3. 全库统计 `callq *0x38(%r15)` 共 **8** 处，其中**只有** `runJobInEstablishedExecutorContext` 的两处（`+0x93`、`+0x183`）同时满足「前面有 `movq 0x40(%r15),%r14`（或 `movq %r15,%rdi`）+ 后面紧跟 `sub $8,%rsp`」；其余 6 处是**四参数**对象方法调用（`rdi/rsi/rdx/rcx` 由调用点显式装载，邻近 `callq *0x8(%rax)` / `*0x20(%r15)` 的同族 vtable 序列），既不装载 `r14 = job->0x40`，也不带 async 语义。**所以 `a2x_ret_is_task_resume` 必须继续以 `asyncsite`（`48 83 ec 08`）为前置**，不能单用 `ff 5? 38` 判定——否则会把这 6 处普通 vtable 调用误判成 task resume。

（第 3 条是这次顺带确认的：单看 `ff 5? 38` 会误判 6 处普通 vtable 调用。）

---

## 8. 未验证项

1. **`A2X_ASYNC_NEG_AREA=8` 的实机 A/B 尚未执行**（本会话只读 + /tmp；跑 lab 宿主需要 bootout 系统 job，属于会中断 AirDrop/Handoff 端点的操作，按约束留给有窗口时做）。
2. **`0x10`（而非 `8`）是不是 guest 侧「async area」的尺寸**：guest 尾声留 `0x10` 然后尾跳，我按「给尾调用的被调方留栈参数」解释；`clang -target arm64` 的 `swiftasynccall` 样例里根本没有 async area，两者并存说明 guest 那 `0x10` 至少不必然是 async word。**这不影响 §5 的结论**：无论它是参数区还是 async 区，都在独立 arm 栈上，与 x86 rsp 无关。
3. **§6.2-1（嵌套入口复用同一 `asp`）** 未实测。属于结构性推断，给出了验证方法。
4. **ship 构建没有 `A2X_ASYNC_NEG_AREA` 通道**：验证通过后必须把 8 落成默认值（§5.2），否则 ship 行为不变。
5. **`gdelta > 0` 那条 `N+16 → 0x28` 的经验映射**本次没有复核，只确认它和本次崩溃无关（本次 gdelta<0）。按 §5.3 改造时应单独跑回归。
6. 本报告没有修改 `/System`、`/Library`、EFI，没有重启、没有部署、没有改 a2x 源码；所有产物在 `/tmp/a2xrev`。

---

## 附录 A：地址表（`slide = 0x17289000`）

| 符号 | 静态 | live |
|---|---|---|
| `swift_job_run` | `0x7ff8079fc550` | `0x7ff81ec85550` |
| `swift_job_runImpl` | `0x7ff8079fc580` | `0x7ff81ec85580` |
| **`swift_job_runImpl + 0x8c`（崩溃点）** | `0x7ff8079fc60c` | **`0x7ff81ec8560c`** |
| `runJobInEstablishedExecutorContext` | `0x7ff8079fa9f0` | `0x7ff81ec839f0` |
| ├ async 调用点 `+0x93` | `0x7ff8079faa83` | `0x7ff81ec83a83` |
| └ 返回点 `+0x97` | `0x7ff8079faa87` | `0x7ff81ec83a87` |
| `swift_task_switch` | `0x7ff8079fceb0` | `0x7ff81ec85eb0` |
| `swift_task_switchImpl` | `0x7ff8079fcf10` | `0x7ff81ec85f10` |
| `swift_task_switchImpl + 0xfb (retq $8)` | `0x7ff8079fd00b` | `0x7ff81ec8600b` |
| `non_future_adapter` | `0x7ff807a011c0` | `0x7ff81ec8a1c0` |

## 附录 B：字节证据

```
0x7ff8079faa83  41 ff 57 38   callq *0x38(%r15)          ; job->Run(swiftasync)
0x7ff8079faa87  48 83 ec 08   subq $8,%rsp               ; asyncsite = true
0x7ff8079fd00b  c2 08 00      retq $0x8                  ; swift_task_switchImpl 的 async 返回
0x7ff807a011e0  ff e0         jmpq *%rax                 ; non_future_adapter 尾跳进 guest async fn
```

## 附录 C：本报告的反汇编复现路径（只读，全部在 /tmp）

```bash
# 1) 从 x86_64 shared cache 取出 libswift_Concurrency 的 __TEXT（无 root）
#    dyld_cache_header: magic[16] | mappingOffset@0x10 | mappingCount@0x14
#    mapping_info 条目 0x20 字节: addr,size,fileOffset,maxProt,initProt
#    镜像起点 0x7ff8079f8000；__TEXT fileoff 在 cache 内是绝对值，重建时需归零并重写各 section.offset
python3 /tmp/a2xrev/textonly.py 0x7ff8079f8000 /tmp/a2xrev/conc_text.dylib
otool -tv /tmp/a2xrev/conc_text.dylib > /tmp/a2xrev/conc.dis     # 约 6 s / 10 万行

# 2) guest arm64e 侧
lipo -thin arm64e -output /tmp/a2xrev/sharingd.arm64e /usr/libexec/sharingd
otool -tv /tmp/a2xrev/sharingd.arm64e > /tmp/a2xrev/sharingd.dis  # 约 2 min / 140 万行

# 3) ABI 对照（clang 属 CLT，可用）
clang -O2 -S -x c -target x86_64-apple-macosx27.0 a.c -o -
clang -O2 -S -x c -target arm64-apple-macosx27.0  a.c -o -
```

> 工具备注：`/usr/bin/lldb` 与 `/usr/bin/otool` 都是 universal，但本机 a2x 会把 `lldb` 以 **arm64e guest** 方式跑起来（`target create` 报 `host platform architectures: arm64e, ...`），所以 `lldb` 读不了这份 thin x86_64 文件；`llvm-objdump` 是纯 arm64，且 `--start-address` 对 Mach-O 无效。**结论：静态反汇编用 `otool -tv` + 地址窗口过滤最稳。** 另外 `swiftc` 在本机直接死在 `a2xhost-mac __arm2x86_interp_native + 708`（CLT 也是被 a2x 路由的 arm64e），所以本次 ABI 对照只用 clang，未用 Swift 编译器。

（全文完）
