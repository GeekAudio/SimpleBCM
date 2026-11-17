# 27-only Set 请求（363/469/483/490/512/575）的 27 internal handler 逆向与适配方案

- 日期：2026-11-18
- 目标系统：macOS 27.2（26B123，x86_64，BCM43602），内核集合 `/System/Library/KernelCollections/BootKernelExtensions.kc`
- 被分析镜像：`com.apple.iokit.IO80211Family`，KC fileset 入口 `0xffffff8001e80000`，`kmutil showloaded` 显示版本 `1200.13.1`，UUID `FCFF2E2C-C353-3ED2-9010-D88CC8A08050`，镜像长度 `0x2fc4ce`
- 驱动侧：SimpleBCM（`cn.laobamac.SimpleBCM 1.2.1`，加载于 `0xffffff8003f9a000`，依赖 55 = IO80211Family），分支 `wifi-assoc-probe`，HEAD `222ed98`
- 本文所有地址均为 **运行时内核虚拟地址（下称 KVA）**；除注明外均为 27 的 IO80211Family。
- 只读分析，未修改任何系统文件、未部署、未重启。

---

## 0. 结论摘要

1. **六个 type 在 27 里有三套表，落点各不相同**：`__ZL16gSetHandlerTable`（607 项）**六个全有**；`_gSetHandlerTableLegacy`（457 项）只有 363 在表内（idx 362），469/483/490/512/575 全部越界；`__ZL24gInternalSetHandlerTable`（607 项）**六个全有**，且是 2 参数薄封装。
2. **六个 internal handler 的签名统一为** `int handler(IO80211SkywalkInterface *iface, T *kernelData)`（mangled 名里带 `apple80211_<T>_data` 类型），**没有 controller、没有 user client、没有 apple80211req**。真实依赖全部在 `iface` 的 vtable 上：先 `isCommandProhibited(type)`，再 `safeMetaCast(iface, <protocol>::gMetaClass)`，最后 tail-jump 到协议 vtable 里的真正 setter。
3. **返回语义**：`0` 成功；`0x66`（EOPNOTSUPP，观测到的 102）不支持；`0x16`（EINVAL）长度不符；`0xe082280e` "该接口不承载此协议"；`0xe082280f` "WCL 未处理，回退"。分发器 `apple80211RouteInternal` 把 `{0xe082280d, 0xe082280e}`、`0x66`、`0xe00002c7` 视为"预期失败"，不额外打日志。
4. **六个 tail slot 在 27 的基类协议 vtable 里全是 `__cxa_pure_virtual`（`0xffffff8000bf9100`）**：`InfraProtocol` 的 vptr+0x1270/0x1358/0x1430/0x1508、`NoneProtocol` 的 vptr+0x1ef0/0x1f60。也就是说**这六个方法必须由驱动子类（payload2 里的接口类）覆写，基类对象直接调用会进纯虚函数 → panic**。
5. **本机不存在可用的 27 协议对象**：`ioreg` 的类实例计数为 `IO80211SkywalkInterface=0`、`IO80211InfraProtocol=0`、`IO80211Controller=0`、`IO80211VirtualInterface=0`，而 `SB80211SkywalkInterface=1`、`SB80211InfraInterface=1`、`SB80211VirtualInterface=1`。驱动 payload 链接的是 **payload0（IO80211FamilyLegacy）** 那一族：payload1 里有 `U __ZN17IO80211Controller20apple80211_ioctl_setEP23IO80211SkywalkInterfacePv`，而 27 kext 的符号表里**没有**任何 2 参数 `apple80211_ioctl_get/set`。
6. **因此"从 SimpleBCM 上下文直接调用 27 internal handler"不可行且不安全**：对象族不匹配（payload0 的 `IO80211SkywalkInterface` vtable 只有 409 项 = `0xcc8` 字节，vptr+0xcf8 已经越界）、六个 tail slot 在基类是纯虚、SimpleBCM 自造的假对象 vtable 仅 512/302 项（`bcmLegacySkywalkVtable[512]`、`nativeViews[3][512]`），0x1270+ 全部越界。最坏结果是任意函数指针调用（panic），不是返回错误码。
7. **最小可行方案**：在 `Bridge::command` 的 set 分支最前面拦截六个 type，走 boot-arg 门控的"已知不支持 → 明确返回"路径（默认保持 `0x66`；`-sbcm27sets=1` 返回 `0`；`=2` 只计数仍返回 `0x66`），同时给 payload0 的 **2 参数 `IO80211Controller::apple80211_ioctl_set`** 加同样的钩子（驱动自己的调用路径走这里，会打 `out of 417` 日志），覆盖 Classic / Virtual / Skywalk 三种端点。
8. **风险必须写清**：返回 `0` 是"伪造成功"（airportd 会认为配置已生效，`WoW: FAILED … -3903` 会消失，但驱动侧并未真正应用外部电源状态 / OS eligibility）；它只能作为诊断与消音手段，不能称为根因修复。真转发需要 27 协议对象 + 驱动覆写的 slot + 隐藏符号解析，三者当前都不具备。
9. **验证**：加 `Set27Hits/Set27LastType/Set27LastResult` 计数器并在 `Bridge::publish` 暴露成 ioreg 属性；观察 `SetRes*` 不再出现 102、`log show` 里 `not recognized: 483/512` 消失、airportd 的 `-3903` 消失；再加一条门控"真转发探针"计数器区分"返回 0"与"handler 真的跑了"。

---

## 1. 方法与复现

### 1.1 把 KC 里的 kext 抽成 objdump 可吃的 Mach-O

`Tools/kernel_collection.py` 只能按 KVA 读字节，`llvm-objdump` 直接对着 `.kc` 只认 root fileset，不认 kext 的 KVA。做法：把 fileset entry 的 header + load command 复制到文件头，把所有 `LC_SEGMENT_64.fileoff`、`section.offset`、`LC_SYMTAB.symoff/stroff` 减去 entry 偏移，`LC_DYSYMTAB` 的 linkedit 偏移清零，然后按新偏移铺段数据。脚本 `/tmp/sb27/kcdis.py`（附录 A），产出 `/tmp/sb27/IO80211Family27.macho`（`0x207c000` 字节），之后：

```bash
llvm-objdump -d --arch=x86_64 --no-show-raw-insn \
  --start-address=0xffffff8001f70c3a --stop-address=0xffffff8001f70c9a \
  /tmp/sb27/IO80211Family27.macho
```

objdump 会顺带解析出 kext 内符号名，跨 kext/内核的调用目标再用 KC 的 symbol table 回填。

### 1.2 表项解码

KC 是 chained fixups：表项是 rebase 记录，`kc.pointer(addr)` 的规则（`(value & 0x3FFFFFFF) + fixup_base`）对表项与 vtable 都成立，已用已知项交叉校验：`set[19] = apple80211setASSOCIATE`（type 20）、`get[10] = apple80211getSCAN_RESULT`、`get[102] = getCurrentNetwork`。

### 1.3 运行期只读证据

```bash
kmutil showloaded | grep -iE '80211|simplebcm'
ioreg -rn SimpleBCM -l                 # 计数器
ioreg -w0 -l -p IOService > /tmp/ioreg.txt   # 类实例计数 + 父子链
ioreg -w0 -p IO80211Plane              # 控制器/en1/P2P，仅三个节点
```

---

## 2. 27 的 set 表结构与六个 type 的落点

### 2.1 表地址与容量

| 符号 | KVA | 容量 | 说明 |
| --- | --- | --- | --- |
| `__ZL16gGetHandlerTable` | `0xffffff800218c150` | 627 | IOUC/新路径 get 表 |
| `__ZL16gSetHandlerTable` | `0xffffff800218d590` | 607 | IOUC/新路径 set 表（**六个全有**） |
| `__ZL24gInternalGetHandlerTable` | `0xffffff80021aac90` | 608 | internal get（下一符号紧邻，含 1 项对齐余量） |
| `__ZL24gInternalSetHandlerTable` | `0xffffff80021abf90` | 607 | internal set（**六个全有**，2 参数） |
| `_gGetHandlerTableLegacy` | `0xffffff800219e6e0` | 590 | BSD ioctl legacy get |
| `_gSetHandlerTableLegacy` | `0xffffff80021a6b10` | 457 | BSD ioctl legacy set |
| `_gGetHandlerTableLegacyCount` | `0xffffff80020cac80` | u32 = 590 | |
| `_gSetHandlerTableLegacyCount` | `0xffffff80020d8150` | u32 = 457 | |

容量按"下一个符号地址 − 表地址"实测（表与表紧邻、无填充）：`0x12f8/8 = 607`、`0x1398/8 = 627`、`0xe48/8 = 457`、`0x1270/8 = 590`。607 与 `apple80211RouteInternal` 的边界 `type-0x260`（1..607）互相印证；457/590 与 `_gSetHandlerTableLegacyCount=457`、`_gGetHandlerTableLegacyCount=590` 一致。

### 2.2 六个 type 在四张表里的实际指针

| type | `gSetHandlerTable`（607） | `_gSetHandlerTableLegacy`（457） | `gInternalSetHandlerTable`（607） | payload0 的 417 表 |
| --- | --- | --- | --- | --- |
| 363 | `setUSB_HOST_NOTIFICATION` `0x1f8e7a1` | `setUSBHostNotification` `0x2061387` | `apple80211setUSB_HOST_NOTIFICATION` `0x1f6f611` | idx 362 有项，返回 0x66 |
| 469 | `setOS_FEATURE_FLAGS` `0x1f8f8e6` | **越界**（idx 468 > 456，读到相邻数据） | `apple80211setOS_FEATURE_FLAGS` `0x1f707de` | 越界 |
| 483 | `setEXTERNAL_POWER_STATE` `0x1f8fc5a` | **越界**（idx 482） | `apple80211setEXTERNAL_POWER_STATE` `0x1f70c3a` | 越界 |
| 490 | `setPRODUCT_INFO` `0x1f8fefa` | **越界**（idx 489） | `apple80211setPRODUCT_INFO` `0x1f70df9` | 越界 |
| 512 | `setINFRA_ENUMERATED` `0x1f903b6` | **越界**（idx 511） | `apple80211setINFRA_ENUMERATED` `0x1f71409` | 越界 |
| 575 | `setOS_ELIGIBILITY` `0x1f912fe` | **越界**（idx 574） | `apple80211setOS_ELIGIBILITY` `0x1f72105` | 越界 |

> 这修正了 `Docs/Analysis-20261117-driver-side.md` §2.1 的一个隐含判断："六个只有 27 internal 表有实现"不准确——27 的 **`gSetHandlerTable`（607 项）六个都有完整 4 参数实现**，只是 legacy 表（457）放不下它们。因此"27 自己也没有实现"不是事实；问题是**入口**：payload0 的 417 表是 legacy 版本，没有这些项。

### 2.3 27 的三个内部分发器

1. `apple80211RouteExternal(IO80211SkywalkInterface*, IO80211APIUserClient*, unsigned long cmd, apple80211req*, bool, bool)` @ `0xffffff8002074b4c`
   - cmd == `0xc02869c9`（get）→ `_gGetHandlerTableLegacy`（590），handler 调用形式 `handler(iface, uc, req, bool)`。
   - cmd == set → `_gSetHandlerTableLegacy`（457），同上。
   - 另一分支（`type-0x260` 边界，即 type 1..607）→ `__ZL16gSetHandlerTable`（607），`handler(iface, uc, req, bool)`；六个 type 走这支才有实现。
2. `apple80211RouteInternal(uint32_t cmd, int type, IO80211SkywalkInterface *iface, void *data)` @ `0xffffff8002074e1d`（mangled `__Z23apple80211RouteInternaljiP23IO80211SkywalkInterfacePv`）
   - 3 个以上的参数：`edi`=cmd、`esi`=type、`rdx`=iface、`rcx`=data。
   - 边界：`eax=-0x260; ecx=type-0x260; jbe → 0x66`，即有效 **type ∈ [1, 0x25f]（607）**。
   - `handler = gInternalSetHandlerTable[type-1]`；调用 `handler(rdi=iface, rsi=data)`（`0x2074f00: movq %r15,%rdi; movq %r12,%rsi; callq *%rax`）。
   - `data` 是**内核指针**（调用者传入的是内核结构体，见 §5.3 的 `setAwdlSyncParams`）。
   - 事后处理：结果 ∈ `{0xe082280d, 0xe082280e}`、`0x66`、`0xe00002c7` 视为预期失败，否则记录/上报。
   - 全镜像里有 **49 处** `call apple80211RouteInternal`，是 27 内部请求的标准入口。
3. payload0 的两个 legacy 入口（SimpleBCM 实际用到的那一族）：
   - 5 参数 `IO80211Controller::apple80211_ioctl_set(IO80211Interface*, IO80211VirtualInterface*, IO80211SkywalkInterface*, void*)` @ payload0 `0x91ede`（417 表，越界/空项/返回 0x66 都打 `IOCTL (from pid %d) not recognized: %d out of %d`）。
   - 2 参数 `IO80211Controller::apple80211_ioctl_set(IO80211SkywalkInterface*, void*)` @ payload0 `0x92016`：`movq %rdx,%r8; movq %rsi,%rcx; xor esi,esi; xor edx,edx; jmp 0x91ede`——**驱动自己的调用路径就是这条**。

---

## 3. 六个 internal handler 的反汇编

### 3.1 统一形状

六个都是同一个模板（以 483 为例，`0xffffff8001f70c3a`）：

```asm
apple80211setEXTERNAL_POWER_STATE:            ; (rdi=iface, rsi=data)
  movq (%rdi), %rax                           ; vptr
  movl $0x1e3, %esi                           ; 参数 = 请求 type
  callq *0xcf8(%rax)                          ; vptr+0xcf8 = isCommandProhibited(int)
  testl %eax, %eax
  jne  .return                                ; 非 0 → 直接返回该值
  leaq IO80211NoneProtocol::gMetaClass, %rsi
  movq %r14, %rdi
  callq OSMetaClassBase::safeMetaCast         ; 0xffffff8000a54170
  testq %rax, %rax
  je   .unsupported                           ; → movl $0xe082280e,%eax; ret
  movq (%r14), %rax
  movq 0x1ef0(%rax), %rax                     ; 协议 vtable 的真正 setter
  movq %r14, %rdi
  movq %rbx, %rsi
  jmpq *%rax                                  ; tail-call，返回值原样传出
```

`0xe082280e` 是 27 自己的"该接口不承载此协议"约定（同文件里 `apple80211setAUTH_TYPE` 就是 `movl $0xe082280e,%eax; ret` 的三指令 stub）。

### 3.2 六个 handler 明细

| type | internal handler KVA | gate 参数 | `safeMetaCast` 目标 | tail slot（相对 vptr） | 该 slot 在 27 基类 vtable 的值 |
| --- | --- | --- | --- | --- | --- |
| 363 | `0xffffff8001f6f611` | `0x16b` | `IO80211InfraProtocol`（`0xffffff80021bcee0`） | `+0x1270`（slot 590） | `__cxa_pure_virtual` |
| 469 | `0xffffff8001f707de` | `0x1d5` | `IO80211InfraProtocol` | `+0x1358`（slot 619） | `__cxa_pure_virtual` |
| 483 | `0xffffff8001f70c3a` | `0x1e3` | `IO80211NoneProtocol`（`0xffffff80021bb1f0`） | `+0x1ef0`（slot 990） | `__cxa_pure_virtual` |
| 490 | `0xffffff8001f70df9` | `0x1ea` | `IO80211NoneProtocol` | `+0x1f60`（slot 1004） | `__cxa_pure_virtual` |
| 512 | `0xffffff8001f71409` | `0x200` | `IO80211InfraProtocol` | `+0x1430`（slot 646） | `__cxa_pure_virtual` |
| 575 | `0xffffff8001f72105` | `0x23f` | `IO80211InfraProtocol` | `+0x1508`（slot 673） | `__cxa_pure_virtual` |

- `+0xcf8` 槽在 27 里是 `IO80211SkywalkInterface::isCommandProhibited(int)` @ `0xffffff8001ffe6ea`，实现是：`rdi = iface->vtable[0xbd8](iface)`（controller），再 `jmp *0xc50(controller_vptr)`，把 type 传下去。**它自己也是 vtable 间接层**。
- 六个 tail slot 的原始 qword 全部是 `0x0040000000af9100` → `0xffffff8000bf9100` = `___cxa_pure_virtual`。`__ZTV20IO80211InfraProtocol` 的范围 `0xffffff8002192e20..0xffffff8002194368`（`0x1548` 字节 = 681 项），`__ZTV19IO80211NoneProtocol` 范围 `0xffffff800217e398..0xffffff80021809c8`（`0x2630` = 1222 项）——slot 索引确实落在表内，但值是纯虚。
- 结论：**这六个 setter 由驱动子类覆写**（27 的基类协议只声明），只有真正的驱动接口对象调用才安全。

### 3.3 27 的 4 参数实现（`gSetHandlerTable`）——真转发的另一候选

六个 4 参数 handler 的共同形状（以 483 为例 `0xffffff8001f8fc5a`）：

```c
int setEXTERNAL_POWER_STATE(IO80211Controller *c, IO80211SkywalkInterface *iface,
                            IO80211APIUserClient *uc, apple80211req *req) {
    if (!iface) return 0x66;
    if (req->length != 1) return 0x16;         // 0x18(%rcx)
    void *data = req->data;                    // 0x20(%rcx)
    if (!data) return 0x16;
    int r = iface->routeIoctlToWcl(0x802869c8, 0x1e3, data, 1);   // 0x1ffe712
    if (r != 0xe082280f) return r;
    return apple80211setEXTERNAL_POWER_STATE(iface, data);         // 2 参数封装
}
```

各 type 的长度门禁与附带副作用：

| type | 长度（`req->length`） | WCL type | 额外动作 |
| --- | --- | --- | --- |
| 363 | 0x10（16） | 0x16b | 无 |
| 469 | 0x8（8） | 0x1d5 | 之后 `controller->setOSFeatureFlags(req->data)` + `controller->loadCardCapabilities(iface)` |
| 483 | 0x1（1） | 0x1e3 | 无 |
| 490 | 0x12c（300） | 0x1ea | 无 |
| 512 | 0x1（1） | 0x200 | 无 |
| 575 | 0x4（4） | 0x23f | **派发前**就写 `controller->[0x120]->b6c = 1`、`->b68 = *(u32*)data`（长度不符也照写） |

长度不符一律 `0x16`（EINVAL）。`routeIoctlToWcl` 是 `IO80211SkywalkInterface` 的非虚方法（`0xffffff8001ffe712`），内部读 `0x120(%rdi)`、`0xd8(%rax)`，**对非 27 对象是野指针解引用**。

---

## 4. 签名、返回语义与依赖总结

| 问题 | 结论 | 证据 |
| --- | --- | --- |
| 形参 | `(IO80211SkywalkInterface*, T*)`，T 为 `apple80211_usb_host_notification_data` / `_feature_flags` / `_external_power_state` / `_product_info` / `_infra_enumerated` / `_os_eligibility` | mangled 名 + 反汇编 |
| 是否需要 controller | 否（要 controller 时通过 `iface->vtable[0xbd8]` 现取） | `isCommandProhibited` |
| 是否需要 user client | 否 | 2 参数签名 |
| 是否需要 skywalk 对象 | **是**，且必须是承载 `IO80211InfraProtocol` 或 `IO80211NoneProtocol` 的接口对象 | `safeMetaCast` + 纯虚 slot |
| 是否访问 req | 否（直接吃内核数据指针） | 反汇编 |
| 返回 0 | 成功 | 分发器把 0 当成功 |
| 返回 0x66 | 不支持；airportd 侧映射为 `-3903` | ioreg `SetRes*=102` + 既有日志 |
| 返回 0x16 | 长度不符（4 参数实现自己的门禁，不是 internal handler 的） | §3.3 |
| 返回 0xe082280e | 接口不承载该协议 | `apple80211setAUTH_TYPE` stub |
| 返回 0xe082280f | WCL 未处理，用于回退 | 4 参数实现 |
| 线程/锁 | internal handler 自身无锁；但 vtable 目标（驱动）与 WCL 路由可能有 gate/lock；调用必须在该接口的 workloop 之外还是之内**未验证** | 反汇编无 `IOLock`/gate 调用 |

---

## 5. 从 SimpleBCM 上下文调用的可行性

### 5.1 SimpleBCM 手上有什么对象

`Bridge::identify()`（`SimpleBCM/Bridge.cpp:214-261`）对三种端点分别取 controller/name：

- `Classic` → `payload0.IO80211Interface::getController/getBSDName`，对象是 **en1 = `AirPort_BrcmNIC_Interface`**；
- `Virtual` → `payload0.IO80211VirtualInterface::...`；
- `Skywalk` → 沿 provider 链找 `AirPort_BrcmNIC`，名字用 `payload0.IO80211SkywalkInterface::getBSDName`。

运行期实际用户客户端（`ioreg -w0 -l -p IOService` 解析父子链）：

| 提供者 | 类 | 数量 | 进程 |
| --- | --- | --- | --- |
| en1 | `AirPort_BrcmNIC_Interface` | 8 | airportd(217) / configd(116) |
| AirPort_BrcmNIC_P2PInterface | `AirPort_BrcmNIC_P2PInterface` | 2 | airportd |

`IO80211Plane` 只有三个节点：`AirPort_BrcmNIC`、`en1`、`AirPort_BrcmNIC_P2PInterface`。**没有任何 skywalk / infra 接口被发布**。

SimpleBCM 自造对象的 vtable 容量：

- `BCMLegacyInterface`：`bcmLegacySkywalkVtable[512]`（`SimpleBCM/NativeSkywalk.cpp:61-63`），按 `skyLegacyEntries` 填 `skyLegacySlotCount` 项（`:240-246`）→ 最大 vptr 偏移 `0xff8`；
- 原生视图：`nativeViews[3][512]`（`:88`）、`clientViews[2][302]`（`NativeUserClient.cpp:23`）。

### 5.2 关键运行期事实

- `ioreg -rn SimpleBCM -l`：`SetHist0..15 = 483`、`SetLen* = 1`、`SetRes* = 102`、`LastSetResult = 102`、`SetCount = 1802`、`Rejects = 0`。
- `ReqFlg*` = `set?1:0 | (kind<<8)`：483 的条目是 `1` → **kind = 0 = Classic**。即 airportd 的 483 是**在 en1 的 classic 端点上**发出的，走 `performCommand`，**不经过 payload0 的 417 表**。
  - payload0 的 `IO80211Interface::performCommand` @ `0x9576e`：识别 `0x802869c8`（set）后 `call *0x850(controller_vptr)` → `performGatedCommand` → `IO80211Controller::apple80211RequestIoctl` @ `0x8ee5c` → `call *0xcb0(controller_vptr)` = 驱动的 `apple80211Request`。
  - 所以 Classic 的 `0x66` 来自**驱动侧**，不是 417 表。
- 417 表的 "out of 417" 日志来自 payload0 的 `apple80211_ioctl_set`（5 参数 0x91ede / 2 参数 0x92016），也就是 Virtual/Skywalk 端点，以及**驱动自己**对 `apple80211_ioctl_set(skywalk, req)` 的调用。
- 类实例计数（`IOKitDiagnostics`）：`IO80211SkywalkInterface=0`、`IO80211InfraProtocol=0`、`IO80211Controller=0`、`IO80211VirtualInterface=0`；`SB80211SkywalkInterface=1`、`SB80211InfraInterface=1`、`SB80211VirtualInterface=1`、`AirPort_Brcm43xxLLSkywalkInterface=1`、`BCMLegacyInterface=1`、`BCMNativeInterface=1`。

### 5.3 驱动链接的是 payload0 那一族

payload1（`AirPortOriginal`）的未定义导入：

```
U __ZN17IO80211Controller16apple80211_ioctlEP23IO80211SkywalkInterfacemPv
U __ZN17IO80211Controller20apple80211_ioctl_getEP23IO80211SkywalkInterfacePv
U __ZN17IO80211Controller20apple80211_ioctl_setEP23IO80211SkywalkInterfacePv
U __ZN17IO80211Controller24apple80211SkywalkRequestEjiP23IO80211SkywalkInterfacePv
U __ZN17IO80211Controller26getPrimarySkywalkInterfaceEv
U __ZN17IO80211Controller15attachInterfaceEP18IOSkywalkInterfaceP9IOService
U __ZN17IO80211Controller15detachInterfaceEP18IOSkywalkInterfaceb
U __ZN17IO80211Controller6enableEP23IO80211SkywalkInterface
U __ZN17IO80211Controller7disableEP23IO80211SkywalkInterface
```

这些符号在 **payload0** 全部有定义（`0x91c08`、`0x91eca`、`0x92016`、`0x92e44`、`0x91b62`、`0x929ba`…），而 **27 kext 的 symbol table 里一个 2 参数 `apple80211_ioctl_*` 都没有**（只有 `apple80211RouteExternal` / `apple80211RouteInternal`）。因此驱动与它的接口对象绑定在 **payload0 的 IO80211 家族**（运行时 metaclass 名是 `SB80211*`），而不是 27 的 `IO80211*` 家族。

### 5.4 判定

**不可行，且不安全。** 具体四条：

1. **对象族不匹配**：27 handler 要求 `safeMetaCast(iface, &IO80211InfraProtocol::gMetaClass)` 通过；SimpleBCM 手上只有 payload0 家族对象/假对象，`gMetaClass` 不同 → 必然返回 `0xe082280e`。但在这之前已经执行 `call *0xcf8(vptr)`：payload0 的 `IO80211SkywalkInterface` vtable 只有 `0xcc8` 字节（409 项），**0xcf8 已经越界**，读到的是相邻数据 → 任意函数指针。
2. **就是有正确对象，基类 slot 也是纯虚**：六个 tail slot 在 27 基类 vtable 里是 `__cxa_pure_virtual`，只有驱动子类覆写才有实现；驱动对象（`SB80211*`/`AirPort_BrcmNIC_Interface`）用的是 payload0 的 vtable 布局，不含这些 slot。
3. **符号不可解析**：`apple80211RouteInternal` 与六个 `apple80211setXXX` 都是 **local 符号**（`__ZL`/`__Z` 但非导出），SimpleBCM 的 `KernelPatcher::solveSymbol` 只支持 `KernelID`（kernel + `_copyin/_copyout`）和 payload 内符号（`Patcher.cpp:17-24`），要解析必须在运行时扫 27 kext 的 `LC_SYMTAB` 或按特征码定位（类似 `NativeSkywalk::findNativeLink`），是新工程量。
4. **WCL 路由**：4 参数实现先 `routeIoctlToWcl`，它对 `iface->[0x120]` 做野指针解引用；internal 2 参数封装反而绕开 WCL，但仍有 1、2 两条。

**能做到的最多是"安全地返回一个明确的值"，不是"真转发"。**

---

## 6. 最小可行方案

### 6.1 设计

在 `Bridge::command`（`SimpleBCM/Bridge.cpp:607`）的 set 分支最前面加一层 27-only 过滤，三种端点统一处理（因为 Classic 走 `performCommand`、Virtual/Skywalk 走 `apple80211_ioctl_set`，都被这一个函数汇聚）：

```cpp
/* 27-only set：payload0 的 417 表与 27 的 legacy BSD set 表（457）都放不下，
   27 只在 gSetHandlerTable（607）与 gInternalSetHandlerTable（607）里实现，
   且实现挂在驱动子类覆写的纯虚 slot 上。SimpleBCM 手上没有 27 协议对象，
   因此这里只做"明确语义 + 计数"，不做函数指针转发。 */
static constexpr uint32_t TwentySevenOnlySets[] = {363, 469, 483, 490, 512, 575};

static bool isTwentySevenOnlySet(uint32_t type) {
    for (auto entry : TwentySevenOnlySets)
        if (entry == type) return true;
    return false;
}

/* boot-arg: -sbcm27sets=0 → 维持 0x66；=1 → 返回 0（消音）；=2 → 只计数、仍返回 0x66 */
static int twentySevenSetsMode;   // Bridge::initialize() 里 PE_parse_boot_argn

int Bridge::command(const Endpoint &endpoint, bool set, LegacyRequest &request,
                    void *shadow, size_t size) {
    if (set && isTwentySevenOnlySet(request.request.type)) {
        __atomic_fetch_add(&counters.set27Hits, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&counters.set27LastType, request.request.type, __ATOMIC_RELAXED);
        __atomic_store_n(&counters.set27LastKind, static_cast<uint32_t>(endpoint.kind), __ATOMIC_RELAXED);
        __atomic_store_n(&counters.set27LastLength, request.request.length, __ATOMIC_RELAXED);
        /* payload 已经在内核 shadow 里：UserClient.cpp:388 把 req->data 指向 shadow */
        if (request.request.length && request.request.data) {
            const auto *bytes = reinterpret_cast<const uint8_t *>(request.request.data);
            __atomic_store_n(&counters.set27LastWord,
                             request.request.length >= 4 ? readUInt32(bytes) : bytes[0], __ATOMIC_RELAXED);
        }
        const int result = twentySevenSetsMode == 1 ? 0 : 0x66;
        __atomic_store_n(&counters.set27LastResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        return result;
    }
    ... /* 原有逻辑不变 */
}
```

要点：

- **位置**：必须在 `ready()/isInactive()` 检查之后、`CopyContext` 注册之前，避免影响 `copyin/copyout` 的 shadow 记账（本分支不调 copyIn）。
- **payload 可用**：`UserClient.cpp:388` 把 `legacy.request.data` 改成 `shadow` 内核地址，长度在 `request.request.length`（27 侧 483/512 是 1 字节，575 是 4 字节，与 §3.3 一致）。因此**即使不转发，也能把值记下来**，用于后续判断"驱动是否真的需要这个值"。
- **默认值**：建议默认 `0x66`（保持现状），用 `-sbcm27sets=1` 才返回 0。这样"消音"是显式选择，符合"先取证、后改行为"的仓库纪律。
- **计数**：在 `Counters` 里加 `set27Hits/set27LastType/set27LastKind/set27LastLength/set27LastWord/set27LastResult`，并在 `Bridge::publish()`（`Bridge.cpp:921` 附近）连同现有计数器一起 `setProperty`，这样 `ioreg -rn SimpleBCM -l` 直接可见。

### 6.2 覆盖驱动自己的路径（必须的第二跳）

只改 `Bridge::command` 漏掉一类：驱动（payload2）自己调用 `IO80211Controller::apple80211_ioctl_set(IO80211SkywalkInterface*, void*)`（payload0 `0x92016`）时，请求不经 SimpleBCM 的 user client。要让六个 type 在这条路径上也统一，需要给 payload0 的这个 2 参数入口加钩子：

```cpp
/* Bridge::patchImage(index==0) 里追加一条 route */
extern "C" int bridgeSkywalkIoctlSet(void *controller, void *iface, void *request);
static int (*originalSkywalkSet)(void *, void *, void *);

int bridgeSkywalkIoctlSet(void *controller, void *iface, void *request) {
    auto req = static_cast<uint8_t *>(request);
    uint32_t type = readUInt32(req + 0x10);
    if (isTwentySevenOnlySet(type) && twentySevenSetsMode == 1) {
        __atomic_fetch_add(&counters.set27DriverHits, 1ULL, __ATOMIC_RELAXED);
        return 0;
    }
    return originalSkywalkSet(controller, iface, request);
}
```

构建侧注意：`KernelPatcher::routeMultipleLong` 只 patch **在生成的 payload 里有 RoutePrefix 描述符**的符号（`Tools/profiles.py:55-61` 的 `ROUTE_SYMBOLS`，`Bridge.cpp` 里也注明了这一点）。payload0 的 2 参数 set 只有 20 字节（`0x92016..0x9202a`）：`push rbp / mov rbp,rsp / mov rdx,r8 / mov rsi,rcx / xor esi,esi / xor edx,edx / pop rbp / jmp 0x91ede`，前缀 14 字节正好落在 `pop rbp` 之前，可以被 `routeMultipleLong` 接过（`prefix>=14` 的校验刚好满足）。**这需要改 `Tools/profiles.py` 的 `ROUTE_SYMBOLS["Legacy"]` 并重新生成 payload，不是纯运行期改动**——属于"离线候选 + 重新构建"范围，本次未实施。

### 6.3 真转发（Phase 2，当前不具备条件）

如果将来要真转发，形状如下（**仅作设计参考，当前不可落地**）：

```cpp
using RouteInternal = int (*)(uint32_t cmd, int type, IOService *iface, void *data);

/* 1) 解析 27 kext 的隐藏符号：扫 com.apple.iokit.IO80211Family 的 __TEXT.__text，
      找"引用 gInternalSetHandlerTable 的那条 lea"（静态分析里是 0x2074ee9，
      运行时按位移/特征码定位；或走 LC_SYMTAB 查 __Z23apple80211RouteInternalji...）。
   2) 取 27 侧 iface：需要 IO80211InfraProtocol 实例（本机 0 个）或
      IO80211Controller::getPrimarySkywalkInterface() 的返回（27 家族对象才有意义）。 */
int forward27(const Endpoint &endpoint, LegacyRequest &request) {
    if (request.request.length > 0x12c || !request.request.data)
        return 0x16;
    IOService *iface27 = /* 真正的 27 InfraProtocol/NoneProtocol 对象 */ nullptr;
    if (!iface27)
        return 0x66;
    int result = route27(0x802869c8, request.request.type, iface27,
                         reinterpret_cast<void *>(request.request.data));
    __atomic_store_n(&counters.set27ForwardResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
    return result;
}
```

即便对象问题解决，仍要处理：`575` 的 4 参数实现会在派发前写 `controller->[0x120]->b68/b6c`（27 对象布局，payload0 对象上偏移未验证）；`469` 会额外调 `setOSFeatureFlags`/`loadCardCapabilities`（payload0 没有这两个符号，27 kext 有）；`363/469/483/490/512/575` 的 WCL 路由会碰 `iface->[0x120]`。这三处都要单独验证布局。

---

## 7. 验证方法

### 7.1 计数器（加完就有）

```bash
ioreg -rn SimpleBCM -l | grep -E 'Set27|SetCount|SetRes|LastSetResult'
# 预期（mode=1，已被拦截）：
#   "Set27Hits" = N（随 airportd 周期性配置增长）
#   "Set27LastType" = 483 / 575 / 512 ...
#   "Set27LastKind" = 0（Classic）
#   "Set27LastLength" = 1（483/512）/ 4（575）
#   "Set27LastResult" = 0
# 未拦截时基线：SetRes* = 102、LastSetResult = 102
```

### 7.2 日志

```bash
# 1) 417 表越界日志（payload0 路径；Virtual/Skywalk 端点或驱动自调用）
log show --last 10m --predicate 'eventMessage CONTAINS "not recognized"' | grep -E '483|512|575'
# 拦截后应只剩 469/490（它们的 0x66 来自驱动侧而不是 417 表时，本来就不打这条）

# 2) airportd 侧
ps aux | grep /usr/libexec/airportd        # a2x 下进程名是 a2xhost-mac
log show --last 10m --predicate 'process == "airportd"' | grep -E 'WoW|external power|3903'
# 期望：-sbcm27sets=1 后 'WoW: FAILED to configure external power state on en1, returned -3903' 消失
```

### 7.3 区分"返回 0"与"真转发跑过"

- 只看 `SetRes=0` 无法区分：两者都返回 0。
- 必须加"真转发探针"：在 `-sbcm27sets=2` 模式下**真的调用** `apple80211RouteInternal`，把返回码写进 `Set27ForwardResult`：
  - `0` → handler 真的跑通了（同时 `Set27ForwardPanics` 之类的守卫计数不应增长）；
  - `0xe082280e` → 对象族不匹配（当前预期）；
  - 若为其它值或系统 panic，说明 vtable slot / 布局判断错误。
- 真转发还应在驱动侧留下可观测痕迹：483 影响 WoW 外部电源状态（`iface->[0x120]` 相关字段、`IO80211Controller` 侧属性），575 影响 `b68/b6c`。可在 `ioreg -rc AirPort_BrcmNIC -l` 里对比前后属性；**仅"日志消失"不足以证明真转发**。

---

## 8. 边界与未验证清单

1. **payload2（27 的 AirPortBrcmNIC-Tahoe）在磁盘上不存在**（是 payload1 + delta 运行时还原），因此"驱动子类是否覆写了六个纯虚 slot、覆写后的实现是否就绪"**没有静态证据**。本文的"纯虚"结论只针对 27 kext 基类 vtable，这一条足以否决"拿基类/假对象调用"。
2. **本机不存在 27 协议对象**：`IO80211SkywalkInterface` / `IO80211InfraProtocol` / `IO80211Controller` 实例计数均为 0；`IO80211Plane` 只有 controller/en1/P2P。是否有未发布的 27 对象（例如 wifid 侧）未验证。
3. **六个 payload 结构体只验证了长度**（16/8/1/300/1/4），字段语义（例如 `apple80211_external_power_state` 的 1 字节取值域、`apple80211_os_eligibility` 的 4 字节位）未逐字段确认。
4. **线程/锁上下文未验证**：internal handler 自身不加锁，但 vtable 目标可能在驱动侧要求 workloop/gate；`Bridge::command` 运行在用户客户端线程（airportd 的系统调用上下文），与 27 正常路径（`apple80211RouteInternal` 的调用者）是否同一上下文未确认。
5. **`575` 的预写入**：4 参数实现在长度/指针检查之前就写 `controller->[0x120]->b68/b6c`，说明 27 认为这两个字段必须在派发前落地；SimpleBCM 无法安全复现（payload0 对象布局未知）。
6. **`469` 的附带动作**：`setOSFeatureFlags` + `loadCardCapabilities` 是 27 kext 的符号，payload0 没有；即使返回 0，功能位也不会真正生效。
7. **本次未改任何代码/未重新构建**：§6.2 的 payload0 钩子需要改 `Tools/profiles.py` 的 `ROUTE_SYMBOLS["Legacy"]` 并重新生成 payload，属离线候选。
8. 既有文档 `Docs/Analysis-20261117-driver-side.md` §2.1/§2.3 需要修正两点：
   - "六个只有 27 internal 表有实现" → 27 的 `gSetHandlerTable`（607）六个都有完整 4 参数实现；
   - "实测 0x66 来自 417 表" → Classic 端点的 0x66 来自驱动 `apple80211Request`（`call *0xcb0`），417 表日志只覆盖 Virtual/Skywalk 端点与驱动对 2 参数 `apple80211_ioctl_set` 的自调用。

---

## 附录 A：KC kext 抽取器（`/tmp/sb27/kcdis.py` 要点）

```python
kc = KernelCollection('/System/Library/KernelCollections/BootKernelExtensions.kc')
entry_addr, entry_off = kc.root.entries['com.apple.iokit.IO80211Family']
data = kc.data
out = bytearray(len(data) - entry_off)
# 1) 按原始绝对 fileoff 铺段数据
# 2) 把 header+LC 的 fileoff/section.offset/LC_SYMTAB 偏移整体减 entry_off
# 3) LC_DYSYMTAB 的 tocoff/modtaboff/extrefsymoff/indirectsymoff/extreloff/locreloff 清零
open('/tmp/sb27/IO80211Family27.macho','wb').write(out)
```

## 附录 B：本次用到的关键 KVA 速查

```
27 kext entry / base                     0xffffff8001e80000
apple80211RouteInternal                  0xffffff8002074e1d
apple80211RouteExternal                  0xffffff8002074b4c
gGetHandlerTable / gSetHandlerTable      0xffffff800218c150 / 0xffffff800218d590
gInternalGetHandlerTable / Set           0xffffff80021aac90 / 0xffffff80021abf90
_gGetHandlerTableLegacy / _SetLegacy     0xffffff800219e6e0 / 0xffffff80021a6b10
setUSB_HOST_NOTIFICATION  (363, 4arg)    0xffffff8001f8e7a1
setOS_FEATURE_FLAGS       (469, 4arg)    0xffffff8001f8f8e6
setEXTERNAL_POWER_STATE   (483, 4arg)    0xffffff8001f8fc5a
setPRODUCT_INFO           (490, 4arg)    0xffffff8001f8fefa
setINFRA_ENUMERATED       (512, 4arg)    0xffffff8001f903b6
setOS_ELIGIBILITY         (575, 4arg)    0xffffff8001f912fe
apple80211setUSB_HOST_NOTIFICATION       0xffffff8001f6f611
apple80211setOS_FEATURE_FLAGS            0xffffff8001f707de
apple80211setEXTERNAL_POWER_STATE        0xffffff8001f70c3a
apple80211setPRODUCT_INFO                0xffffff8001f70df9
apple80211setINFRA_ENUMERATED            0xffffff8001f71409
apple80211setOS_ELIGIBILITY              0xffffff8001f72105
IO80211SkywalkInterface::isCommandProhibited   0xffffff8001ffe6ea
IO80211SkywalkInterface::routeIoctlToWcl       0xffffff8001ffe712
OSMetaClassBase::safeMetaCast                  0xffffff8000a54170 (kernel)
__cxa_pure_virtual                             0xffffff8000bf9100 (kernel)
payload0 5 参数 apple80211_ioctl_set            0x91ede
payload0 2 参数 apple80211_ioctl_set            0x92016
payload0 apple80211RequestIoctl                  0x8ee5c
payload0 performCommand                          0x9576e
payload0 getPrimarySkywalkInterface              0x91b62
```

## 附录 C：复现命令

```bash
PY=/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3
OBJ=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump
$PY /tmp/sb27/kcdis.py com.apple.iokit.IO80211Family /tmp/sb27/IO80211Family27.macho
$OBJ -d --arch=x86_64 --no-show-raw-insn \
     --start-address=0xffffff8001f70c3a --stop-address=0xffffff8001f70c9a \
     /tmp/sb27/IO80211Family27.macho
$PY /tmp/sb27/dis27.py 0xffffff8002074e1d 0xffffff8002075020   # 内部分发器 + 符号注释
```
