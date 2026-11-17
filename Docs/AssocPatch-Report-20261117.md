# 关联补丁工作区报告（macOS 27 / Golden Gate，2026-11-17）

- 仓库：`simplebcm-r27`
- 分支/HEAD：`wifi-assoc-probe` / `93df845`
- 范围：复核 A1/A2/A3；补齐 B1/B2（0x290 识别 + 转换，受 `-sbcmggassoc` 控制，默认关闭）；
  确认 `Tools/profiles.py` 的符号/route 注册；本地静态与编解码验证。
- 边界：**未 commit、未 push、未部署、未重启**；未修改 `/System`、`/Library`、EFI；
  未运行完整 Xcode 构建，未重新生成 payload。
- 工作区 patch：`/tmp/sbcm-assoc.patch`（`git diff`，仅已跟踪文件；未跟踪的 Docs 不包含在内；
  518 行，sha256 `250724f99c19142a297fdb01b86901dd20427af6fd1bab2ad8defd0eb2a0a8e9`）。

## 1. 改了什么

### A1：持久关联诊断（已实现）

- `Bridge.hpp::Counters`：`associateLengthMismatch`、`lastAssociateLength`、16 条 Set 历史
  （`setHistory/SetLength/SetResult`、`lastSetType/Length/Result`）。
- `UserClient.cpp::runCommand`：在长度/接口门禁之前记录 `associationRequests`、`lastAssociateLength`；
  所有 set 请求写 Set 历史，`done:` 回填结果。
- `Bridge.cpp::publish`：发布 `LastAssociateLength`、`AssociateLengthMismatch`、`SetCount`、
  `LastSetType/Length/Result`、`SetHist*/SetLen*/SetRes*`。
- 语义修正：`AssociateLengthMismatch` 现在统计**所有** `header->length != abi.associateSize`
  的 set+20，包含 27 的 0x290；0x290 另由 `GoldenGateAssociateRequests` 单独计数。
  这与 PatchDraft A1 的验收树一致（`AssociationRequests>0 && AssociateLengthMismatch>0`）。

### A2：内嵌驱动 `AirPort_BrcmNIC::setASSOCIATE` 入口计数（已实现，运行期需重新生成 payload）

- `Bridge.cpp`：新增 `countSetAssociate`，统计 `driverAssociateRequests` 与
  `lastDriverAssociateWord`，然后透传原函数；`setASSOCIATE` 作为**可选 route** 安装，
  失败只 `clearError()`，不 disable bridge；发布 `DriverAssociateRequests`、
  `DriverAssociateHookReady`、`LastDriverAssociateWord`。
- `Tools/profiles.py`：符号加入 `SYMBOLS["AirPort"]`（named/`findSymbol`）和
  `ROUTE_SYMBOLS["AirPort"]`（既有 route 14/15 字节，setASSOCIATE 为 20 字节 prefix）。
- 当前已部署产物没有该 route descriptor，所以 `DriverAssociateHookReady=0`；
  重新 bootstrap/embed 生成 payload 后才会变为 1。

### A3：事件 9 的 endpoint kind 观测（已实现，仅记录）

- `PendingEvent` 增加 `InterfaceKind kind`，`queueEvent` 写入并按 Classic/Virtual/Skywalk 计数；
  发布 `LastAssociationEventKind`、`AssociationEventsClassic/Virtual/Skywalk`。
- 没有改 `captureJoinEvent` 的转换条件（仍只对 Classic + 空 payload 合成 join status）。

### B1/B2：27 的 0x290 关联转换（已实现，默认关闭）

- `WirelessABI.hpp`：
  - `GoldenGateAssociateSize=0x290`、`GoldenGateNativeAssociateSize=0x38C`、
    `GoldenGateAssociateGap=0x1FC`、gap 宽度 4；
  - 27 侧校验偏移常量：ssid 0x10、rsn 0xD0、pmk 0x1D8、bssidCount 0x202、scope 0x240；
  - `prepareAssociateGoldenGate(request, buffer, capacity, abi, convert)`：
    长度/capacity/ABI 门禁 → 五个 27 校验点 → `convert=false` 直接拒绝且不改缓冲 →
    在 0x1FC 插入 4 字节 gap 还原 0x38C → 复用 `prepareAssociate` → 写回 0x224 并清零尾部；
  - 编译期断言保证 gap 还原、样本窗口、五个偏移都在 0x290/0x38C 内。
- `UserClient.cpp`：
  - `goldenGateAssociate = set && type==20 && abi.kernel==27 && header->length==0x290`；
  - 长度门禁对 0x290 放行到 `prepareAssociateGoldenGate`，其他长度仍按 `abi.associateSize` 拒绝；
  - 转换前记录 32 个 word（0x1D8..0x257，覆盖 pmkLength、PMK、gap、bssidCount、scope），
    发布为 `GoldenGateWord0..31`；另发布 `LastGoldenGateBssidCount`/`LastGoldenGateScope`；
  - `-sbcmggassoc` 关闭时 `prepareAssociateGoldenGate` 返回 false，`goto done`，
    结果为 `kIOReturnBadArgument`，缓冲不被修改。
- `Bridge.cpp`：`initialize()` 读取 `-sbcmggassoc`；`Bridge::goldenGateAssociateEnabled()` 供
  UserClient 查询；默认 false。
- `Tools/verify.py`：新增 0x290 向量（从 0x38C 向量删除 gap 构造 0x290）：
  默认关闭不改缓冲、长度/capacity 拒绝、gap 还原后与 `prepareAssociate` 参考输出一致、
  0x224 后清零、守卫字节不变、ssid/rsn/pmk/bssid/scope 越界拒绝。

### 文档

- `Docs/PatchDraft-Assoc-20261117.md` 的实施状态/B2 小节已同步为当前实现；
  本报告是独立的状态与验证记录。

## 2. 验证命令与结果

| 命令 | 结果 |
| --- | --- |
| `clang++ -std=c++14 -fsyntax-only -target x86_64-apple-macosx12.0 -mkernel -I SimpleBCM -I <MacKernelSDK>/Headers SimpleBCM/UserClient.cpp` | exit 0；3 条既有 warning（shorten-64-to-32 / sign-conversion），无新增 |
| 同上，`SimpleBCM/Bridge.cpp` | exit 0；3 条既有 warning，无新增 |
| `python3 -B -m py_compile Tools/profiles.py Tools/verify.py` | exit 0 |
| `python3 -B Tools/check.py` | `Source metadata, native configuration and version checks passed.` |
| `python3 -B Tools/native_references.py verify` | `Native ABI references verified: Sonoma, Sequoia, Tahoe, GoldenGate` |
| HOST ABI harness（`Tools/verify.py` 的 `HOST_SOURCE`，本机去 ASan 编译后运行） | exit 0；`associationConversions=18`（含新增 0x290 向量） |
| 同上，`-fsanitize=undefined` | exit 0，无 UBSan 报告 |
| `python3 Tools/macho.py .research/extract/payload1.bin --symbols setASSOCIATE` | `0x42b8e __ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data` |
| `python3 Tools/macho.py .research/extract/payload0.bin --symbols setASSOCIATE` | 无输出（Legacy payload 不含 AirPort 符号，符合预期） |
| 用 `embed.py::route_prefixes` 算法检查 payload1 | setASSOCIATE prefix = 20 字节，14..32 内且无 `%rip`/跳转；既有两个 route 14/15 字节 |
| 93a2f82 旧 artifact 的 payload1（AirPortOriginal）+ payload2 delta 还原（AirPort） | 两个 backend 的 `setASSOCIATE` 都在 0x42b8e，prefix 都是 20 字节 |
| `python3 -B Tools/verify.py`（带 ASan，原样） | **环境失败**：`a2x-stop ... SIGABRT`，ASan runtime 在 a2x 下无法启动；不是测试断言失败 |

MacKernelSDK：仓库 `.research/MacKernelSDK` 不存在；本机找到两份同 pinned commit
`3f750085caa17ec3a7880f11c11bf4f48cd6a164` 的副本，验证使用
`/Users/geek/Documents/Macintosh/cpufriend-r27/MacKernelSDK/Headers`。

Python：本机 `/usr/bin/python3` 是 arm64-only CLT framework，a2x 下
`posix_spawn ... Undefined error: 0`；以上 Python 命令使用
`/Users/geek/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3`（x86_64）。

## 3. 没验证 / 剩余风险

1. **真实 0x290 样本尚未取得**。当前实测 `AssociationRequests=0`，所以 B 的目标准确性
   （0x290 的完整字段布局、wifid 是否真的按 0x290 填 `header->length`）没有运行期证据。
   转换默认关闭，必须先用 A1/A2 拿到样本。
2. **gap 位置（0x1FC）仍是假设**，来自 27 legacy handler 的 0x202/0x240 校验点；
   0x1FC 与 0x1DC 目前无法静态区分。转换里 gap 4 字节填 0；若真实 27 结构删除的 4 字节
   在旧 legacy 结构里不是零语义，转换会得到错误字段。
3. **A2 在当前部署产物上不生效**（`DriverAssociateHookReady=0`）：route descriptor 需要在
   bootstrap 后重新生成 payload；`Tools/profiles.py` 已加入符号，但本次没有运行
   `Tools/embed.py`。
4. **27 legacy ifnet ioctl 路径绕过 BCM80211UserClient**；B 只覆盖用户客户端路径。
   若 A2 显示 `DriverAssociateRequests>0 && AssociationRequests=0`，需要在控制器/驱动边界处理，
   而不是只改用户客户端。
5. `SimpleBCM/Profiles.hpp`、`Docs/ABI.json` 是已提交的生成物，本次没有重新生成
   （缺 `.research/binaries`）。A2 的 `findSymbol`/route 来自 `SYMBOLS`/`ROUTE_SYMBOLS`，
   不依赖这两个文件；但 setASSOCIATE 的 ByteGuard 要等
   `python3 -B Tools/profiles.py` 重新生成后才存在。
6. 本机没有完整 Xcode（`xcodebuild` 不可用），没有跑 `Tools/build.py`、
   `Tools/embed.py`、ASan/UBSan 全量 build harness；CI 的 `macos-26-intel` 才会覆盖。
7. `-sbcmggassoc` 只是转换开关，不会让 27 用户态自动发送 type 20；它只在请求到达用户客户端后
   改变 0x290 的处理方式。

## 4. CI 构建需要哪些步骤

`.github/workflows/build.yml`（GitHub Actions）：

- 触发：`push`（所有分支）、`pull_request`、`release: published`、`workflow_dispatch`。
- build job（`macos-26-intel`）：checkout → choose channel → Show toolchain →
  `python3 Tools/check.py` → `python3 Tools/native_references.py verify` →
  `python3 Tools/bootstrap.py`（拉取 pinned MacKernelSDK/OCLP 驱动）→
  `python3 Tools/build.py build --configuration Debug` → Release →
  `python3 Tools/build.py analyze --configuration Release` → package Debug/Release →
  upload artifacts。
- publish job：`push` 或 `release` 时运行 `python3 Tools/publish.py --channel ...`，
  **push 会更新 alpha release**；本次未 push，所以不会触发。
- 维护者本地完整验证（需要完整 Xcode）：

  ```sh
  python3 -B Tools/bootstrap.py
  python3 -B Tools/check.py
  python3 -B Tools/build.py build --configuration Debug
  python3 -B Tools/build.py build --configuration Release
  python3 -B Tools/build.py analyze --configuration Release
  python3 -B Tools/build.py package --configuration Debug --channel pre
  python3 -B Tools/build.py package --configuration Release --channel pre
  ```

- 重新生成 payload/Profiles（A2 生效、ByteGuard 更新所需）：

  ```sh
  python3 -B Tools/profiles.py
  # build.py/embed.py 在 Xcode build phase 中重新生成 payload
  ```

## 5. 产物

- `/tmp/sbcm-assoc.patch`：`git diff` 全文（已跟踪的 `SimpleBCM/*`、`Tools/profiles.py`、
  `Tools/verify.py`）。
- 未跟踪的 `Docs/*-20261117.md`（含本报告）不在 `git diff` 中；需要随分支一起 `git add` 才会进入提交。
