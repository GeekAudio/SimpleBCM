# 首次实机验证：macOS 27.2（Golden Gate）

日期：2026-11-16
系统：macOS 27.2（26B123，Darwin 27.2.0，x86_64）
硬件：Broadcom BCM43602（`pci14e4,43ba`）
部署：SimpleBCM 1.2.1 RELEASE，`config27-sbcm.plist`（MinKernel/MaxKernel 留空）
状态：**首次实机，扫描失败；内核侧通过，用户态请求被拒**

## 结果摘要

改造版在 Darwin 27 上成功加载并通过内核 ABI 校验，但 IO80211 用户客户端请求全部返回
`kIOReturnBadArgument (0xe00002c2)`，扫描流程未启动。

| 层 | 实测 | 判定 |
| --- | --- | --- |
| PCI / 硬件 | BCM43602 枚举正常，Link up，Driver Installed: Yes | 正常 |
| 驱动对象 | `AirPort_BrcmNIC`、en1、P2P、LLSkywalkInterface 均 active | 正常 |
| 注入 | `cn.laobamac.SimpleBCM 1.2.1` 已加载 | 正常 |
| 内核 ABI | `ActiveABI=GoldenGate`、`NativeABIValidated=Yes`、`LoaderError=0` | 通过 |
| Loader | `Status=StartedAwaitingHardware` | 预期状态，非故障 |
| 用户态 | `Opens` 与 `CommandErrors` 同步增长；`LastRequest=12`、`LastResult=0xe00002c2` | 异常 |
| 事件 | `ScanRecords`/`ScanDoneEvents`/`DriverAvailabilityEvents` 全 0 | 异常 |
| 探针 | `bcmprobe --scan`：`scanCompleted=false`，NSCocoaErrorDomain 4097 | 复现 |

`CommandErrors == Opens`、`Commands == 2 × Opens`、`Selector0 == Commands` 表明 wifid
每次打开用户客户端后立即查询卡能力，被拒后关闭重试。

## 候选根因（未定案）

`WirelessABI.hpp` 中 `GoldenGateABI` 直接沿用 Tahoe 的用户态结构尺寸
（`scanResultSize 0x8E0`、`capabilitySize 21`、`associateSize 0x38C`、
`joinStatusSize 0x1D4`、`filterMonitorEvents 0x234`、`selectorCount 9`）。

`UserClient.cpp` 的 `runCommand()` 在 `outputSize` 与 `abi.capabilitySize` 不符时
`goto done`，带着默认 `kIOReturnBadArgument` 返回；实测 `LastRequest=12`
（CardCapabilitiesRequest）与该路径吻合。

27.2 的 `IO80211Family.__text` 中这些尺寸常量的精确 cmp 立即数命中数为 0，
说明无法从内核二进制直接验证，与改造报告第六节「尚未验证」一致。

并列未排除：`DriverAvailabilityEvents=0`，0x37 驱动可用事件从未送达用户态，
可能与 Golden Gate Skywalk Ethernet 槽位后移 5 有关。

## 复现与取证

```sh
# 结构状态
ioreg -rn SimpleBCM -l | grep -E 'Status|ActiveABI|NativeABIValidated|LastRequest|LastResult|CommandErrors|Opens|ScanRecords|DriverAvailabilityEvents'

# 用户态扫描（只读）
./Extra/bcmprobe --scan

# 内核日志（DEBUG 构建）
sudo dmesg | grep -E 'SimpleBCM: (iouc|loader)'
```

`iouc` 日志会打印 `command / request / length / outputSize / result`，用于确定
具体失败分支与 wifid 实际传入的结构尺寸。

## 下一步

1. DEBUG 构建（`DEBUG=1` 已在 Xcode Debug 配置中定义）实机复现，抓 `iouc` 日志。
2. 按真实 `outputSize` 修正 `GoldenGateABI`，重建并跑 31 项 native ABI 校验。
3. 复验关联、扫描、睡眠唤醒、AWDL/AirDrop；验收以 `bcmprobe --scan` 返回非空
   SSID 且实际关联成功为准，不以编译/ABI 校验/kext 加载代替。

## 后续：根因确认（DEBUG 实机，2026-11-16 14:46）

DEBUG 版部署并重启后，`sudo dmesg` 抓到决定性一行：

```
SimpleBCM: iouc en1 command 0xc02869c9 request 12 length 23 output 23 result 0xe00002c2
```

- `0xc02869c9` = GetCommand，`request 12` = CardCapabilitiesRequest。
- **wifid 传入的 output 是 23 字节，而 `GoldenGateABI.capabilitySize` 是 Tahoe 的 21。**
- `UserClient::runCommand` 中 `outputSize == abi.capabilitySize` 不成立，走到
  `goto done`，带着默认 `kIOReturnBadArgument` 返回，因此每次打开客户端都失败。

同一份 dmesg 还显示 airportd 在发 `469/483/490/512/575/363` 等 IOCTL，全部
`not recognized: N out of 417`。417 是内嵌 **BrcmTahoe** payload 的 Apple80211
命令表上限（`AirPortSHA256 = 0b6cf936…`，见 `Tools/native_abi.py` 的 `BrcmTahoe`）；
27 的 airportd 新增命令超出该表。这一层是并列的第二障碍，先修 capability 尺寸
再观察扫描路径是否还需要命令表扩展。

修复：`WirelessABI.hpp` 的 `GoldenGateABI.capabilitySize` 由 21 改为 **23**，
`expandCapabilities` 会把底层驱动的 12 字节能力结构补齐到 23 并清零新增字节。


## 修复 2：scanResultSize 0x8E0 → 0x8E8

capability 修复（23）部署后，`LastResult` 变为 0，能力查询放行；新的 dmesg 显示：

```
request 11 length 2280 output 2280 result 0xe00002c2   (10 次)
```

`request 11` = ScanResultRequest，2280 = **0x8E8**，而 `GoldenGateABI.scanResultSize`
仍是 Tahoe 的 0x8E0（2272）。`prepareScanResult` 要求入参长度等于
`abi.scanResultSize`，不匹配即 `goto done`，扫描结果永远读不出来。

修复：`scanResultSize` 改为 **0x8E8**；`expandScanResult` 会把底层驱动的
legacy 0x48C 结构补齐到 0x8E8，新增 8 字节清零。

同一份日志里仍有 `request 103`（2280，result 0x66）、`request 69`（15064，
result 0x16）以及 469/483/490/512/575/363 的 IOCTL 超界。先验证 request 11
是否成功，再判断这些是否需要单独处理。

## 修复 3：request 103 → 11 映射（实验）

`scanResultSize` 改为 0x8E8 后，`request 11` 成功 10 次（`ScanRecords=10`），
但 Wi-Fi 菜单仍无列表。dmesg 同时显示 27 的 airportd 在发：

```
request 103 length 2280 output 2280 result 0x00000066   (46 次)
```

`0x66` 是内嵌 Tahoe 驱动返回的“不支持”。103 与 11 同为 GetCommand、
同为 2280 字节输出，判断它是 27 的扫描结果新请求号。

处理：`UserClient::runCommand` 把 103 也纳入 scanResult 判定，转发给内嵌驱动前
把 `legacy.request.type` 改写回 11；`prepareScanResult` / `expandScanResult`
继续按 0x8E8 处理。若实验成功，菜单应出现扫描列表；失败则回滚该提交。

## 修复 3 回滚：103 不是 scanResult

公开枚举（itlwm / MacKernelSDK，最大 353）里 `APPLE80211_IOC_CURRENT_NETWORK = 103`，
不是扫描结果；把 103 映射到 11 会让“当前网络”查询返回扫描结构，方向错误。
该映射已回滚。

## 修复 4：动态 probe 取证

静态反汇编 airportd（arm64e slice）确认：
- `469/363/483/490/575` 都是 `Apple80211Set` 的配置命令（WoW/参数字典），不是扫描入口；
- `Apple80211Set/Get` 的 72 个直接调用里没有 `10/86`（SCAN_REQ / SCAN_REQ_MULTIPLE），
  扫描调用使用了动态 cmd，静态抓不全。

因此在 `UserClient::runCommand` 增加 DEBUG 日志，记录 `request 11/69/103/207/15`
的 command、length、outputSize、header length 和前 8 字节，用于确定 27 的扫描
发起/结果读取路径与结构。日志仅在 Debug 构建（`DEBUG=1`）输出。

## 修复 5：probe 扩展（含 10/86 与返回值）

首轮 probe 显示所有请求都是 Get，没有 `10/86`（SCAN_REQ / SCAN_REQ_MULTIPLE），
说明扫描从未发起。probe 条件已加入 10/86，并在 `done:` 处额外打印
`result` 与输出 buffer 前 8 字节，用来确认：
- `req=15`（OP_MODE）返回的模式值；
- `req=103`（CURRENT_NETWORK）和 `req=11`（SCAN_RESULT）的错误码；
- 是否出现 `req=10/86` 的 Set 扫描请求。
