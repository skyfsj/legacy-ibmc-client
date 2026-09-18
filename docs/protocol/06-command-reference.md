# 06 — 命令速查表

## 1. 客户端 → BMC（KVM 通道）

命令码 = payload 第 1 字节。构建函数都在 `PackData.java`。

| 码 | 十进制 | 常量 | payload | 方法 | 备注 |
|---|---|---|---|---|---|
| `0x03` | 3 | `KEY_PACK` | `{3, blade, <8 或 16 字节>}` | `keyPressedPack` 等 | 见 04 章 |
| `0x04` | 4 | `KEY_STATE` | `{4, blade, 1}` | `keyBoardState` | 查询锁定灯 |
| `0x05` | 5 | `MOUSE_PACK` | `{5, blade, …}` | `mousePack` / `mousePackNew` / `mousePackNew_abs` | 见 04 章 |
| `0x06` | 6 | `CONNECT_BLADE` | `{6, blade, colorBit, 1, 1}` | `connectBlade` | 走**加密帧**格式 |
| `0x07` | 7 | `INTERRUPT_BLADE` | `{7, blade}` 或 `{7, blade, 1, 1}` | `interruptBlade` | 断开 |
| `0x08` | 8 | `I_REQ` | `{8, blade}` | `resendData` | **请求重发 I 帧** |
| `0x09` | 9 | `HEART_BEAT` | `{9, 0}` 或 `{9, blade}` | `heartBeat` | |
| `0x0B` | 11 | `REQ_BLADE_PRESENT` | `{11}` | `reqBladePresent` | 查询刀片在位 |
| `0x14` | 20 | `REQ_BLADE_STATE` | `{20, blade}` | `reqBladeState` | `connMode==1` 时用 `0x21` |
| `0x17` | 23 | `REQ_BLADE_MONITOR` | `{23, blade, 1}` | `monitorBlade` | |
| `0x18` | 24 | `INTERRUPT_MONITOR` | `{24, blade, 1}` | `interruptMonitor` | |
| `0x19` | 25 | `DELETE_USER` | `{25}` | `deleteUser` | ⚠️ 注销用户 |
| `0x1A` | 26 | `REPLAY_SMM` | `{26, blade, number}` | `replayToSMM` | 收到 `0x02`/`0x04` 时回 |
| `0x1B` | 27 | `COLOR_BIT` | `{27, blade, colorBit}` | `setColorBit` | **无调用者（死代码）** |
| `0x1C` | 28 | `FRAME_COMM` | `{28, frameNum}` | `contrRate` | 帧率，实测发 35 |
| `0x1E` | 30 | `RETRY_CONN` | `{30}` | `retryConn` | |
| `0x20` | 32 | `KVM_CMD_POWEROFF` | `{32, 0}` | `kvmCmdPowerControl` | ⚠️ 写操作 |
| `0x21` | 33 | `KVM_CMD_POWERON` | `{33, 0}` | 同上 | ⚠️ 写操作 |
| `0x22` | 34 | `KVM_CMD_RESTART` | `{34, 0}` | 同上 | ⚠️ 写操作 |
| `0x23` | 35 | `KVM_CMD_SAFETY_RESTART` | `{35, 0}` | 同上 | ⚠️ 写操作 |
| `0x25` | 37 | `KVM_CMD_SAVE_POWEROFF` | `{37, 0}` | 同上 | ⚠️ 写操作 |
| `0x24` | 36 | `MOUSE_MODE_SET` | `{36, 0, mode, 0, 0}` | `mouseModeControl` | 第 2 字节恒 0 |
| `0x27` | 39 | `DQT_MODE_SET` | `{39, 0, mode, type, 0}` | `DQTModeControl` | 第 2 字节恒 0 |
| `0x30` | 48 | `KVM_CMD_USBRESET` | — | `USBResetAction` | 复位远端 USB |
| `0x31` | 49 | `REQ_VMM_CODEKEY` | `{49, blade}` | `reqVMCodeKey` | VMM 引导 |
| `0x33` | 51 | `KVM_CMD_SECURITY` | `{51, 0, <AES 16 字节>}` | `kvmCmdPowerControl` | **compress=1 时的开关机载体** |
| `0x35` | 53 | `REQ_VMM_PORT` | `{53, blade}` | `reqVMPort` | VMM 引导 |
| `0x40` | 64 | 打开视频 | `{64, 0}` | `kvmCmdvideoControl` | |
| `0x41` | 65 | 关闭视频 | `{65, 0}` | `kvmCmdvideounControl` | |
| `0x42` | 66 | `GET_SUITE` | `{66, blade}` | `getSuiteList` | |
| `0x44` | 68 | `SET_SUITE` | `{68, blade, hmac, iter(4B)}` | `setSuitePack` | |

> **开关机在 `compress=1` 时要走 `0x33`**（`PackData.java:715-732`）：
> ```java
> byte[] cmd_data = new byte[16];
> cmd_data[15] = cmd;                                    // 真正的命令码放在第 16 字节
> temDes = AESHandler.kvm_encry(cmd_data, Base.getKvm_key(), 16);
> data[0] = 51; data[1] = 0;
> System.arraycopy(temDes, 0, data, 2, 16);
> ```
> 即实际命令（32/33/34/35/37）被 AES 加密后塞进 `0x33` 的 payload。

---

## 2. BMC → 客户端（KVM 通道）

命令码 = payload 第 3 字节（`payload[2]`），`payload[3]` = 刀片号。

| 码 | 十进制 | 常量 | 解析出的结构 | 处理函数 |
|---|---|---|---|---|
| `0x01` | 1 | `PRESENT_BLADE` | `{1, p3, p4}` | `ClientSocketCommunity` |
| `0x02` | 2 | `IMAGE_DATA` | `{2, p3…}` | `DrawThread`（见 03 章） |
| `0x04` | 4 | `KEY_STATE` | `{4, p3, p4}` | `distributeKeyStateData` |
| `0x08` | 8 | `CONNECT_STATE` | `{8, p3, p4}` → `p4` = 状态 | `distributeConnectStateData` |
| `0x15` | 21 | `BLADE_STATE` | 变长 | `reportBladeState` |
| `0x1D` | 29 | `CHANNEL_SWITCH` | `{29, p3}` | `switchChannel` |
| `0x21` | 33 | `RAPCONNECT_BLADE` | `{33, p3}` | `rapCloseBlade` |
| `0x25` | 37 | `MOUSE_MODE` | `{37, p3, p4}` → `p4` = 模式 | `distributeMouseModeData` |
| `0x28` | 40 | `DQT_MODE` | `{40, p3, p4}` | `distributeDQTModeData` |
| `0x32` | 50 | `VMM_CODEKEY_REPORT` | `{50, p3, <20B key><16B salt>}` | `distributeNegotiVMMCodeKey` |
| `0x36` | 54 | `VMM_PORT_REPORT` | `{54, p3, <2B 端口，小端>}` | `distributeVMMPort` |
| `0x40` | 64 | `KVM_KEY_SET` | `{64, p3, <48 或 128 字节密文>}` | `distributeKVMSetKey` |
| `0x43` | 67 | `KVM_SUITE_LIST` | `{43, p3, count, (algo+iter)×count}` | `distributeConsultation` |
| `0x51` | 81 | `NOT_PRI` | `{81, p3, p4}` | `distributeNoVMMPri` |

**注意** `UnPackData.setkvmType` 的分派用的是 `data[2]`，
而 `getData()` 返回的数组里 `[0]` 是**重新编号后的命令码**。映射关系
（`UnPackData.java:28-88`）：

| 线上命令 | 内部 kvmType 字符串 | 说明 |
|---|---|---|
| `0x01` | `"1"` | |
| `0x02` | `"2"` | |
| `0x04` | `"4"` | |
| `0x15` | `"21"` | |
| `0x1D` | `"29"` | |
| `0x21` | `"33"` | |
| `0x08` | `"8"` | |
| `0x25` | `"25"` | 注意：线上是 37 |
| `0x28` | `"28"` | 注意：线上是 40 |
| `0x40` | `"40"` | |
| `0x32` | `"50"` | |
| `0x43` | `"43"` | |
| `0x51` | `"51"` | |
| `0x36` | `"54"` | |

`getData()` 返回的数组以**实际命令码**作为 `[0]`，
而 `BladeThread.run` 的 `switch (unPackData[0])` 用的就是它。
所以 `BladeThread` 的 case 值是 2/4/8/37/40/50/54/64/67/81 —— **与线上码一致**。

---

## 3. 实测抓包样本（2026-09-18，设备 192.168.1.100）

### 3.1 客户端 → BMC

```
HEART_BEAT(0x09)    fe f6 0004 6c713278 ba98 09 00
GET_SUITE(0x42)     fe f6 0004 6c713278 6bae 42 00
SET_SUITE(0x44)     fe f6 0009 6c713278 7fb8 44 00 03 00002710
CONNECT_BLADE       fe f6 8007 <24B encodeKey> 80f5 06 00 02 01 01
MOUSE_MODE_SET      fe f6 0007 6c713278 efd2 24 00 02 00 00
```

逐字段拆解（心跳）：

| 字节 | 值 | 含义 |
|---|---|---|
| 0-1 | `fe f6` | 魔数 |
| 2-3 | `00 04` | 长度 = payload(2) + 2 = 4 |
| 4-7 | `6c 71 32 78` | codeKey = `1000000002` 大端 |
| 8-9 | `ba 98` | CRC-16/CCITT-FALSE over `09 00` |
| 10-11 | `09 00` | payload：心跳，刀片 0 |

`CONNECT_BLADE` 拆解：

| 字节 | 值 | 含义 |
|---|---|---|
| 2-3 | `80 07` | `length = 0x8000 \| 5`，+2 = `0x8007`；`0x8000` 表示带 24 字节密钥头 |
| 4-27 | 24 字节 | `encodeKey`（PBKDF2-SHA256/10000 派生 + 4 字节组反序） |
| 28-29 | 2 字节 | CRC-16 over payload |
| 30-34 | `06 00 02 01 01` | `CONNECT_BLADE, blade=0, colorBit=2, 1, 1` |

### 3.2 BMC → 客户端（成功会话）

```
套件表(0x43)   00 00 43 00 03 01 00001388 02 00002710 03 00002710
连接状态(0x08) 00 00 08 00 00 00 00 00        ← 状态 0 = 接受
KVM_KEY_SET    00 00 40 00 <48B AES 密文>     ← dlen=52
KVM_KEY_SET    00 00 40 00 <128B AES 密文>    ← dlen=132（重连密钥，连发第二个）
DQT_MODE(0x28) 00 00 28 00 46 00 00 00        ← payload[4]=0x46=70 → 画质 70
MOUSE_MODE     00 00 25 02 01 00 00 00        ← payload[4]=1 → 同步/绝对模式
KEY_STATE(0x04)00 00 04 00 01 00 00 00
IMAGE_DATA     00 00 02 00 00 00 02 00 00 14 08 03 20 02 58 dc ff ff ff ff 07
```

`0x43` 拆解（dlen = 20）：

| 偏移 | 值 | 含义 |
|---|---|---|
| 0-1 | `00 00` | 恒为 0，**不是 CRC**（已证伪，见 01 章 §2.3） |
| 2 | `43` | `KVM_SUITE_LIST` |
| 3 | `00` | 刀片号 |
| 4 | `03` | 套件数量 = 3 |
| 5-9 | `01 00 00 13 88` | algo 1，迭代 5000 |
| 10-14 | `02 00 00 27 10` | algo 2，迭代 10000 |
| 15-19 | `03 00 00 27 10` | algo 3，迭代 10000 |

长度自校验：`count*5 + 3 = 18 = dlen - 2 = 20 - 2` ✅

**`0x08` 与拒绝情形对比：**

| 情形 | payload[4] | 结果 |
|---|---|---|
| 新 JNLP 首次连接 | `00` | 接受，视频正常 ✅ |
| 同一 JNLP 二次连接 / 旧 JNLP | `03` | `str_errorname`，立即断链 ❌ |

> **JNLP 会话是一次性的**：断开后再连必被拒，必须重新下载 JNLP。
> 见 [07-live-verification.md](07-live-verification.md)。

`IMAGE_DATA` 帧头子包拆解（dlen = 21，800×600、I 帧、DQT 7）：

| payload 偏移 | 值 | 含义 |
|---|---|---|
| 0-1 | `00 00` | 恒 0 |
| 2 | `02` | `IMAGE_DATA` |
| 3 | `00` | — |
| 4-5 | `00 00` | 子包序号 = 0（帧头包） |
| 6 | `02` | 帧号 = 2 |
| 7-10 | `00 00 14 08` | `packLenght` = 5128（大端，只含序号≥1 的子包） |
| 11 | `03` | bit7=0（非差分）；bit6..0 = 宽度高 7 位 |
| 12 | `20` | 宽度低 8 位 → **宽 = 0x320 = 800** |
| 13-14 | `02 58` | **高 = 600** |
| 15 | `dc` | 恒 220（= 子包数据上限）⚠️ 语义未定论 |
| 16-17 | `ff ff` | remoteX（光标隐藏） |
| 18-19 | `ff ff` | remoteY |
| 20 | `07` | bit7=0（非 I 帧）；低 4 位=7 → DQT 档 7（画质 70） |

---

## 4. 常量汇总

| 名称 | 值 | 出处 |
|---|---|---|
| 帧魔数 | `FE F6` | `PackData.PACKHEAD1/2` |
| 接收帧魔数 | `FE F6 00` | `KVMUtil.diviStreamNew` 的 `16709120` |
| 接收帧最大 dlen | 250 | `KVMUtil.java:954` |
| 接收帧最小 dlen | 3 | 同上 |
| 子包数据上限 | **220**（实测帧头 `buf[11]` 恒为 `0xDC`） | `KVMUtil.java:538` 的 `packLenght / 220 + 1` |
| 视频块尺寸 | 64 × 64 | `ImageDecoder.blockImageWidth/Height` |
| 800×600 的块数 | 13 × 10 = 130 | `ceil(w/64) × ceil(h/64)`，实测吻合 |
| 合成 JPEG 头里的宽高 | 固定 `0x40 × 0x40` | `JPEGData.HEAD_SYN_SOF_444` |
| JPEG 采样方式 | **4:4:4**（`HEAD_SYN_SOF_444`；`_420` 未使用） | 同上 |
| JPEG 重启间隔 DRI | 100 | `HEAD_SYN_SOF_SOS` 里的 `FF DD 00 04 00 64` |
| DQT 档数 | 10 | `DQTZData.HEAD_SYN_DQT_*_S` |
| **DQT 默认档** | **70（索引 6 → `_70`）**，实测 BMC 主动报 `0x28 → 0x46` | `Base.currentDqtSize = 7` → `dqttags = 6` |
| 鼠标归一化坐标上限 | 3000 | `PackData.java:349-350` |
| 鼠标相对位移限幅 | ±120 像素/包 | `ImagePane.java:1085-1140` |
| 远端光标隐藏哨兵 | `remoteX/Y = 0xFFFF` | 实测帧头 |
| VMM 帧头长度 | 12 | `ProtocolCode.PACKET_HEAD_SIZE` |
| VMM 认证证明长度 | 24 | `ProtocolCode.SECRET_CERTIFYID_SIZE` |
| VMM 光驱分片 | 32768 | `vmconfigResource.properties` |
| VMM 软驱分片 | 4096 | 同上 |
| VMM 心跳周期 | 10000ms | 同上 |
| VMM 断链阈值 | 40000ms | `VMTimerTask` |
| VMM 版本串 | `3.01.01.01` | 同上 |
| 客户端 KVM 版本串 | `1.1.0` / `2.20.5.52`（回退） | `ResourceUtil.java:87` |
| INQUIRY 标识 | `"Virtual FLOPPY VM 1.1.0     "`（尾部 5 个空格） | `UFIProcessor.java:19` |
| INQUIRY 标识 | `"Virtual DVD-ROM VM 1.1.0 225"` | `SFF8020iProcessor.java:25` |
| `kvm_key` 分段 | `[0:16]` 数据密钥、`[16:32]` 键盘密钥、`[32:48]` IV | `AESHandler.java:57-141` |

---

## 4.1 关于电源状态（实测结论）

**本协议不提供电源状态上报。** 依据：

- 厂商客户端所有电源动作（`PowerOnAction` / `PowerOffAction` / `RestartAction` …）
  的 `actionPerformed` 只有两步：弹确认框 → `kvmCmdPowerControl(cmd)`，**没有任何状态检查**
- `PowerPanel` 中不存在 `setEnabled` 之类的状态逻辑
- 全代码库检索 `powerState` / `isPowerOn` / `PowerStatus` / `power_status` **无任何命中**

被误认为「电源状态」的 `BLADE_STATE(0x15)`，其解析结果（`BladeState`）只含
`bladeIP` / `bladePort` / `enable` / `isNew` —— `enable` 表示**该刀片是否可连接**，
不是电源状态。

所以电源按钮只能始终可用、发完即返回；**想知道真实电源状态需要走 Redfish**
（本机型暴露 Redfish 1.0.2，`/redfish/v1/Systems/1` 的 `PowerState`），
那是在本协议之外新增的查询，不属于复刻范围。

## 5. 与既有开源实现的对照

| 方案 | 能否用 | 原因 |
|---|---|---|
| VNC / noVNC | ❌ | 完全不同的私有协议 |
| RDP | ❌ | 同上 |
| IPMI SOL | ❌ | 只有串口，无图形 |
| Redfish 虚拟控制台 | ⚠️ | Redfish 1.0.2 可访问，但只提供**启动 JNLP 的入口**，图形仍走本协议 |
| `javaws` / OpenWebStart | ⚠️ | 能拉起 applet，但旧 JAR 在新 JDK 上会在 `DrawThread` 抛数组越界，**不可靠** |
| 自己实现原生客户端 | ✅ | 本文档即为此准备 |

> 目标设备的 Redfish 版本是 1.0.2（较老），
> 未认证时无法确认图形控制台能力。
