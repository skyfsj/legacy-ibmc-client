# 05 — 虚拟介质（VMM）通道

VMM = Virtual Media，把本地的 ISO / IMG / 物理光驱、软驱挂到远端服务器上。
它是一个**独立 TCP 通道**（JNLP `vmmPort`，本机型 `8208`），由 KVM 通道引导。

代码主要在 `com/huawei/vm/console/**` 和 `com/kvm/VirtualMedia*.java`。

> 本章全部为源码分析（📖），**未做实网验证**。

---

## 1. 通道拓扑

| 通道 | 端口 | 帧格式 | 内容 |
|---|---|---|---|
| KVM | JNLP `port`（2198） | `FE F6 ...` + CRC-16 | 视频、键鼠、电源、**VMM 引导** |
| VMM | JNLP `vmmPort`（8208） | 12 字节定长头，**无魔数** | SCSI（UFI / SFF-8020i） |

`VirtualMedia.java:107` 硬编码默认 `private int port = 8208;`，
`VirtualMedia.java:714-733` 在 KVM 通道拿不到端口时报错并回退到 8208。

TCP 参数：`setTcpNoDelay(true)`，连接超时 20000ms（`VMConsole.java:645-668`）。

---

## 2. 帧格式（`ProtocolCode.PACKET_HEAD_SIZE = 12`）

`ProtocolProcessor.java:43-45` 每次都先读 12 字节头：

```java
this.curPakHead = new byte[12];
this.nextDataSize = 12;
```

**没有魔数**：`parsePak` 直接 `switch (packet[0] & 0xFF)`（`ProtocolProcessor.java:89`）。
这与 KVM 通道的 `FE F6` 形成鲜明对比。

### 2.1 头部布局

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 1 | **操作码**（见 §3） |
| 1 | 1 | 子类型 / 状态（各操作码含义不同） |
| 2 | 1 | ACK 码 / 关闭原因 / 打印级别（多数客户端→BMC 帧为 0） |
| 3 | 1 | 事务 ID（UFI/SFF 用，BMC 原样回送） |
| 4 | 4 | **payload 长度，大端 u32** |
| 8 | 4 | 版本号（仅 `CERTIFY_ID`）或 `00 00 00 00` |
| 12 | N | payload（仅 `CERTIFY_ID` 和 UFI/SFF DATA 有） |

所有多字节字段都是**大端**。`ProtocolCode.getInt32bits(b, 5)` 返回
`b[4]<<24 | b[5]<<16 | b[6]<<8 | b[7]`（位置参数是 1-based）。

12 字节这个尺寸被独立佐证：缓冲区池 `DataElement.getComPakInstance` /
`getUSBRequestInstance` 都要求 `12 == pakLength`（`DataElement.java:17-34`），
`DataArray.smallArrSize = 12`。

### 2.2 各操作码的具体帧

**客户端 → BMC**

| 帧 | b0 | b1 | b2 | b3 | b4..7 | b8..11 | 总长 |
|---|---|---|---|---|---|---|---|
| `CERTIFY_ID` | `01` | 00 | 00 | 00 | `00 00 00 1D`（29） | 版本 `03 01 01 01` | **41** |
| `DEVICE_TYPE` | `02` | 设备类型 `01`/`02` | 00 | 00 | 00… | 00… | **12** |
| UFI/SFF DATA | `03`/`04` | `(state<<4)\|1` | 00 | ID | payload 长度 | 00… | **12+N** |
| UFI/SFF 完成 | `FE`/`FF` | 结果 `00`/`01` | 00 | ID | 00… | 00… | **12** |
| `HEARTBIT` | `06` | 00 | 00 | 00 | 00… | 00… | **12** |
| `CLOSE_VM` | `05` | `设备类型 & 3` | 原因 | 00 | 00… | 00… | **12** |

**BMC → 客户端**

| 帧 | b0 | b1 | b2 | b4..7 | 总长 |
|---|---|---|---|---|---|
| ACK | `00` | — | **ACK 码** | — | **12** |
| UFI/SFF CDB 或 DATA | `03`/`04` | `(cont<<4)\|(0=CDB,1=data)` | 00 | payload 长度 | **12+N** |
| `CLOSE_VM` | `05` | `(类型<<4)` | 原因 | — | **12** |
| `SHUTDOWN` | `07` | — | 原因 | — | **12** |
| 打印级别控制 | `F0` | — | 级别 | — | **12** |

> ⚠️ **注意收发不对称**：`CLOSE_VM` 的客户端构建器把设备类型写在**低 2 位**
> （`ProtocolProcessor.java:280`：`pack[1] = (byte)(deviceType & 3);`），
> 而接收解析读的是**高 4 位**（`ProtocolProcessor.java:95-99`：
> `packet[1] >> 4 & 0xF`）。实现时必须两边分开处理。

### 2.3 子类型半字节（UFI/SFF）

```java
// ProtocolProcessor.java:170-173
private void parseTransField(byte[] packet) {
    this.isDataContinue = 1 == (packet[1] >> 4 & 0xF);
    this.nextDataSize   = ProtocolCode.getInt32bits(packet, 5);
}
// ProtocolProcessor.java:113
this.dataType = 0 == (packet[1] & 0xF) ? 1 : 2;
```

- 高半字节 `1` = CONTINUE（后续还有数据），`3` = END（最后一个分片）
- 低半字节 `0` = COMMAND（12 字节 SCSI CDB），`1` = DATA

### 2.4 超时与心跳

- 读头用 `soTimeout = HEARTBIT_INTERVAL` = **10000ms**
- 读 payload 用 `BUSINESS_OVER_TIME` = **20000ms**（`ProtocolProcessor.java:33`）
- 客户端每 10s 发一次 `HEARTBIT`；若 **40s** 内既没收到任何包、
  也没发出过非心跳的 12 字节包，就 `errorProcess(0, 123)` 断链
  （`VMTimerTask.java:16-53`）
- ⚠️ 客户端自己的心跳**不会**重置该计时器，所以 BMC 必须在 40s 内主动发点东西
  （比如一个 `ACK(0)`），否则客户端会主动断链 —— 这点待实测确认
- 收包缓冲上限 = `CDROM_PACKET_SIZE + 12 + 20` = **32800 字节**（`DataArray.java:14`）

---

## 3. 操作码表（`ProtocolCode.java`）

Java `byte` 是有符号的，下表同时给出无符号十六进制。

### 3.1 命令码

| 常量 | Java | 无符号 | 含义 |
|---|---|---|---|
| `ACK` | 0 | `0x00` | BMC→客户端 应答 |
| `CERTIFY_ID` | 1 | `0x01` | 客户端→BMC 认证 |
| `DEVICE_TYPE` | 2 | `0x02` | 客户端→BMC 注册设备 |
| `UFI_DATA` | 3 | `0x03` | 软驱 SCSI 流量（双向） |
| `SFF_DATA` | 4 | `0x04` | 光驱 SFF-8020i 流量（双向） |
| `CLOSE_VM` | 5 | `0x05` | 关闭单个/全部设备 |
| `HEARTBIT` | 6 | `0x06` | 心跳 |
| `SHUTDOWN` | 7 | `0x07` | BMC→客户端 关机通知 |
| `CONSOLE_PRINT_CONTROLLER` | -16 | `0xF0` | 设置客户端打印级别 |
| `UFI_COMMAND_COMPLETE` | -2 | `0xFE` | UFI 命令完成 |
| `SFF_COMMAND_COMPLETE` | -1 | `0xFF` | SFF 命令完成 |
| `MIC_FILE_CMD` | -4 | `0xFC` | **声明但全代码库无引用** —— 遗留 |

### 3.2 ACK 码（`ACK` 帧的第 2 字节）

| 常量 | Java | 含义 |
|---|---|---|
| `ACK_CERTIFY_PASS` | 0 | 认证通过 → 接着发 `DEVICE_TYPE`（`VMConsole.java:316`） |
| `ACK_CERTIFY_ID_FAIL` | 1 | ⚠️ 仅知常量名：会话 ID / PBKDF2 不匹配 |
| `ACK_CERTIFY_VER_NOTSUP` | 2 | ⚠️ 仅知常量名：客户端版本不支持 |
| `ACK_DEVICE_CREAT` | 16 | 设备创建成功 → 进入 ACTIVE、启动心跳（`VMConsole.java:335-351`） |
| `ACK_DEVICE_FAIL_ENUM` | 17 | ⚠️ 仅知常量名：设备枚举失败 |
| `ACK_CLOSE_UPDATA` | 34 | ⚠️ 仅知常量名（`VMConsole.java:468,503,517` 里作为致命原因） |
| `ACK_CLOSE_IPCONFIG` | 35 | ⚠️ 仅知常量名 |
| `CN_EXIST` | 49 | 设备被其他用户占用 → `errorProcess(type, 401)`（`VMConsole.java:352-359`） |

### 3.3 子码与设备类型

| 常量 | 值 | 含义 |
|---|---|---|
| `UFI_SFF_DATA_COMMAND` | 0 | 低半字节 = 0 → 12 字节 CDB |
| `UFI_SFF_DATA_DATA` | 1 | 低半字节 = 1 → 数据 |
| `UFI_SFF_DATA_CONTINUE` | 1 | 高半字节 = 1 → 还有后续分片 |
| `UFI_SFF_DATA_END` | 3 | 高半字节 = 3 → 最后分片 |
| `UFI_SFF_CMD_OK` | 0 | 完成帧结果 = 成功 |
| `UFI_SFF_CMD_FAIL` | 1 | 完成帧结果 = 失败（含 sense key） |
| `DEVICE_TYPE_FLOPPY` | 1 | 软驱 |
| `DEVICE_TYPE_CDROM` | 2 | 光驱 |
| `CLOSE_VM_TYPE_LINK` | 0 | 关闭全部 |
| `CLOSE_VM_TYPE_FLOPPY` | 1 | 关闭软驱 |
| `CLOSE_VM_TYPE_CDROM` | 2 | 关闭光驱 |

---

## 4. 认证握手

### 4.1 状态机

`VMConsole.java:48-56`：
`CONSOLE_IDLE=0, CONSOLE_INIT=1, CONSOLE_CERTIFY=2, CONSOLE_DEVICE=3, CONSOLE_ACTIVE=4`，
`CERTIFY_TIMEOUT=10000`，`DEVICE_TIMEOUT=10000`。

```
TCP 连接（20s 超时）                            0 → 1
发送 CERTIFY_ID（41 字节）                      1 → 2   10s 看门狗 → error 121
  ← ACK(code=0 CERTIFY_PASS)                    2 → 3
发送 DEVICE_TYPE（12 字节，01 软驱 / 02 光驱）    3      10s 看门狗 → error 122
  ← ACK(code=16 ACK_DEVICE_CREAT)               3 → 4，启动心跳定时器
SCSI CDB / 数据交换                             4（ACTIVE）
```

- 一个 VMM 连接**同时承载两个设备**：第二个设备挂载时复用同一 socket，
  只补发一个 `DEVICE_TYPE`（`VMConsole.java:199-201`、`sentVirtualCommand`）
- 卸载时才发 `CLOSE_VM`，然后关 socket（仅在 ACTIVE 且无错误时）

### 4.2 `CERTIFY_ID` 精确字节

`ProtocolProcessor.connectPak`（`ProtocolProcessor.java:221-263`）+
`VMConsole.sentCertifyCode`（`VMConsole.java:264-286`）。
`getSessionID()` 恒为 24 字节（`VMConsole.java:240`），所以 24 字节分支是唯一会走的。

```
偏移  长度  值                        含义
 0     1    01                        CERTIFY_ID
 1     3    00 00 00                  保留
 4     4    00 00 00 1D               payload 长度 = 24 + 1 + 4 = 29（大端）
 8     4    03 01 01 01               客户端 VM 控制台版本（配置 "3.01.01.01"）
12    24    <session id>              24 字节证明 = PBKDF2(...)[0..23]
36     1    00 = IPv4, 01 = IPv6     ipLen==4 ? 0 : 1
37     4    <本机 IP>                 socket.getLocalAddress().getAddress()
                              总长 = 41
```

### 4.3 密钥派生（PBKDF2 56 字节）

`VMConsole.createSecretCertifyCode`（`VMConsole.java:227-246`）：

```java
String str = new String(certifyID, "UTF-8");
char[] chararray = str.toCharArray();
byte[] completeKey = AESHandler.getvmmcodekey(chararray, 56, vmm_salt, hmac, iter);
this.sessionid = new byte[24];
System.arraycopy(completeKey,  0, this.sessionid, 0, 24);
System.arraycopy(completeKey, 24, tempBuff, 0, 16); this.setSecretKey(tempBuff);
System.arraycopy(completeKey, 40, tempBuff, 0, 16); this.setSecretIvBMC(tempBuff);
```

```java
// AESHandler.java:30-35
PBEKeySpec spec = new PBEKeySpec(password, vmm_salt, iterations, len * 8);
SecretKeyFactory skf = SecretKeyFactory.getInstance(hmac);
return skf.generateSecret(spec).getEncoded();
```

56 字节输出的三段用途：

| 切片 | 用途 |
|---|---|
| `[0..23]` | **session id**，作为 `CERTIFY_ID` 的 payload 发给 BMC |
| `[24..39]` | `secretKey` —— VM 数据 AES-128 密钥 |
| `[40..55]` | `secretIv` —— VM 数据 AES-CBC IV |

- **口令** = `certifyID` 按 UTF-8 解码后的字符串。走协商路径时 `certifyID`
  就是 KVM 通道下发的 **20 字节 code key**；老路径是 4 字节大端 `mmVerifyValue`
  （本机型 `（会话值已脱敏）` = `2C 98 06 C4`）⚠️ 前者是否为 ASCII 文本未验证
- **salt** = 16 字节 `vmm_salt`；若协商从未发生，`getVmmSalt()` 返回全 0
  （`VirtualMedia.java:1237-1243`）
- **迭代次数 / PRF** 来自 KVM 通道的套件协商；
  `ConsoleControllers` 默认 `PBKDF2WithHmacSHA1` / 5000（`ConsoleControllers.java:34-35`），
  实际被 `setPbkdf2Params(kvmInterface.getHmac(), kvmInterface.getIterations())` 覆盖
  （`VirtualMedia.java:807, 816`）

### 4.4 VM 数据的 AES

- 算法 `AES/CBC/NOPadding`，**零填充**，不传输真实长度
- `vmmencry(src, key_data, len, vmm_iv)`：key = `key_data[0..15]`，IV = `vmm_iv`
- `vmm_decry(src, key_data, len, vmm_iv)`：直接用 `key_data` 当密钥（不取偏移）
- 因为 NoPadding，**真实明文长度必须显式携带** —— 这就是 DATA 帧里 4 字节长度前缀的用途

### 4.5 `vmm_compress` 的真实含义

`KVMApplet.java:249-254`：参数缺失时**默认 1（加密）**。
注意它控制的不是压缩，而是 **VM payload 是否加密**：

| | `vmm_compress == 0` | `vmm_compress == 1` |
|---|---|---|
| 发送 DATA payload | 原始数据 | `4 字节大端明文长度` + `AES-CBC 密文`；头部长度字段 = 密文长度 + 4 |
| 接收 DATA payload | 原始 | 前 4 字节 = 真实长度，其余解密 |
| CDB / ACK / 心跳 / CERTIFY_ID / DEVICE_TYPE / 完成帧 | **从不加密** | **从不加密** |

（`SFF8020iProcessor.java:410-463`、`UFIProcessor.java:382-434`、`USBProcessor.java:102-142`）

> 「compress」是历史误名。KVM 通道的 `compress` 与 VMM 的 `vmm_compress`
> 是**两个独立开关**。

---

## 5. 设备注册与数据通路

### 5.1 设备注册

`ProtocolProcessor.devicesPak`（`ProtocolProcessor.java:265-270`）：12 字节，
`pack[0]=2`、`pack[1]=设备类型`。

设备来源在 `creatVMLink`（`VMConsole.java:145-196`）按 `srcType` 决定：

| 设备 | 类型 | srcType | 实现类 |
|---|---|---|---|
| 软驱 | 1 | 0 | `FloppyDevice`（本地物理软驱，走 JNI） |
| 软驱 | 1 | 1 | `FloppyImage`（`.img`，2880 × 512 字节） |
| 光驱 | 2 | 0 | `CDROMDevice`（本地物理光驱，走 JNI） |
| 光驱 | 2 | 1 | `CDROMImage`（`.iso`，2048 字节/扇区） |
| 光驱 | 2 | 2 | `CDROMLocalDir`（本地目录 → 内存中构造 UDF ISO） |

几何参数：`FloppyDriver.TOTAL_BLOCKS = 2880`、`BLOCK_LENGTH = 512`、
`MEDIUM_TYPE_CODE = 148`；`CDROMDriver.BLOCK_LENGTH = 2048`。

> 本地 G 盘 / 目录挂载依赖 JNI 库（配置里的 `VMConsoleLib` / `VMConsoleLib_x64`），
> 纯 Java 实现者只能走「镜像文件」路径。

### 5.2 两套 SCSI 子协议

BMC 把**原始 12 字节 SCSI CDB** 作为 `0x03`（软驱）或 `0x04`（光驱）的 payload
下发，低半字节 = 0。客户端原样取出后按 `command[0] & 0xFF` 分派。

**UFI（软驱，`UFIProcessor.java:57-125`）**：
`0` TEST_UNIT_READY、`1` REZERO_UNIT、`3` REQUEST_SENSE、`4` FORMAT_UNIT、
`18` INQUIRY、`27` START_STOP、`29` SEND_DIAGNOSTIC、
`30` PREVENT_ALLOW_MEDIUM_REMOVAL、`35` READ_FORMAT_CAPACITY、`37` READ_CAPACITY、
`40` READ_10、`42` WRITE_10、`43` SEEK_10、`46` WRITE_AND_VERIFY、`47` VERIFY、
`85` MODE_SELECT、`90` MODE_SENSE、`168` READ_12、`170` WRITE_12；
其它 → sense 5/0x24

**SFF-8020i（光驱，`SFF8020iProcessor.java:75-151`）**：
`0` TEST_UNIT_READY、`3` REQUEST_SENSE、`18` INQUIRY、`27` START_STOP、
`30` PREVENT_ALLOW、`37` READ_CAPACITY、`40`/`168` READ_10/12、`43` SEEK_10、
`66` READ_SUB_CHANNEL、`67` READ_TOC、`68` READ_HEADER、`74` TEST_UNIT_READY_EXP、
`85` MODE_SELECT、`90` MODE_SENSE、`185` READ_CD_MSF、`190` READ_CD；
其它 → sense 5/0x24。
**光驱无写入路径**（`42`/`170` 未分派 → 5/0x24）。

LBA 取自 CDB 字节 2..5（`getInt32bits(command,3)`），传输长度取自
字节 6..9（READ_12/READ_CD）或字节 7..8（READ_10）—— **CDB 是字节精确的标准 SCSI**。

**固定应答**：

- UFI INQUIRY（`UFIProcessor.java:19`）：`00 80 00 01 1F 00 00 00` +
  ASCII `"Virtual FLOPPY VM 1.1.0    "`（共 36 字节）
- SFF INQUIRY（`SFF8020iProcessor.java:25`）：`05 80 00 21 1F 00 00 00` +
  `"Virtual DVD-ROM VM 1.1.0 225"`（36 字节）
- REQUEST_SENSE 模板（`USBProcessor.java:17`）：
  `70 00 <key> 00 00 00 00 0A 00 00 00 00 <ASC> <ASCQ> 00 00 00 00`
  （索引 12/13 = ASC/ASCQ，索引 2 = sense key；若有 information 则字节 0 改 `0xF0`
  并把 LBA 塞进字节 3..6）

### 5.3 数据帧

客户端 → BMC DATA：

```
偏移 0     1                    2  3    4-7              8-11
     03/04 (state<<4)|01        ID      payload 长度      00 00 00 00   然后是 payload
                                       （加密模式下 = 密文长度 + 4）
```

`state = 1`（CONTINUE）表示还有后续，`3`（END）是最后一片。
分片大小：软驱 `FLOPPY_PACKET_SIZE = 4096`，光驱 `CDROM_PACKET_SIZE = 32768`。
SFF 允许零长度尾片（`sffDataPak(1, 3, 0, id)`）。

数据阶段后**总是**跟一个完成帧：

- UFI：`FE <result> 00 <ID> 00…`，`result = 1` 表示有待处理 sense
  且命令不是 REQUEST_SENSE
- SFF：`FF <result> 00 <ID> 00…`，`result = 1` 表示出错；
  `TEST_UNIT_READY_EXP(74)` 无条件返回 1

BMC → 客户端 DATA 用**完全相同的 12 字节容器**（`ProtocolProcessor.java:134-161`）：
操作码 3/4、低半字节 1、同一 ID、长度在字节 4..7；加密模式下 payload 前 4 字节是明文长度。

---

## 6. KVM 通道引导 VMM

### 6.1 引导序列

```
KVM 通道：
  ① TX  REQ_VMM_CODEKEY(0x31/49)  payload {49, blade}
     RX  VMM_CODEKEY_REPORT(0x32/50) → 20 字节 code key + 16 字节 vmm salt
  ② TX  REQ_VMM_PORT(0x35/53)     payload {53, blade}
     RX  VMM_PORT_REPORT(0x36/54)  → 2 字节端口（小端）
  ③ 用 ① 的材料派生 session id / secretKey / secretIv
  ④ 连 VMM 端口，走 §4 的认证握手
```

客户端每步等待 50 × 60ms = **3s**（`VirtualMedia.java:762-769, 790-797`），
并由 `bVmmPri` 门控 —— 收到 `NOT_PRI(0x51/81)` 表示别的用户持有优先级
（`BladeThread.java:515-523`）。

### 6.2 `VMM_CODEKEY_REPORT`(0x32/50) 精确布局

`BladeThread.distributeNegotiVMMCodeKey`（`BladeThread.java:473-495`）：

```java
byte[] code_key_data = new byte[20];
byte[] salt = new byte[16];
System.arraycopy(unPackData, 2, nego_data, 0, data_len);
if (Base.getCompress() == 1) {
    conde_data = AESHandler.decry(nego_data, Base.getKvm_key(), data_len);
    System.arraycopy(conde_data, 0, code_key_data, 0, 20);
    System.arraycopy(conde_data, 20, salt, 0, 16);
} else {
    System.arraycopy(nego_data, 0, code_key_data, 0, 20);
    System.arraycopy(nego_data, 20, salt, 0, 16);
}
```

```
compress == 0 :  20 字节 code key || 16 字节 vmm salt      （36 字节明文）
compress == 1 :  AES-CBC(K = kvm_key[0..15], IV = kvm_key[32..47])
                 对上面 36 字节零填充到 48 字节后的密文
```

- 20 字节 code key → 作为 PBKDF2 的**口令**（§4.3）
- 16 字节 vmm salt → PBKDF2 的 **salt**
- 两者最终进 `KVMUtil.setVMMSecretCodeKey` → `VirtualMedia.setNegotiCodeKey`，
  并置 `Base.setBvmmCodeKeyNego(true)`（协商成功标志）

### 6.3 `VMM_PORT_REPORT`(0x36/54)

`BladeThread.distributeVMMPort`（`BladeThread.java:497-513`）：2 字节端口，
同样在 `compress == 1` 时用 `AESHandler.decry` 解密。

⚠️ 解析时按**小端**：
```java
// VirtualMedia.java:705-734
tmpPort  = (this.strPort[1] & 0xFF) << 8;
tmpPort |= this.strPort[0] & 0xFF;
```
（与协议其余部分的大端相反，容易踩坑。）

只有当 JNLP 派生出的端口 `<= 0` 时才会走 53/54 查询；
正常 JNLP（`vmmPort=8208`）直接用它，跳过这一步。

---

## 7. 配置项（JAR 内 `com/huawei/vm/console/vmconfigResource.properties`）

`ResourceUtil.java:11` 的 bundle 名 = `com.huawei.vm.console.vmconfigResource`，
英文 locale，`FORMAT_PROPERTIES`。实际内容：

```properties
com.huawei.vm.console.config.version = 3.01.01.01
com.huawei.vm.console.config.library = VMConsoleLib
com.huawei.vm.console.config.library.x64 = VMConsoleLib_x64
com.huawei.vm.console.config.libExt = .dll
com.huawei.vm.console.config.library.path = com/huawei/vm/console/
com.huawei.vm.console.config.device.read.retry = 1
com.huawei.vm.console.config.receiver.overtime = 3000
com.huawei.vm.console.config.business.overtime = 20000
com.huawei.vm.console.config.print.level = 100
com.huawei.vm.console.config.cdrom.datapacket.size = 32768
com.huawei.vm.console.config.floppy.datapacket.size = 4096
com.huawei.vm.console.config.heartBit.interval = 10000
```

| 键 | 值 | 用途 |
|---|---|---|
| `...config.version` | `3.01.01.01` | `CERTIFY_ID` 的版本字段 |
| `...config.business.overtime` | 20000 | payload 读超时 |
| `...config.cdrom.datapacket.size` | 32768 | → `CDROM_PACKET_SIZE` |
| `...config.floppy.datapacket.size` | 4096 | → `FLOPPY_PACKET_SIZE` |
| `...config.heartBit.interval` | 10000 | 心跳周期 + 读头超时 |
| `...config.receiver.overtime` | 3000 | 声明未使用 |
| `...config.print.level` | 100 | `TestPrint` 默认级别 |

> ⚠️ `ProtocolCode` 是**类初始化时**读这些键并 `Integer.parseInt` 的。
> 如果资源文件缺失，`ResourceUtil` 的兜底分支对这两个数据包大小键返回 `"0"`
> （`ResourceUtil.java:87`），会让发送循环死循环。

错误提示文案在 `com/huawei/vm/console/vmResource*.properties`
（键 `com.huawei.vm.console.error.<code>`）：

- `121` = 「服务器无响应，连接未建立」
- `122` = 「虚拟介质设备创建失败，服务器无响应」
- `123` = 「服务器无响应，连接已中断」
- `401` = 「虚拟介质已被其他用户使用」
