# 01 — 传输层与帧格式

## 1. 传输

| 项 | 值 | 证据 |
|---|---|---|
| 协议 | 裸 TCP，**无 TLS、无握手加密** | 📖 `com/kvm/BladeCommu.java:63` `new Socket(ip, port)` |
| KVM 端口 | JNLP `<param name="port">`，本机型 `2198` | 📖 `KVMApplet.java`；✅ 实测连通 |
| VMM 端口 | JNLP `<param name="vmmPort">`，本机型 `8208` | 📖 `VirtualMedia.java:107` 硬编码默认 8208 |
| 套接字选项 | `setTcpNoDelay(true)`、`setSoTimeout(20000)` | 📖 `BladeCommu.java:65-66` |
| 连接失败重试 | 若失败且耗时 <15s，补足到 15s 再抛异常 | 📖 `BladeCommu.java:70-81` |

⚠️ 端口是明文 TCP，`verifyValue` 等凭证在**首次 `CONNECT_BLADE` 之前**就已在
套件协商里用到，因此**不要跨不可信网络使用**。

---

## 2. 两个方向的帧格式**不一样**

这是本协议最容易搞错的地方。发出去和收进来的格式不同。

### 2.1 客户端 → BMC（普通帧）

构建函数 `PackData.makePackData(id, data, length)`（`PackData.java:137-156`）：

```
偏移  长度  字段
 0     2    固定魔数  FE F6
 2     2    长度字段 = payload_len + 2，大端 u16
 4     4    codeKey，大端 i32（见下）
 8     2    CRC-16，大端（高字节在前）
10     N    payload（第一个字节是命令码）
```

总长度 = `payload_len + 10`。

**关于 `length` 字段**：`packData[2..3] = (length + 2)`，而 CRC 恰好占 2 字节，
所以长度字段的语义是「CRC + payload」的总字节数。✅

**关于 `codeKey`**：两种取值
- 会话级命令（心跳、套件、VMM 查询、关机等）：`kvmInterface.getCodeKey()`，
  即 JNLP 的 `verifyValue`（截断成 32 位有符号整数）。
- 刀片级命令（视频、键鼠、帧率）：`KVMUtil.getImagePaneCodeKey(bladeNo)`，
  单刀片机型下等于同一个 `verifyValue`（`InterfaceContainer.java:79-82`：
  `codeKey == -1` 时回退到 `kvmInterface.getCodeKey()`）。
- 实测：`verifyValue=1000000001` = `0x4A7DA307`，抓包中偏移 4..7 就是 `4a 7d a3 07` ✅

### 2.2 客户端 → BMC（连接帧 / "压缩帧"）

连接命令 `CONNECT_BLADE` 走一个**变体**：`PackData.makeEncrypPackData(id24, data, length)`
（`PackData.java:158-178`）。当 JNLP `compress != 0` 时使用
（`PackData.connectBlade`，`PackData.java:215-243`）。

```
偏移  长度  字段
 0     2    FE F6
 2     2    (length + 2)，大端 u16，**最高位 0x8000 置起表示这是加密帧**
 4     24   encodeKey（PBKDF2 派生的会话证明，见 02 章）
28     2    CRC-16，大端
30     N    payload
```

注意长度字段用的是**变量 `length` 而不是掩码后的 `len`**：
`connectBlade` 里 `length = 0x8000 | data.length`，所以长度字段 =
`0x8000 | 5` + 2 = **`0x8007`**。✅ 实测抓包中正是 `fef6 8007 ...`。

解析方（BMC）看到 `length & 0x8000` 就知道带 24 字节密钥头；
`len = length & 0x7FFF` 才是真实 payload 长度。

### 2.3 BMC → 客户端

解析器是 `KVMUtil.diviStreamNew(byte[] bytes, boolean isNew)`（`KVMUtil.java:942-977`）。
它是**带状态**的增量解析器，逐字节扫描：

```
状态 0：滑动匹配 3 字节魔数 FE F6 00
        （代码里是 head 左移累积，比较 (head & 0xFFFFFF) == 16709120 == 0xFEF600）
状态 1：读 1 字节 dlen；若 dlen < 3 或 dlen > 250 → 判定失步，回到状态 0
状态 2：读满 dlen 字节，整帧完成，返回 true
```

所以线上格式是：

```
偏移  长度  字段
 0     3    固定  FE F6 00        ← 注意第三字节固定 0，等于长度高字节
 3     1    dlen，1 字节，范围 3..250
 4     dlen payload
```

总长度 = `4 + dlen`。

**关键结论：**

- ✅ **接收方向没有 codeKey，也不校验 CRC**。`diviStreamNew` 完全不校验 CRC，
  长度字段就是 payload 长度（不像发送方向是 payload+2）。
- ✅ **帧贴合已验证**：一次 TCP 段里收到两帧时，`4 + len` 精确衔接
  （实测 `4+0x14=24`，第二帧起于偏移 24，总 36 字节）。发送方向发两个
  `GET_SUITE` 也会收到两个 `0x43`，各自完美贴合。
- ✅ `payload[0]`、`payload[1]` **恒为 `00 00`，不是 CRC**。
  实测按 `payload[2..]` 算出的 CRC-16/CCITT-FALSE 是 `0x7499`／`0x969E`，
  与 `0x0000` 不符，**该假设已证伪**。
  老的解析器 `KVMUtil.doDivi`（`KVMUtil.java:797-867`）在同样位置**校验过 CRC**
  （比较 `bytes[start+4]`/`bytes[start+5]`），所以这是历史遗留字段，
  当前 BMC 填 0、新客户端不校验。
- ⚠️ `payload[3]` **不总是刀片号**：在 `0x02`/`0x08`/`0x43` 里是 0（刀片号），
  但实测 `0x25`（鼠标模式）里是 `0x02`（疑似请求模式的回显），
  而客户端只读 `payload[4]`。该字节语义未完全定论。
- ✅ payload 内部布局：`payload[2]` = 命令码，`payload[3]` = 刀片号。
  这与 `UnPackData.setkvmType` 用 `data[2]` 分派、`presentBladeInfo()` 返回
  `{1, sourceData[3], sourceData[4]}` 完全一致。
- **dlen ≤ 250 是硬限制**：更大的视频帧会在 BMC 侧被拆成多个子包（见 03 章）。

> 为什么两个方向格式不对称？这是历史遗留：老的
> `doDivi`（`KVMUtil.java:797-867`）期望 `FE F6 00 | len | CRC16 | payload`，
> 与发送方向对称；新的 `diviStreamNew` 把长度压成 1 字节并去掉了 CRC 校验。
> 两者都要求长度高字节为 0，所以线格式互相兼容，只是校验被放弃了。

---

## 3. CRC-16 算法

`KVMUtil.java:69` 使用 `new CCrc("CRC_16_H")`。按 `CCrc.java:28-31, 95-117`：

- 多项式 `4129` = **`0x1021`**
- 初始值 **0**
- MSB-first，不反转输入/输出，无最终异或

即标准 **CRC-16/CCITT-FALSE**（也叫 CRC-16/XMODEM，区别只在 XMODEM 无别名）。

表生成（`CCrc.java:51-60`，`CRC_16_H` 分支）：
```java
w = i << 8;
for (j = 0; j < 8; ++j)
    w = ((w & 0x8000) != 0) ? ((w << 1) ^ 0x1021) : (w << 1);
```

逐字节（`CCrc.java:109-116`）：
```java
temp = ((startCrc >> 8) & 0xFF) ^ addr[i];
crcResult = crc16Table[temp] ^ (startCrc << 8);
```

**覆盖范围**：只覆盖 payload，**不含帧头**。✅

参考实现（JS）：
```js
const TBL = new Int32Array(256);
for (let i = 0; i < 256; i++) {
  let w = i << 8;
  for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff;
  TBL[i] = w;
}
function crc16(buf) {
  let c = 0;
  for (const b of buf) c = (TBL[((c >> 8) & 0xff) ^ b] ^ ((c << 8) & 0xffff)) & 0xffff;
  return c;
}
```

---

## 4. 接收方向的流处理

`BladeThread.run()`（`BladeThread.java:116-205`）的循环：

```
while (isConn) {
    bytes = bladeCommu.getData();          // 一次 read()，最多 4096 字节
    kvmUtil.setStart(0);                   // ★ 重置解析器游标（重要）
    flag = kvmUtil.diviStreamNew(bytes, isNew);
    while (flag) {                          // 一个 TCP 段里可能有多帧
        unPack.setkvmType(kvmUtil.getResult());
        unPackData = unPack.getData();
        switch (unPackData[0]) { ... }      // 按命令码分派
        flag = kvmUtil.diviStreamNew(bytes, isNew);   // 继续取下一帧
    }
}
```

要点：

- ✅ **必须按完整帧边界解析，不能按 TCP 分段**。这正是早期原型（见
  `PROTOCOL.md` 旧版）踩过的坑：同一个 `write()` 里可能挤了多个命令。
- `setStart(0)` 每次 `read()` 前重置，解析器状态（`state`/`head`/`dlen`/`rdlen`）
  跨调用保留，所以**跨 TCP 段的半帧会被正确拼接**。
- 背压：若绘制队列 `lList` 超过 2000，`Thread.sleep(10)` 等待（`BladeThread.java:126-129`）。

---

## 5. 字节序速查（很容易搞混）

`KVMUtil` 里有两个方向相反的整数写入函数：

| 函数 | 位置 | 字节序 |
|---|---|---|
| `KVMUtil.intToByte(dest, off, v)` | `KVMUtil.java:399-404` | **小端**：`[0]=v, [1]=v>>8, [2]=v>>16, [3]=v>>24` |
| `KVMUtil.intToByteCon(dest, off, v)` | `KVMUtil.java:406-411` | **大端**：`[0]=v>>24, ... [3]=v` |

具体用到的地方：

- 帧头 codeKey：`intToByteCon` → **大端**
- CRC 写入：先 `intToByte`（小端）得到 `temp`，再手动 `packData[8]=temp[1]; packData[9]=temp[0]`
  → 抵消成**大端**
- 鼠标坐标：`intToByte` 取 `temp[1],temp[0]` → 也变成**大端**（见 04 章）
- 长度字段：直接位运算 `>>8` / `&0xFF` → **大端**

**结论：协议里所有多字节数值都是大端**，两个 helper 的反向只服务于
个别需要拆字节的场合。

---

## 6. BMC 对客户端帧到底校验什么（实测）

对真实设备做了逐字段篡改实验（每例独立 TCP 连接，只发只读的 `GET_SUITE`）：

| 篡改 | BMC 是否应答 | 结论 |
|---|---|---|
| 基线（字段全对） | ✅ 应答 `0x43` | — |
| 一次 write 发**两帧** | ✅ 应答**两个** `0x43` | BMC 会处理同一 TCP 段里的多帧 |
| 一帧**拆成两次 write** | ❌ 无应答 | **必须整帧一次 write**，BMC 不做跨 read 重组 |
| **CRC 字段改成 `0000`** | ✅ 应答 | **BMC 不校验 CRC**（至少 `GET_SUITE` 不校验） |
| **codeKey 改成 `0`** | ✅ 应答 | 套件协商**免认证** |
| **codeKey 全部取反** | ✅ 应答 | 同上，会话号在此阶段完全不被检查 |
| 长度字段 `payload+3` | ❌ 无应答 | BMC 按长度字段决定还要读多少字节，会一直等 |
| 长度字段 `payload+1` | ✅ 应答 | 声明偏短仍能工作（命令字节在最前） |
| 魔数 `FE F6` → `FE F5` | ❌ 无应答 | 魔数是硬要求 |

**实现要点：**

1. **一帧一次 `write()`**，不要依赖 BMC 重组 TCP 分片。
2. CRC 字段仍应正确计算（真实的 Java 客户端会算，且老版本 BMC 可能校验），
   但不要把它当作可靠的完整性保护 —— 它既不被校验，也不保护机密性。
3. 真正的认证发生在 `CONNECT_BLADE`（携带 PBKDF2 派生的 24 字节证明），
   `GET_SUITE`/`SET_SUITE` 阶段任何人都能发。
   **不要把这理解为「协议不安全就无需登录」** —— 登录态由 JNLP 会话号承载，
   `CONNECT_BLADE` 才是门。
