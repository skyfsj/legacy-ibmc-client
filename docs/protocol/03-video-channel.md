# 03 — 视频通道

> **证据说明**：本章的帧结构、块编解码、合成 JPEG 头、DQT 选表**已用真实会话端到端验证** ✅
> —— 抓到真帧后完整解码并渲染出了远端服务器的实际画面
> （`No bootable device , please reboot system with manual operation.`）。
> 验证方法与证据见 [07-live-verification.md](07-live-verification.md)。
> 仍属推断的部分已单独标注 ⚠️。

视频数据全部由 `IMAGE_DATA(0x02)` 命令承载（BMC → 客户端，单向，不需要请求）。

---

## 1. 三层封装

```
BMC → 客户端 帧:   FE F6 00 | dlen | payload
                                    payload[0..1] = 00 00      ← 恒为 0，见 §1.4
                                    payload[2]    = 0x02       命令
                                    payload[3]    = 0x00
                                    payload[4..5] = 子包序号（大端 u16）
                                    payload[6]    = 帧号
                                    payload[7..]  = 子包内容
        ↓ UnPackData.imageData()  得到 currentData = {2} ++ payload[3..]
        ↓ 序列号==0 → 明文，不解密
        ↓ 序列号!=0 → AES 解密 payload[8..]
        ↓ kvmUtil.isComplete() 按帧号+序号重组
        ↓ kvmUtil.combine() 拼成「重组缓冲」
        ↓ imageDecoder.decodeRLEorJPEG0()
```

### 1.1 为什么需要重组

接收帧 `dlen ≤ 250`（见 01 章），一帧视频远大于此，所以 BMC 把它切成多个
**子包**（每个子包数据 ≤ 220 字节）分开发送，客户端按序号拼回。

实测：一个 800×600 的 I 帧被切成 **25 个子包**（序号 0..24），
`packLenght = 5128`，重组后缓冲正好 5129 字节 ✅

### 1.2 子包头部（✅ 已验证）

子包数组 `buf`（= 客户端里的 `imageData`，即 wire 上 `payload[4..]`），
所以 **`buf[k] == payload[k+4]`**：

| buf 偏移 | payload 偏移 | 长度 | 字段 |
|---|---|---|---|
| 0 | 4 | 2 | **子包序号**，大端 u16；0 = 帧头子包 |
| 2 | 6 | 1 | **帧号**，递增、回绕 |
| 3 | 7 | 4 | **数据总长** `packLenght`（大端 u32） |
| 7 | 11 | 1 | bit7 = **差分帧标志**；bit6..0 = 宽度高 7 位 |
| 8 | 12 | 1 | 宽度低 8 位 |
| 9 | 13 | 2 | **高度**，大端 u16 |
| 11 | 15 | 1 | 观察值恒为 **0xDC = 220**（= 子包数据上限）⚠️ 语义未最终确认 |
| 12 | 16 | 2 | **remoteX**（远端光标 X）大端 u16 |
| 14 | 18 | 2 | **remoteY**（远端光标 Y）大端 u16 |
| 16 | 20 | 1 | bit7 = **I 帧标志**；低 4 位 = **DQT 档位** |

实测样本（800×600 帧的帧头子包，wire payload）：

```
00 00 02 00 00 00 02 | 00 00 14 08 | 03 | 20 | 02 58 | dc | ff ff | ff ff | 07
  ↑恒0  ↑cmd ↑  序号0 帧号2         总长5128  宽高字节 宽800  高600   220   rx     ry   DQT7/非I帧
```

推出：

- **宽度 = `((buf[7] & 0x7F) << 8) | buf[8]`**（15 位有效，差分标志占了宽度的最高位）
- **高度 = `buf[9] << 8 | buf[10]`**
- `remoteX/Y = 0xFFFF/0xFFFF` 表示**远端光标不可见**（与客户端里
  `mousePack(65535,65535)` 的哨兵约定一致）
- I 帧标志与 DQT 档位共用一个字节

> `packLenght` 的语义（✅ 已验证）：**只统计序号 ≥ 1 的子包**的 `(长度-3)`。
> 帧头子包（序号 0）不计入 —— 对应客户端 `isComplete` 里首个序号 0 包
> 直接存入 `bufferA[0]` 而**不累加 `packSum`** 的分支。
> 所以重组缓冲长度恰好 `packLenght + 1`，**没有零填充**。

### 1.3 关键：序号 0 的子包**不加密**

`DrawThread.java:140-157` 的 `if / else if` 结构：

```java
if (Base.getIsNewCompAlgorithm() && this.currentData[2] == 0 && this.currentData[3] == 0) {
    int isSameFrame = (this.currentData[9] & 0x80) >> 7;   // 帧头包里直接可读！
    if (1 == isSameFrame) { ... continue; }                 // 整帧无变化，跳过
} else if (Base.getCompress() == 1) {
    reallen += this.currentData[5] & 0xFF;                  // 明文长度
    CompressData = new byte[this.currentData.length - 6];
    System.arraycopy(this.currentData, 6, CompressData, 0, CompressData.length);
    temDes = AESHandler.decry(CompressData, Base.getKvm_key(), CompressData.length);
    ...
}
```

因为是 **`else if`**：新算法下、且序号为 0 的子包**完全跳过解密分支**，
`currentData` 被当作明文。所以：

| 子包 | 编码 | 客户端处理 |
|---|---|---|
| 序号 0（帧头） | **明文** | `imageData = payload[4..]`，直接解析帧头 |
| 序号 ≥ 1 | **AES-CBC 密文** | `payload[7]` = 明文长度；`payload[8..]` = 密文；解密后取前 `payload[7]` 字节 |

序号 ≥ 1 的子包：`imageData = payload[4..7) ++ 解密结果[0 .. payload[7])`。

密文用 `kvm_key[0..15]` 作密钥、`kvm_key[32..47]` 作 IV（`AESHandler.decry`）。

### 1.4 重组（✅ 已验证）

- `doSort` 按 `buf[0..1]`（序号）升序排序（`KVMUtil.java:455-472`）
- `combine()`（`KVMUtil.java:474-516`）：

```java
byte[] buf = (byte[])list[0];          // 序号 0 的帧头包
data[0] = (byte)k;                     // k = buf[7] bit7 = 差分标志
for (i = 1; i < list.length; ++i) {    // ★ 从 1 开始：帧头包不参与拼接
    byte[] bytes0 = (byte[])list[i];
    int temLen = bytes0.length - 3;
    System.arraycopy(bytes0, 3, data, index, temLen);
    index += temLen;
}
```

**重组缓冲 = `[差分标志] ++ 拼接(序号≥1 子包的 buf[3..])`，长度 = `packLenght + 1`。**
块流从**索引 1** 开始。

实测：25 个子包 → 重组缓冲 5129 字节 = `5128 + 1` ✅ 完全吻合，无尾部填充。

### 1.5 帧头包的 `payload[0..1]` 恒为 0（不是 CRC）

曾怀疑 wire payload 前两字节是 CRC-16。**实测证伪**：
两个独立样本都是 `00 00`，而按 payload[2..] 算出的 CRC-16/CCITT-FALSE
分别是 `0x7499` 和 `0x969E`，与 `0x0000` 不符。

老的解析器 `KVMUtil.doDivi`（`KVMUtil.java:797-867`）确实在同样位置校验 CRC，
所以历史格式那里应该是 CRC，**但当前 BMC 发的是 0，且新客户端根本不校验**。

> 另外经实测，**BMC 也不校验客户端帧的 CRC 字段**：把 CRC 改成 `0000`
> 后 `GET_SUITE` 仍然正常应答。见 [07-live-verification.md](07-live-verification.md)。

### 1.6 无效帧（屏幕无变化）

BMC 会周期性发送**只有帧头、`packLenght = 0`** 的子包，表示「画面没变」：

```
帧号 n: 序号0, 总长=0, 差分=1, I帧标志=1, 800x600
```

客户端在 §1.3 那个 `if` 里通过 `isSameFrame = buf[9] bit7` 判定并 `continue` 跳过，
所以不会重绘。实测在一个静止画面里收到 5 个这样的帧。

---

## 2. 像素格式

### 2.1 色深

`connectBlade(bladeNO, colorBit)` payload 第 3 字节（`PackData.java:215-243`），
取值来自色深对话框（`ColorBit.java:33-36`）：

| colorBit | 含义 |
|---|---|
| 2 | 8 bit |
| 1 | 7 bit |
| 0 | 6 bit（`ImagePane.custBit` 默认值） |
| 3 | 4 bit |

⚠️ 实测我们发送的是 `colorBit = 2`，BMC 回的块全部是 JPEG（4:4:4 + DQT 量化），
没有出现 RLE 块。**`colorBit` 各档位是否改变块类型选择，尚未验证**（见 §9）。

### 2.2 颜色转换（📖 `ColorConverter.java`）

**YCbCr → RGB888**（`ycbcr2rgb`，BT.601 全范围）：

```java
R = Y + 1.402 * (Cr - 128);
G = Y - 0.34414 * (Cb - 128) - 0.71414 * (Cr - 128);
B = Y + 1.772 * (Cb - 128);
```

**YCbCr → 8 位打包 3-3-2**（`ycbcr2rgb332`）：

```java
R = 1.164*(Y-16) + 1.596*(Cr-128);
G = 1.164*(Y-16) - 0.813*(Cr-128) - 0.392*(Cb-128);
B = 1.164*(Y-16) + 2.017*(Cb-128);
// clamp 后：
bgr233 = (B & 0xC0) | ((G & 0xE0) >> 2) | ((R & 0xE0) >> 5);
```

位分配：`bit7..6 = B 高 2 位`、`bit5..3 = G 高 3 位`、`bit2..0 = R 高 3 位`
（对应 `DirectColorModel(8, 7, 56, 192)`）。

> 3-3-2 只在**老算法路径**使用；新算法 `decodeRle` 用 24 位 RGB。
> 实测的 JPEG 块直接由标准 JPEG 解码得到 24 位 RGB。

---

## 3. 分块结构（✅ 已验证）

`ImageDecoder`（`ImageDecoder.java:16-17, 43-52`）：

```java
private static int blockImageWidth  = 64;
private static int blockImageHeight = 64;
this.blockXcount = imageWidth  / 64 + (imageWidth  % 64 == 0 ? 0 : 1);
this.blockYcount = imageHeight / 64 + (imageHeight % 64 == 0 ? 0 : 1);
this.blockcount  = this.blockXcount * this.blockYcount;
this.blockCutWidth  = 64 - (this.blockXcount * 64 - imageWidth);
this.blockCutHeight = 64 - (this.blockYcount * 64 - imageHeight);
```

- 屏幕按 **64×64 块**切网格，行优先编号 `blocknum = row * blockXcount + col`
- 800×600 → `blockXcount = 13`、`blockYcount = 10` → **130 块** ✅ 实测正好 130 块

块流从重组缓冲**索引 1** 开始，每次前进 `syclen`（`decodeRLEorJPEG1`，
`ImageDecoder.java:332`）：

```java
for (int i = 1; i < zipDatas.length; i += syclen) {
    zipType  = (zipDatas[i] & 0xFF & 0xE0) >> 5;   // bit7..5
    rZipType = (zipDatas[i] & 0xFF & 0x1C) >> 2;   // bit4..2
    ...
}
```

**块描述符 1 字节**：`bit7..5 = zipType`，`bit4..2 = rZipType`，`bit1..0` 未使用。

✅ 实测：130 块走完后指针正好停在缓冲末尾（5129 = 5129 字节），**零剩余零越界**。

---

## 4. 块类型

### 4.1 大类

| zipType | 含义 | 实测出现次数（800×600 静止画面） |
|---|---|---|
| 0, 1 | **RLE 块**，由 `rZipType` 选变体 | 0 |
| 2, 3 | **JPEG 块**（裸扫描数据）；代码里 2 和 3 处理完全相同 | 10 + 3 = 13 |
| 4 | 空操作，`syclen = 1` | 0 |
| 5 | **复制上一行同列块**（`blocknum - blockXcount`） | 96 |
| 6 | **复制左邻块**（`blocknum - 1`） | 21 |

> 实测的分布完全合理：第 0 行 13 块全是 JPEG（屏幕上那一行文字），
> 下面 9 行共 117 块全部是复制（`96 + 21`），因为屏幕其余部分是纯黑。
> 这解释了增量刷新如何做到极小码率。

### 4.2 RLE 块的子类型（`rZipType`）

| rZipType | 名称 | 调色板 | 数据结构 | `syclen` |
|---|---|---|---|---|
| 0 | 纯色填充 | 1 色 (Y,Cb,Cr) | 无位流 | `4` |
| 1 | 双色位流 | 2 色 (6B) | 6 位游程 + 变色标志 | `3 + 6 + len` |
| 2 | 3 色调色板 | 3 色 (9B) | 6 位游程 + 2 位索引 | `3 + 9 + len` |
| 3 | 4 色调色板 | 4 色 (12B) | 6 位游程 + 2 位索引 | `3 + 12 + len` |
| 4 | 复制左邻块 | 继承 | 源为纯色则 `syclen=1` | `1` 或 `3+len` |
| 5 | 复制左邻块 + 色调旋转 | 继承 | 无调色板，只有位流 | `3 + len` |
| 6 | 复制上一行块 | 继承 | 同 4 | `1` 或 `3+len` |
| 7 | 复制上一行块 + 色调旋转 | 继承 | 同 5 | `3 + len` |

`rZipType ≥ 1` 时颜色表紧跟描述符，位流长度在 `i+1..i+2`（大端 u16）：

```
[i]      描述符
[i+1..2] 位流长度 len（大端 u16）
[i+3..]  颜色表：1色 3B / 2色 6B / 3色 9B / 4色 12B（每色 Y,Cb,Cr）
[...]    位流 len 字节
```

### 4.3 位流编码

**双色（type 1）**（`ImageDecoder.java:537-594`）：

```java
subPixlen = ((tmpdata & 0xFC00) >> 10) + 1;   // 高 6 位 = 游程，1..64
tmpdata = (tmpdata << 6) & 0xFFFF;  lastnum -= 6;
if (subPixlen < 64) change_flag = 0;
else { change_flag = (tmpdata & 0x8000) >> 15; tmpdata <<= 1; --lastnum; }  // 游程=64 时多读 1 位
// 填充 subPixlen 个像素为当前色
// change_flag == 0 时切换颜色：
bufColor3 = (bufColor3 == bufColor1) ? bufColor2 : bufColor1;
```

6 位游程 + 两色交替；游程恰为 64 时额外 1 位 `change_flag`。位流大端位序跨字节打包。

**调色板（type 2/3）**（`ImageDecoder.java:596-619`）：

```java
subPixlen = ((temBlockData1[m] & 0xFC) >> 2) + 1;   // 高 6 位 = 游程
index     = temBlockData1[m] & 3;                    // 低 2 位 = 调色板索引
```

每字节 = `游程(6位,1..64) | 索引(2位)`。

**色调旋转（type 5/7）**（`ImageDecoder.java:369-386`）：源块调色板按
`[3,4,5,0,1,2]` 重排（RGB 三通道循环移位）。

---

## 5. JPEG 块与合成 JPEG 头（✅ 端到端验证）

BMC **不发完整 JPEG**，只发**裸熵编码扫描数据**；客户端**现场合成 JPEG 头**。

```java
// ImageDecoder.java:429-444
case 2: case 3: {
    len = ((zipDatas[i + 1] & 0xFF) << 8) + (zipDatas[i + 2] & 0xFF);
    byte[] synHeadData = JPEGData.createSynHeadData();
    zipData = new byte[len + synHeadData.length + JPEGData.TAIL.length];
    System.arraycopy(synHeadData, 0, zipData, 0, synHeadData.length);
    System.arraycopy(zipDatas, i + 3, zipData, synHeadData.length, len);   // 裸扫描数据
    System.arraycopy(JPEGData.TAIL, 0, zipData, synHeadData.length + len, JPEGData.TAIL.length);
    syclen = 3 + len;
    BufferedImage JPEGimage = this.imageCreater.JPEGDecodeAsImage(zipData);
}
```

块布局：

```
[i]      描述符（zipType = 2 或 3）
[i+1..2] len（大端 u16）= 裸扫描数据长度
[i+3..]  裸 JPEG 扫描数据，len 字节
```

### 5.1 合成头组成

| 段 | 长度 | 内容 |
|---|---|---|
| `HEAD_SYN_SOI_APPO` | 20B | `FF D8 FF E0 00 10 "JFIF" 00 01 01 00 00 01 00 01 00 00` |
| `HEAD_SYN_DQT_Y` | 69B | `FF DB 00 43 00` + 64 字节亮度量化表（**按 DQT 档位选**） |
| `HEAD_SYN_DQT_U` | 69B | `FF DB 00 43 01` + 64 字节色度 U 表 |
| `HEAD_SYN_DQT_V` | 69B | `FF DB 00 43 02` + 64 字节色度 V 表 |
| `HEAD_SYN_SOF_444` | 19B | `FF C0 00 11 08 00 40 00 40 03 01 11 00 02 11 01 03 11 02` |
| `HEAD_SYN_SOF_SOS` | 452B | 三张 DHT 表 + `FF DD 00 04 00 64`(DRI=100) + SOS |
| 裸扫描数据 | len | 来自块 |
| `TAIL` | 2B | `FF D9`（EOI） |

关键点（全部已验证）：

- ✅ **SOF 宽高写死 `0x40 × 0x40` = 64×64**，与 64×64 分块对应
- ✅ 用 **4:4:4** 采样（`HEAD_SYN_SOF_444`，分量采样因子全 `0x11`）。
  同文件里的 `HEAD_SYN_SOF_420`（`0x22`）**未被使用**
- ✅ **DQT 有 10 档**（`DQTZData.java`），索引 = `DQT档 - 1`
- ✅ `DRI` 重启间隔 = 100，所以裸扫描数据里每 100 个 MCU 有 RST 标记
- ✅ 按此规则合成的 JPEG 能被标准解码器解出 **130/130 块，0 失败**

### 5.2 块可以跨子包

⚠️ 更正：JPEG 块的 `len` **不受 250 限制**。实测单个 JPEG 块的扫描数据
最大 **600 字节**，远超声道上限 —— 因为 250 是**子包**限制，
而块流是在**重组之后**才解析的，一个块可以横跨多个子包。

---

## 6. 差分帧（增量刷新）

- 帧头 `buf[7]` 的 **bit7 = 差分标志**（`KVMUtil.setVar`、`combine`）
- 差分帧要与上一帧做 **XOR**：

```java
// DrawThread.java:195-203
if (this.kvmUtil.isDispDiff()) {
    if (!this.kvmUtil.xorData(data, this.previImage)) {   // 就地 dataA ^= dataB
        this.bladeCommu.sentData(this.kvmInterface.getPackData().resendData(this.bladeNo));
        continue;
    }
} else {
    System.arraycopy(data, 0, this.previImage, 0, data.length);
}
```

- **重传请求**：需要差分帧但没有参考帧时发 `I_REQ(0x08)`
  （`KVMUtil.sentIFrame`，500ms 节流）
- 分辨率变化（`resolutionCh`）会清空参考帧并请求 I 帧
- 抓包/录屏功能每 200 帧主动请求一次 I 帧

✅ 实测：收到的一帧 I 帧 `差分=0`，随后的无变化帧 `差分=1`。
`remoteX/Y = 0xFFFF` 表示远端光标隐藏。

---

## 7. 老算法路径（`isNewCompAlgorithm == false`）

`Base.isNewCompAlgorithm` 默认 **true**（`Base.java:660`），本机型走新算法。
老路径保留在代码里，用**另一种 RLE**（整帧、不分块、3-3-2 色）：

`RLEJPEGUtil.unZipData`（`RLEJPEGUtil.java:125-437`）—— **半字节共享** RLE：

- 读 1 字节颜色，再读 1 字节游程高半字节；若高半字节非 0，
  低半字节就是**下一个**游程长度（半字节复用）
- 高半字节为 0 时用 `& 0xC`（bit3..2）选长度宽度：
  `0` → 6 位、`0x4` → 10 位、`0x8` → 18 位、`0xC` → 22 位
- 输出 8 位像素，`DirectColorModel(8, 7, 56, 192)` → 3-3-2 色

---

## 8. 实测样本（一次完整会话）

800×600、DQT 档 7（画质 70）、I 帧，`packLenght = 5128`，25 个子包：

```
块#  0 @    1 zip=2  裸扫描 600B      ← 第 0 行文字
块#  1 @  604 zip=2  裸扫描 552B
...
块#  8 @ 4427 zip=2  裸扫描 114B
块#  9 @ 4544 zip=6  复制左邻块        ← 第 1 行开始全是复制
块# 12 @ 4547 zip=3  裸扫描 114B
...
块# 21 @ 4788 zip=5  复制上一行
...
块#129 @ 5012 zip=3  裸扫描 114B
块流结束于 offset 5129（缓冲长度 5129）✅ 完全吻合
块类型分布: {"2/0":10, "3/0":3, "6/0":21, "5/0":96}
```

---

## 9. 仍未验证的部分

| # | 项 | 说明 |
|---|---|---|
| 1 | **RLE 块（zipType 0/1）从未在实测中出现** | 本帧只出现 JPEG + 复制块。RLE 位的解码逻辑来自源码（📖），未跑过真实数据 |
| 2 | `colorBit` 各档位是否改变块类型选择 | 只验证了 `colorBit = 2` |
| 3 | `buf[11]` 字段语义 | 观察值恒为 `0xDC = 220`，与客户端硬编码的子包上限 220 一致 ⚠️ |
| 4 | zipType 4（空操作）从未出现 | 用途不明 |
| 5 | zipType 2 与 3 的区别 | 客户端代码里两者处理完全相同，差异不明 |
| 6 | 多刀片机型的行为 | 本设备只有 1 个刀片 |

---

## 10. DQT 画质控制

命令 `DQT_MODE_SET(0x27)`（`PackData.java:749-752`）：

```java
byte[] data = {39, 0, mode, type, 0};   // 第 2 字节硬编码 0（不是刀片号）
```

- `mode` = 档位；`type` = `2` 表示滑条拖动中，`1` 表示松开提交
- 实际上线值：**40, 50, 70, 80, 90, 100**（60 永不发出）
- 响应 `DQT_MODE(0x28)`：`Base.setDqtzSize(state / 10 - 1)`
- `JPEGData.setDqttags(DQT档 - 1)` → 选 `DQTZData` 里的量化表

✅ 实测：连接后 BMC 主动发 `0x28`，`payload[4] = 0x46 = 70`，
即默认画质 **70**（索引 6 → `_70` 表）。
与 `Base.currentDqtSize = 7`（默认）→ `dqttags = 7 - 1 = 6` 一致。
**所以实际默认档是 70，不是 `JPEGData.dqttags` 字段初值 4。**

| 档位（命令值） | `dqttags` | 表变量后缀 |
|---|---|---|
| 10 | 0 | `_10` |
| 20 | 1 | `_20` |
| 30 | 2 | `_30` |
| 40 | 3 | `_40` |
| 50 | 4 | `_50` |
| 60 | 5 | `_60` |
| **70（实测默认）** | **6** | **`_70`** |
| 80 | 7 | `_80` |
| 90 | 8 | `_90` |
| 100 | 9 | `_100` |

---

## 11. 帧率控制

命令 `FRAME_COMM(0x1C)`（`PackData.java:700-708`）：payload `{0x1C, frameNum}`。
客户端连接后发 **35**（`ClientSocketCommunity.java:448`）。

> ⚠️ 注意：因 TCP 写与断链存在竞态，本文档早期版本声称「实测抓到 0x1C」
> 并不成立 —— 那只是本地发送日志，不代表 BMC 收到。

视频开关：`kvmCmdvideoControl(64)` / `kvmCmdvideounControl(65)`，
payload `{cmd, 0}`（`PackData.java:734-742`）。
