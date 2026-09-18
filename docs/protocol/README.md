# 华为 iBMC 老机型 KVM 协议（逆向整理）

针对设备 `192.168.1.100`（Huawei 5288 V3，SN `SN0000000000`）生成的
JNLP `kvm.jnlp`（`com.kvm.KVMApplet`，JAR `vconsole*.jar`）的完整协议整理。

本文档基于**反编译源码静态分析**，并用**真实设备握手抓包**做了交叉验证。
所有结论都标注了证据等级：

| 标记 | 含义 |
|---|---|
| ✅ 已实测 | 在真实 BMC 上抓包验证过，字节级确认 |
| 📖 代码确认 | 反编译源码里写死的逻辑，无歧义 |
| ⚠️ 推断 | 由代码结构推测，未直接验证 |

**逆向依据**（本机已有）：
- 反编译源码：`<decompiled-vendor-sources>/`（CFR 0.152，227 个类）
- 原始 JAR：`<local-scratch>`
- 本次实测抓包工具：[`tools/kvm-capture.mjs`](tools/kvm-capture.mjs)

---

## TL;DR

1. **不是 VNC / RDP / IPMI SOL**，是华为私有协议，裸 TCP，无 TLS。
2. 两个通道：**KVM**（JNLP `port`，默认 2198）和**虚拟介质 VMM**（JNLP `vmmPort`，默认 8208）。
3. 两个方向**帧格式不一样**，这点最容易踩坑：
   - 客户端 → BMC：`FE F6 | len(payload+2) | codeKey(4B) | CRC16 | payload`
   - BMC → 客户端：`FE F6 00 | len(1B≤250) | payload`，**没有 CRC、没有 codeKey**
4. 密钥链：JNLP `decrykey`(32B 十六进制) 拆成 `user_key`/`user_iv`；
   套件协商后派生 `encodeKey`(24B)；连接后再由 BMC 下发 48 字节
   口令+salt 派生 **`kvm_key`(48B)**，它同时提供 KVM 数据密钥、键盘密钥和 IV。
5. 视频是**分块增量**格式：64×64 像素块，每块描述符 1 字节，块类型有
   **RLE（4 种变体）/ JPEG 裸扫描数据 / 复制上一块**。JPEG 块**不带 JPEG 头**，
   客户端用 10 张内置 DQT 表 + 固定 SOF/DHT **现场拼一个 JPEG 头**再解码。
6. 键盘就是 **USB HID Boot Keyboard 报文**（8 字节：修饰键 + 保留 + 6 个 Usage ID）。
7. **JNLP 里的会话参数会过期**：实测两个旧 JNLP 都能通过套件协商，
   但 `CONNECT_BLADE` 一律被拒（连接状态=3 并断链）。

---

## 文档索引

| 文件 | 内容 |
|---|---|
| [01-transport-and-frames.md](01-transport-and-frames.md) | 传输层、两个方向的帧格式、CRC 算法、流分帧状态机、BMC 校验行为实测 |
| [02-handshake-and-crypto.md](02-handshake-and-crypto.md) | 完整连接时序、密码套件协商、PBKDF2 密钥链 |
| [03-video-channel.md](03-video-channel.md) | 视频分块格式、RLE/JPEG 编码、色深与 DQT 质量 |
| [04-input-channel.md](04-input-channel.md) | 键盘 HID 报文、鼠标三种模式、USB HID 码表 |
| [05-virtual-media.md](05-virtual-media.md) | VMM 通道：12 字节头、认证、SCSI UFI/SFF-8020i |
| [06-command-reference.md](06-command-reference.md) | 双向操作码完整速查表 + 校验值 + 实测样本 |
| [07-live-verification.md](07-live-verification.md) | **实测验证记录与被更正的结论** |
| [tools/](tools/) | 抓包、离线解析、块流校验、渲染工具链 |

---

## 验证状态

**✅ 整条链路已端到端打通**：从 JNLP 到视频解码全部实测通过，
并**渲染出了远端服务器的真实画面**（800×600）：

```
No bootable device , please reboot system with manual operation.
_
```

具体地：130 个 64×64 块中 **130 个 JPEG 块全部解码成功（0 失败）**，
重组缓冲 5129 字节被**精确逐块消耗完（剩 0 字节）**。
这类结果不可能在格式理解错误的情况下出现。

**已实测的环节**：JNLP 参数解析、双向帧格式（含帧贴合验证）、
套件协商、PBKDF2 派生 `encodeKey` + 字节反序、`0x40` 解密与 `kvm_key` 派生、
子包重组与 `packLenght` 语义、帧头解析（宽/高/DQT/I帧/差分）、
块网格、块流推进、合成 JPEG 头、DQT 选表、复制块。

**未实测**：RLE 块（真实帧里没出现）、虚拟介质 VMM 通道、键鼠注入、
`colorBit` 其它档位、多刀片。

详见 [07-live-verification.md](07-live-verification.md)，其中也**逐条列出了
早期版本说错或说重了的地方**（例如「接收帧前两字节是 CRC」已被证伪）。

### 两个关键运行性约束

1. **JNLP 会话是一次性的。** 断开后再连必被拒（`CONNECT_STATE = 3`）。
   每次抓包都要重新下载 JNLP。
2. **客户端帧必须整帧一次 `write()`。** 实测把一帧拆成两次 write 后
   BMC 完全无应答（它不跨 read 重组）。此外 BMC **不校验** CRC 与 codeKey
   （至少对 `GET_SUITE` 如此），但**不要依赖 BMC 重组 TCP 分片**。

---

## 安全边界

- JNLP 里的 `verifyValue` / `verifyValueExt` / `decrykey` 等价于**会话凭证**，
  按机密处理，不要提交、不要贴日志。
- 本仓库的抓包工具只做握手和观察，**不发送**键盘、鼠标坐标、按键、开关机、
  虚拟介质写入命令。
- 浏览器扩展无法直接连裸 TCP：若要做 Web UI，必须
  「浏览器扩展 ⇄ 本机认证的原生代理 ⇄ BMC:2198」，不能把 BMC 端口暴露给网页。
