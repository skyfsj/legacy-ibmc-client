# 工具链

全部为**只读**工具：只做握手、查询、观察。
**不发送**键盘、鼠标坐标/按键、开关机、虚拟介质写入命令。

> ⚠️ **JNLP 会话是一次性的。** 每次运行抓包工具前都要重新下载 JNLP
> （浏览器里点一次「远程控制台」），否则 `CONNECT_BLADE` 会被拒（状态 3）。

## 工具一览

| 工具 | 作用 |
|---|---|
| `kvm-capture.mjs` | 最小握手探针：验证帧格式与套件协商，打印收发十六进制 |
| `kvm-live.mjs` | **完整抓包**：握手 + 派生 `kvm_key` + 把服务端原始流存盘 |
| `kvm-analyze.mjs` | 离线解析：解析帧、解密 `0x40`、派生 `kvm_key`、重组子包 |
| `kvm-blocks.mjs` | 走块流：逐块校验 `syclen`，验证是否精确消耗完缓冲 |
| `kvm-render.py` | 合成 JPEG 头并渲染出 PNG 画面（需 `Pillow`） |
| `kvm-falsify.mjs` | 逐字段篡改探针：测 BMC 校验哪些字段（CRC / codeKey / 长度 / 魔数） |
| `kvm-split.mjs` | 测 BMC 是否重组跨 TCP 分片的帧 |

## 标准流程

```bash
# 0) 浏览器登录 iBMC → 点「远程控制台」→ 拿到新 JNLP（一次性！）

# 1) 抓包（会存 <dir>/server.bin 和 <dir>/frames.json）
node tools/kvm-live.mjs ~/Downloads/kvm.jnlp /tmp/kvmlive 20000

# 2) 离线解析：派生 kvm_key、重组子包、导出各帧块流
node tools/kvm-analyze.mjs /tmp/kvmlive/server.bin ~/Downloads/kvm.jnlp /tmp/kvmanalyze

# 3) 走块流，校验字节是否精确消耗（关键正确性指标）
node tools/kvm-blocks.mjs /tmp/kvmanalyze/frame-2.bin

# 4) 渲染画面（第 4 个参数是 DQT 档位，通常 6 = 画质 70）
python3 tools/kvm-render.py /tmp/kvmanalyze/frame-2.bin \
        /tmp/kvmanalyze/frame-2.blocks.json /tmp/kvmanalyze/frame-2.png 6
```

`kvm-analyze.mjs` 会打印每一帧的：子包数、序号是否连续、声明的 `packLenght`、
实际数据字节数、分辨率、差分标志、DQT 档、I 帧标志、远端光标坐标。

## 正确的判定标准

看这三个指标，不要只看「有没有数据」：

1. **帧贴合**：`kvm-analyze` 报「完美贴合 ✅」—— 帧边界与长度字段一致。
2. **块流精确消耗**：`kvm-blocks` 报「走完 N/N 块，恰好消耗完」——
   N 应等于 `ceil(w/64) × ceil(h/64)`（800×600 → 130）。
3. **JPEG 块全部解码成功**：`kvm-render` 报「失败 0」——
   合成 JPEG 头正确才会 0 失败。

三者同时满足才说明格式理解正确。仅「收到字节」不构成验证。

## 依赖

- Node.js（无第三方包）
- Python 3 + `Pillow`（仅 `kvm-render.py` 需要）
