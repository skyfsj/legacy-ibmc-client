# iBMC 远程控制台（Go + 系统 webview）

用**逆向出的私有 KVM 协议**直连华为 iBMC 的桌面客户端。这一版把协议层放在 Go 里，
界面交给**操作系统自带的 webview**，因此不再自带一整个 Chromium。

## 为什么有这一版

上一版用 Electron，功能可用但体积/内存代价明显。实测对比：

| | Electron | **本版（Go + 系统 webview）** | 差异 |
|---|---|---|---|
| 打包体积 | 332 MB | **6.6 MB** | **约 50×** 更小 |
| 运行时内存 | 449.7 MB | **204.0 MB** | 约 2.2× 更小 |
| 依赖的浏览器引擎 | 自带 Chromium（322 MB） | 系统 WKWebView | 不打包 |
| 跨平台 | ✅ | ✅（macOS 用 WKWebView；Windows/Linux 换 webview 后端即可） | — |

**要诚实说明**：系统 webview 不是免费的。WebKit 仍会拉起 3 个 XPC 进程：

```
app 进程      102.2 MB
WebKit GPU     37.8 MB
WebKit WebContent 45.4 MB
WebKit Networking 18.6 MB
------------------------
合计          204.0 MB
```

省下的大头是**磁盘**（不再自带 Chromium），内存只降到约 45%。

## 架构

```
┌─ Go 进程 ──────────────────────────────────────────┐
│  internal/kvm/     帧编解码、CRC、PBKDF2、AES、重组 │
│  internal/vmm/     虚拟介质通道（ISO/IMG 挂载 + SCSI）│
│  internal/ibmc/    HTTPS 登录 + 取 JNLP            │
│  internal/store/   会话持久化 + 密码加密（钥匙串）  │
│  main.go           系统 webview + JS 绑定           │
│  net/http          进程内 loopback 静态服务         │
└─────────────── webview 绑定 / Eval ────────────────┘
┌─ 系统 webview ─────────────────────────────────────┐
│  decoder.js  64×64 块解码（RLE / JPEG / 复制块）    │
│  app.js      会话管理器 / 画面 / 输入 / 缩放       │
│  bridge.js   用 Go 绑定实现 window.kvm 接口        │
└────────────────────────────────────────────────────┘
```

关于「无后端」：web 资源由**进程内的 loopback 静态服务**提供（随机端口、仅监听
127.0.0.1、随窗口启停）。这不是需要部署的后端，只是为了让 webview 拿到一个正常
的 origin —— `file://` origin 下 ES module 与 localStorage 都受限。

渲染层（`web/decoder.js`、`web/app.js`、`web/hid.js`、`web/jpeg-tables.js`）与
Electron 版**是同一份代码**，只把传输层换成了 `bridge.js`。

## 虚拟介质（VMM）

`internal/vmm` 是 VMM 通道的移植（源码依据：`com/huawei/vm/console/**` 与
`com/kvm/VirtualMedia.java`，见 `docs/protocol/05-virtual-media.md`）。协议细节
（12 字节帧头、CERTIFY_ID、PBKDF2 56 字节切分、AES-CBC 数据面、SFF-8020i / UFI
命令集）都是逐行对照 Java 的，**尚未在实机上验证过**。

```go
// 1) KVM 通道引导：取 code key + 端口（也可用 JNLPOptions 走旧路径）
b, err := vmm.Negotiate(kvmSession, kvmSession.KvmKey(), compress, 3*time.Second)
opts := b.Options(bmcHost, kvmSession.Status(), false)

// 2) 挂载镜像（第一次 Mount 负责建链与认证；第二个设备复用同一 socket）
s := vmm.New(opts)
s.Log = emitLog            // 可选钩子：OnState / OnError / OnClosed
err = s.MountISO("/path/to/install.iso")
err = s.MountFloppy("/path/to/disk.img", true) // 第二参数 = 写保护

// 3) 卸载
err = s.Detach(vmm.CloseTypeFloppy) // 只卸软驱，连接保留
err = s.Close()                     // 关闭全部
```

要点：

- 软驱镜像必须**恰好** 1474560 字节（2880 × 512），否则挂载报错 335。
- 光驱按 2048 字节/扇区读 ISO；镜像以**只读**方式打开。
- `vmm_compress`（默认 1）控制数据面是否加密；错误码沿用 Java 的编号
  （121/122/123/401/335…），`*vmm.Error` 带 `Message()` 中文文案。
- 客户端每 10s 发心跳，但**40s 内服务器必须有流量**，否则主动断链（Java 原逻辑）。

## 没有系统 webview 时怎么办

**先说清楚各平台的实际情况**：

| 平台 | 系统 webview | 现实风险 |
|---|---|---|
| **macOS** | WKWebView（`WebKit.framework`） | **不存在缺失** —— 随系统安装 |
| **Windows** | WebView2（基于 Edge） | Win10 1803+ / Win11 自带；**老旧或精简版可能缺** |
| **Linux** | WebKitGTK | **通常需要单独装**（`libwebkit2gtk-4.1-0`） |

所以缺失是 Windows/Linux 的真实场景。程序按**三级降级**处理：

```
--mode auto（默认）
  1. 系统 webview 可用 → 用它（体积/内存最优）
  2. 不可用 → 找一个已安装的 Chromium 系浏览器，
             以 `--app=` 模式打开（无地址栏/标签页）
             候选：Chrome / Edge / Brave / Chromium / Vivaldi / Arc
             并使用独立 profile 目录，不干扰你平时的浏览器
  3. 都没有 → 用系统默认浏览器兜底；仍不行则给出**安装指引**
```

第 2、3 级下，界面通过**同一个 loopback 服务**工作：操作走 `POST /api/call`，
事件走 `GET /api/events`（SSE）。**与 webview 模式共用同一份 Go 处理器**，
所以两条路径行为一致，`app.js` / `decoder.js` 一行都不用改。

`bridge.js` 会自动探测：有 Go 绑定就用绑定，没有就切 HTTP。

```bash
./ibmc-kvm --mode auto      # 默认：优先系统 webview，失败自动降级
./ibmc-kvm --mode webview   # 强制系统 webview，不可用则报错退出
./ibmc-kvm --mode browser   # 强制用浏览器（用于验证降级路径）
```

### 关于「自动装一个最小的」

**没有做静默自动安装**，这是有意的：下载并安装运行时是重量级、且会触碰系统权限的
动作，不该由程序替你决定。现在的做法是检测 → 用已有的 → 都没有时给出官方安装指引：

- **Windows**：装 Microsoft Edge WebView2 运行时（约 2MB 的官方引导程序），
  装完即可用内置 webview 模式，连浏览器都不需要
- **Linux**：`apt install libwebkit2gtk-4.1-0`
- 或者：装任意一个 Chromium 系浏览器，程序会以 app 模式使用它

> 另一种「最小」是内置一个非 Chromium 的小引擎（Servo / Ultralight / Sciter），
> 但它们要么不成熟、要么是商业授权，且会重新引入「自带引擎」的维护与安全问题。

## 构建与运行

```bash
# 依赖下载走镜像（proxy.golang.org 在部分网络下会超时）
export GOPROXY=https://goproxy.cn,direct

go build -ldflags="-s -w" -o ibmc-kvm .
./ibmc-kvm
```

打包成 macOS .app（约 6.6 MB）：

```bash
APP="iBMC 远程控制台.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp ibmc-kvm "$APP/Contents/MacOS/"
cp -R web "$APP/Contents/Resources/"
# 再加一个 Info.plist（CFBundleExecutable=ibmc-kvm）
```

## 测试

```bash
export GOPROXY=https://goproxy.cn,direct
go build ./... && go vet ./...
go test -count=1 ./...          # 52 项断言
go test -race ./...
```

测试全部用**真实抓包**做基准（`../huawei-ibmc-kvm-protocol/evidence/`），
期望值是逆向阶段实测到的字节，例如：

- `crc16({09 00}) == 0xba98`、`crc16({42 00}) == 0x6bae`
- `BuildFrame(1000000002, {09 00})` 的十六进制必须是 `fef600043b9aca02ba980900`
- 5946 字节的服务端流必须解析出 **38 帧并精确铺满**
- 真实帧头必须是 800×600 / DQT 索引 7 / 非 I 帧 / `remoteX/Y = 0xffff` / `packLenght = 5128`
- `frame-2.bin` 的块流必须是 **130 块、恰好消耗 5129 字节**

这些断言在移植时被 mutation 验证过（改 CRC 多项式、改 `/64` 网格、去掉 `Reverse4`
都会让测试失败），所以它们是真的能挡住回归。

另有三个**可选**的实机测试（默认跳过）：

```bash
# 真实 BMC 的登录链路（用不存在的用户名，避免触发账号锁定计数）
HUAWEI_IBMC_KVM_TEST_LIVE=192.168.1.100 go test -run TestLiveLogin ./internal/ibmc/ -v

# 真实系统钥匙串读写
HUAWEI_IBMC_KVM_TEST_KEYCHAIN=1 go test -run TestSecurityKeyring ./internal/store/
```

## 已验证 / 未验证

| 环节 | 状态 |
|---|---|
| 协议帧格式、CRC、密钥派生、子包重组 | ✅ 真实抓包基准测试 |
| 块解码（JPEG / 复制块 / 合成头 / DQT 选表） | ✅ 130/130 块、5129/5129 字节 |
| 对真实 BMC 的原生 TCP 握手 | ✅ 实测拿到套件表 |
| 对真实 BMC 的 HTTPS 登录链路 | ✅ 实测（不存在的用户返回码 130） |
| webview 加载 + Go↔JS 绑定 | ✅ `--selftest` |
| **用真实账号完整走通一次（出画面）** | ❌ 未做（没有密码） |
| RLE 块 | ❌ 无实测样本（照源码实现） |
| 键鼠注入的远端效果 | ❌ 未验证 |

## 与 Electron 版共用配置（含密码）

两个版本使用**同一个配置目录和同一个加密方案**：

```
~/Library/Application Support/huawei-ibmc-kvm-client/sessions.json
```

- **机器列表共享** —— 一边添加的机器，另一边直接可见。
- **密码也共享** —— 在 Electron 版保存的密码，本版能直接解密使用，反之亦然。

共用靠的是双方都使用 **Chromium / Electron `safeStorage` 的格式与密钥**：

```
blob = "v10" | AES-128-CBC( PKCS#7 明文 )        # 无独立 IV
IV   = 16 个空格 (0x20)
key  = PBKDF2-HMAC-SHA1(钥匙串口令, "saltysalt", 1003, 16)
钥匙串条目: service "<app> Safe Storage", account "<app> Key"
```

这个格式不是猜的——先让 Electron 加密已知串、再反推验证，并用一个
**与实现无关的 openssl 参考向量**钉住字节布局（`TestOSCryptInteropVector`）。
另外有测试直接解开真实保存的密码（`TestDecryptsElectronSavedPassword`）。

> **首次会弹一次钥匙串授权**：macOS 会对「另一个程序要读取这条钥匙串项」征求同意。
> 选「始终允许」即可永久生效；不点则读取会在 10 秒后超时并给出明确提示。

### 关于密钥归属

本版**不会创建也不会改写**那条钥匙串项 —— 它属于 Electron 的 safeStorage，
改写会让 Electron 已保存的所有密码失效。所以如果钥匙串里还没有该条目，
本版会明确报「请先用 Electron 版保存一次密码以创建它」，而不是自己造一把。

## 与 Electron 版的关系

两个版本并存，共用同一套逆向文档与渲染层代码：

- [`../huawei-ibmc-kvm-protocol/`](../huawei-ibmc-kvm-protocol/) —— 协议规范与实测记录
- [`../huawei-ibmc-kvm-client/`](../huawei-ibmc-kvm-client/) —— Electron 版（功能更全：跨平台打包、更多 UI 打磨）

需要**更小体积**就用本版；需要**立刻能跑的多平台打包**就用 Electron 版。
