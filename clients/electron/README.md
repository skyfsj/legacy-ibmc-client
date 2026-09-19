# iBMC 远程控制台（原生客户端）

用**逆向出来的私有 KVM 协议**直连华为 iBMC，替代已废弃的 Java applet。
输入地址 + 账号密码即可直接进入远程界面。

跨平台（Electron：macOS / Windows / Linux），**无后端**——所有逻辑在本地进程内，
不需要部署任何服务。

---

## ⚠️ 为什么不是「纯网页」

**浏览器无法打开裸 TCP 连接。** 这是硬约束，不是实现选择：

| 方案 | 能否直连 BMC |
|---|---|
| 网页 + JavaScript | ❌ 浏览器没有任意 TCP socket API |
| 网页 + **WASM** | ❌ **WASM 自己没有 I/O 能力** —— 见下 |
| 网页 + WebSocket | ❌ BMC 的 2198 端口不跑 WebSocket |
| 网页 + WebRTC / WebTransport | ❌ BMC 不实现这些对端，且都不是裸 TCP |
| 浏览器扩展 | ❌ WebExtension 同样拿不到裸 TCP |
| **Chrome Direct Sockets + Isolated Web App** | ⚠️ 理论上可以，但有硬门槛，见下 |
| **桌面应用（Electron / Tauri / 原生）** | ✅ 有 socket API |

KVM 通道是 `BMC:2198` 上的**裸 TCP 私有协议**（视频 + 键鼠），
所以必须有一个能开 socket 的执行环境。

### 为什么 WASM 不解决问题

WASM 只是一套**指令集，本身没有任何 I/O 能力**。它要读写网络，只能调用宿主
（host）通过 import 显式提供的函数。在浏览器里，宿主能提供的就只有 JS 也
能拿到的那套 Web API —— 里面没有 socket。所以：

> **WASM 的能力上限 = JS 的能力上限。** 它不能绕过浏览器沙箱，
> 因为限制在**宿主**（浏览器），不在语言。

WASI 确实定义了 `sock_*` 系列接口，但**浏览器不实现 WASI sockets**。
WASI sockets 只在独立运行时（Wasmtime、WAMR、Node 的 WASI）里可用 ——
那已经是一个本机进程，也就是本方案在做的事。

（顺带：WebContainer 这类「浏览器里的 Node」也不行，它的网络走 Service Worker
代理，只支持 HTTP(S)，没有裸 TCP。）

### 真正存在的例外：Chrome Direct Sockets

浏览器原生的裸 TCP/UDP API 确实有，但**不是 WASM**，是 Chrome 的
**Direct Sockets API**（`TCPSocket` / `UDPSocket` / `TCPServerSocket`）。
在本机 Chrome 152 上的实测结果：

| 条件 | `typeof TCPSocket` | 能连上吗 |
|---|---|---|
| 普通页面，默认标志 | `undefined` | — |
| 普通页面 + `--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSockets` | `function` | ❌ 构造成功，但之后**整个页面立即卡死**（连预先注册的 `setInterval` 都不再触发） |
| **Isolated Web App**（`isolated-app://` 源） | `function` | 按权限模型可以，**未实测** |

也就是说：API 存在，但**只对 Isolated Web App 开放** —— 必须打包成
**签名的 Web Bundle**，通过企业策略或开发者模式安装。普通网页（哪怕是
localhost、哪怕开了 flag）都用不了。

用 IWA 的代价：**只支持 Chrome/Edge**（Safari 和 Firefox 都没有、也没有计划），
而且分发要签名 + 策略下发。相比之下 Electron 三平台都能跑、双击即装。

> 如果你就是想要「Chrome 里的原生应用」，IWA 路线可行：协议层是传输无关的，
> 把 `session.js` 里的 Node `net` 换成 `TCPSocket` 即可，
> 解码 / 输入 / 登录都能直接复用。但要先接受上面的分发门槛。

> **另一个可能更省事的选择 —— 已排除**：前端里有 `openway=html5` → `kvm.php?kvmway=1`
> 的分支，本以为固件可能自带 HTML5 控制台。**实测（2026-09-18）确认没有**：
> 登录后访问 `/bmc/pages/remote/kvm.php?kvmway=1` 仍然触发 JNLP 下载，
> 两个 kvmway 值返回的是同一个 JNLP。前端那个 html5 分支是死代码。
> 所以 **JNLP + 私有 KVM 协议是唯一路径**，本客户端就是必需的。

---

## 架构

```
┌─ Electron 主进程（Node）────────────────────────────┐
│  ibmc.js      HTTPS 登录 → 取 JNLP                 │
│  protocol.js  帧编解码 / CRC / PBKDF2 / AES        │
│  session.js   裸 TCP:2198、握手、子包重组、键鼠注入 │
└──────────────────── IPC ───────────────────────────┘
┌─ 渲染进程（Chromium）──────────────────────────────┐
│  decoder.js   64×64 块解码（RLE / JPEG / 复制块）   │
│  jpeg-tables.js  从反编译源码提取的合成 JPEG 头常量 │
│  app.js       画布显示 + 键鼠捕获                   │
└────────────────────────────────────────────────────┘
```

`src/main/` 里的协议代码与逆向文档
[`../huawei-ibmc-kvm-protocol/`](../huawei-ibmc-kvm-protocol/) 一一对应，
字节布局都由真实抓包验证过。

### 视频解码要点

BMC 把画面切成 **64×64 块**；每块 1 字节描述符：
`bits7..5` = 块大类，`bits4..2` = RLE 子类型。

- **JPEG 块**：BMC 只发**裸熵编码扫描数据**，JPEG 头（SOI/APP0、3 张 DQT、
  SOF 4:4:4、DHT/DRI/SOS）由客户端**用 10 档内置量化表现场合成**，
  然后交给 Chromium 的 JPEG 解码器。量化表从反编译源码里程序化提取
  （`tools/gen-jpeg-tables.py`），避免手抄出错。
- **复制块**（zipType 5/6）：直接复制上一行或左邻块 —— 这是增量刷新的主要手段。
  实测一个几乎全黑的 800×600 画面里 130 块中有 117 块是复制块。
- **块状态跨帧保留**，所以复制块能引用上一帧的内容。

---

## 登录流程

从 BMC 前端 `/bmc/resources/js/login.js` 逆出来的：

```
POST /bmc/php/processparameter.php
     check_pwd=<密码>&logtype=0&user_name=<用户>&func=DirectKVM&IsKvmApp=0
  → JSON，DirectKVM[0] == 0 表示直接拿到了 KVM 会话
  → 然后 GET /bmc/pages/remote/kvm.php?kvmway=0 取得 JNLP 会话描述符
```

前端里 `way` 的构造（`login.js`）是：

```js
var kvmway = "jre";
if (requestStr["redirect_type"] == "1") {
    functions = "DirectKVM";
    if (requestStr["openway"]) kvmway = requestStr["openway"];
}
var way = (kvmway == "html5") ? "?kvmway=1" : "?kvmway=0";
window.open("/bmc/pages/remote/kvm.php" + way, "_self");
```

默认（不带 `openway`）走 `?kvmway=0`。`?kvmway=1` 在本固件上返回同一个 JNLP，
**没有 HTML5 控制台**（已实测确认）。客户端会依次尝试几个候选 URL，
失败时把响应开头打印到日志，并提示改用 JNLP 文件方式。

**密码不落盘**：只存在内存里用于这一次登录；应用不写任何凭据文件。
注意这个 RPC 是**明文提交密码**（`check_pwd`），这也是原厂前端的行为——
所以**只在可信网络里用**。BMC 是自签证书，应用按原厂客户端的做法不校验它。

拿到 JNLP 后，`verifyValue` / `verifyValueExt` / `decrykey` 就是会话凭证，
后续握手完全按逆向结果走（PBKDF2 → `encodeKey` → `kvm_key` → AES 解帧）。

> **JNLP 会话是一次性的。** 断开后同一份 JNLP 不能复用（BMC 会回
> `CONNECT_STATE=3`）。本应用每次「连接」都会重新登录并取新的 JNLP，
> 所以正常使用不会碰到这个问题；但如果你想用「JNLP 文件连接」复用旧文件，
> 会遇到状态 3。

---

## 运行

```bash
npm install
npm start
```

然后填地址 / 用户名 / 密码，点「连接」。

> **安装 Electron 的坑**：Electron 的二进制要从 GitHub 下载，国内通常很慢或超时。
> 用镜像：
> ```bash
> ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ npm install
> ```
> 如果报 `Cannot find native binding ... @electron-internal/extract-zip`
> （npm 的可选依赖已知 bug），删掉 `node_modules` 和 `package-lock.json` 再装一次。

### 打包

```bash
npm run dist:mac      # macOS → dist-full/ibmc-kvm-full-mac-<arch>.zip
npm run dist:win      # Windows → dist-full/ibmc-kvm-full-win-x64.zip
npm run dist:linux    # Linux → dist-full/ibmc-kvm-full-linux-<arch>.tar.gz
npm run dist          # 当前平台
```

产物解压后自带 Chromium，不需要系统 webview，代价是解压后约 200 MB。

macOS 包用 `package.json` 里的 `"mac": { "identity": "-" }` 做 ad-hoc 签名：不需要证书，
下载后右键 →「打开」即可。不加签名的话签名状态是「未绑定」，用户会看到「已损坏，请移到废纸篓」，
只能靠 `xattr -dr com.apple.quarantine` 解隔离。

> 打包前删掉 `package-lock.json`：锁文件记录的是生成它的那个平台的可选依赖，而 Electron
> 自己的可选依赖（`@electron-internal/extract-zip`）正好是跨平台会出问题的那个，见上面的安装坑。
> 仓库因此不提交锁文件，CI 也用 `npm install` 而不是 `npm ci`。

### 验证（不需要登录、不需要 BMC）

```bash
npm test              # 协议层 + 解码器（Node）
npm run test:store    # 会话存储与密码加密（Electron，沙箱目录）
npm run test:gui      # Electron 里加载 UI 并自检渲染进程
npm run test:chromium # 把真实帧送进 Chromium 的解码路径
npm run test:all      # 以上全部
```

四个层次，全部拿**真实抓包**跑：

| 命令 | 验证内容 | 结果 |
|---|---|---|
| `npm run test:replay` | 14 项：CRC、客户端帧构造、接收帧解析、套件表、密钥派生、子包重组 | 14 通过 / 0 失败 |
| `npm run test:decoder` | `decoder.js` 在 Node 里跑真实帧（`jpeg-js` 解码 JPEG） | 5129/5129 字节、130/130 块 |
| `npm run test:store` | 会话增删改、**密码加密且磁盘无明文**、`resolvePassword` 契约、改密码覆盖 | 19 通过 / 0 失败 |
| `npm run test:gui` | Electron 真实加载 UI，确认 preload 桥与整个 ESM 模块图无错 | 通过 |
| `npm run test:chromium` | 真实帧走**Chromium 自带 JPEG 解码器**（即发布路径） | 4/4 项通过 |

> `test:store` 会在系统临时目录里建沙箱 profile —— 它一开始会清空会话，
> 绝不能跑在真实 profile 上。这点在测试里有显式注释和 `app.setPath('userData', …)`。

`test:replay` 的期望值全部来自实测，例如心跳 `{09 00}` 的 CRC 必须是
`0xba98`，`buildFrame` 必须重建出与抓包**逐字节相同**的帧 —— 能挡住协议回归。

`test:chromium` 的输出：

```
✅ 块流精确消耗: 5129/5129
✅ 块数正确: 130/130
✅ JPEG 块无失败: 13 个, 失败 0
✅ 画面非全黑: 99.56%
[replaytest] 全部通过（Chromium JPEG 解码器）
```

三种彼此独立的 JPEG 解码器（Python/PIL、jpeg-js、Chromium）对同一帧给出
**完全一致**的统计（99.56% 非黑，逐字节差异 0.077%，纯属取整差异），
说明解码器与逆向阶段已验证的那条路径等价。

### 备选：用 JNLP 文件连接

如果登录接口在你的固件版本上不一样，点「用 JNLP 文件连接…」选一个从
Web UI 下载的 `.jnlp` 即可绕过登录，直接走协议层。
（每个 JNLP 只能用一次。）

---

## 会话管理器

启动后是机器列表 + **空白的新建连接表单**（不会自动进入某台机器的编辑态）。

- **左侧**列出已保存的机器。**单击 = 选中并编辑**；`▶` 或**双击 = 连接**；
  `✕` = 删除。
- **右侧**填：名称（可留空，默认用地址）、地址、HTTPS 端口、用户名、密码、色深。
- 新建表单会**用上次连接过的机器预填**地址/端口/用户名，省得重打——
  但仍是「新建连接」状态，不会误改到那台机器。
- **名称可以随时改**，改完点「保存修改」（只在编辑已保存的机器时出现）。
- 主按钮就是**「连接」**。

> 单击行**不会**直接连接：JNLP 会话是一次性的，误点一次就白白消耗一个会话，
> 而且你会没法只是查看某台机器的设置。

### 连接与保存是分开的

**连接不会自动保存任何东西。** 只有当你连的是一台**没保存过**的机器时，
连接成功后会弹一个模态问你：

```
保存这台机器？
192.168.1.100 — root@192.168.1.100:443
[✓] 记住密码
不保存也可以继续使用本次连接。
        [保存]  [不保存，仅本次连接]
```

- 选「保存」→ 存入列表；勾了「记住密码」才把密码交给系统钥匙串。
- 选「不保存」→ 什么都不写，本次连接照常可用，下次要重新填。
- 连**已保存**的机器不会弹窗；此时表单里的改动（改名、改端口…）会静默保存。

> 「记住密码」= 用 **Electron `safeStorage`（macOS 走系统钥匙串）加密**后存到
> `~/Library/Application Support/huawei-ibmc-kvm-client/sessions.json`。
> 不勾选则完全不保存密码。

安全上做了三件事：

1. 密码字段**只存在于主进程**——从钥匙串取出的密码不会经 IPC 交给渲染进程，
   渲染进程只知道「有没有存过密码」。
2. 如果系统提供不了加密（`safeStorage.isEncryptionAvailable()` 为 false），
   应用会**拒绝保存**而不是退回明文。
3. 有专门的测试断言**磁盘文件里不出现明文密码**，以及对
   `resolvePassword` 的字段名契约测试（`npm run test:store`，15 项）。

会话文件权限是 `0600`，且用「写临时文件再 rename」的方式落盘，
崩溃不会留下半截文件。

---

## 操作说明

| 操作 | 说明 |
|---|---|
| 键盘 | 连上后**直接可用**，不需要先点画面；`Ctrl+Shift+Esc` 之类不受影响的操作会被拦截转发给远端 |
| 鼠标 | 绝对坐标模式（连上后请求 `0x24`，按远端应答决定），坐标归一化到 0..3000 |
| 滚轮 | 累加超过阈值后按格发送 |
| 缩放 | 工具栏「缩放」：**适应窗口**（默认，等比缩放）/ 50% / 100% / 150% / 200% |
| Ctrl+Alt+Del | 工具栏按钮 |
| 画质 | 工具栏滑块，**会记住**（全局 + 每台机器各存一份），默认 **70**（= 固件自身默认，也是唯一验证过量化表映射的档位）。拖动发 `0x27 type=2`，松手发 `type=1` 提交。日志会打印每个帧头里的 DQT 索引，可据此判断设置是否真的生效 |
| 刷新画面 | 发 `I_REQ` 请求关键帧 |
| 统计 / 日志 | 工具栏按钮，**弹模态窗口**（不再占据底部，避免误点） |
| 调试信息 | 默认**隐藏**。需要时点工具栏「调试」，会显示输入计数与最近收发的包（节流到 ~10Hz）；开关状态会记住 |

窗口大小变化时，适应窗口模式会等比重新缩放；画布内部始终按远端原生分辨率
渲染（`image-rendering: pixelated`），所以放大不会糊。

失焦或页面隐藏时会**自动释放所有按键**，避免远端按键卡住。

> 排查输入问题时再打开「调试」：它能区分「事件没捕获到」（计数不涨）和
> 「发出去了但 BMC 不认」（计数在涨但远端无反应）。
> 同样的数据在「统计」模态里也能看到，不必常驻工具栏。

---

## 已知限制

1. **登录流程没有用真实凭据跑通过。** 我没有你的密码，而故意用错密码测试会有
   触发账号锁定的风险（前端里有 `AuthFailLockTime`），所以只验证到：
   - 端点真实存在（`/bmc/php/processparameter.php` 返回 403 而不是 404）；
   - 用**不存在的用户名**走完整登录代码路径，BMC 正确解析并回
     `DirectKVM 返回码 130` —— 说明 URL、Content-Type、参数名、响应解析都对；
   - 顺带确认了**必须先 GET `/login.html` 拿到 cookie**，否则直接 POST 会被 403。

   首次用真实账号连接时请留意日志里 `GET /bmc/pages/remote/kvm.php` 的返回：
   如果它不是 JNLP 而是 HTML，说明你的固件用别的方式下发 JNLP，
   需要按实际返回调整 `ibmc.js` 里的 `findJnlpUrl`。

2. **RLE 块没有实测样本。** 实测帧里只出现了 JPEG 块和复制块。
   RLE 解码（4 种变体）是照反编译源码实现的，未经真实数据验证 ——
   如果画面出现彩色花屏，这里是第一嫌疑。
3. **差分帧被跳过**，与厂商客户端一致（新算法路径下
   `isDispDiff() && !resolutionCh && !firstJudge → continue`）。
   差异是靠复制块表达的。工具栏「统计」里能看到跳过计数。
4. **只支持单刀片**（本机型 `bladesize=1`）。
5. **虚拟介质（挂 ISO/IMG）未实现** —— 协议已整理在
   [05-virtual-media.md](../huawei-ibmc-kvm-protocol/05-virtual-media.md)，
   但未实测。
6. 未做重连/断线恢复。
7. 登录接口只在这一个固件版本上确认过（`resource_id=15557332052019`）。
8. `test/decoder.test.mjs` 用 `jpeg-js` 代替 Chromium 的 JPEG 解码器；
   两者在本帧上一致到 0.077%，但真实客户端始终用 Chromium 解码。

---

## 目录

```
src/main/ibmc.js        登录 + JNLP 获取
src/main/protocol.js    帧格式 / CRC / 密钥派生
src/main/session.js     TCP 会话、握手、重组、键鼠
src/main/main.js        Electron 主进程 + IPC
src/preload.js          contextBridge 桥
src/renderer/decoder.js 块解码器
src/renderer/hid.js     按键 → USB HID 映射
src/renderer/app.js     UI / 画布 / 输入捕获
test/replay.test.js     真实抓包回归测试（协议层）
test/decoder.test.mjs   真实帧解码器测试（Node + jpeg-js）
tools/gen-jpeg-tables.py 从反编译源码提取 JPEG 常量
```

---

## 验证状态小结

| 环节 | 状态 |
|---|---|
| 帧格式 / CRC / 密钥派生 / 子包重组 | ✅ 实测验证（真实抓包回放） |
| 视频块解码（JPEG 块、复制块、合成 JPEG 头、DQT 选表） | ✅ 三种解码器交叉验证 |
| 登录接口的请求格式与响应解析 | ✅ 走到 BMC 并拿到 `DirectKVM 返回码 130` |
| GUI 启动与模块加载 | ✅ Electron 自检通过 |
| **用真实账号完整走通一次** | ❌ 未做（没有你的密码；也不想冒险触发账号锁定） |
| RLE 块 | ❌ 无实测样本 |
| 键鼠注入的远端效果 | ❌ 未验证（没敢在活跃会话上注入按键） |
| 虚拟介质 | ❌ 未实现 |
