# 04 — 输入通道（键盘 / 鼠标）

命令：`KEY_PACK(0x03)` 键盘、`MOUSE_PACK(0x05)` 鼠标。
两者都走**刀片级 codeKey**（`getImagePaneCodeKey(bladeNo)`），payload 第 2 字节是刀片号。

两种编码形态，由 `compress` 决定（`PackData.keyDataProc` / `mousePack`）：

| `compress` | 形态 | 键盘 payload | 鼠标 payload |
|---|---|---|---|
| 0 | 明文 | 10 字节 | 6 或 8 字节 |
| 1（本机型） | AES 加密 | 18 字节 | 18 字节 |

---

## 1. 键盘

### 1.1 载荷结构 —— 就是 USB HID Boot Keyboard 报文

`PackData.keyData` 是 `byte[8]`（`PackData.java:19`），布局与
USB HID Boot Protocol 的 8 字节输入报文**完全一致**：

| 索引 | 含义 |
|---|---|
| `keyData[0]` | **修饰键位图**（见 §1.2） |
| `keyData[1]` | 保留，**恒为 0**（全代码库只在 `PackData.java:533` 显式写过一次 `= 0`） |
| `keyData[2..7]` | 最多 6 个**键码**，每个是 USB HID Usage ID（Usage Page 0x07） |

发送（`PackData.java:613-636`）：
```java
for (int i = 2; i < 8; ++i) {
    if (this.keyData[i] != 0) continue;
    KVMUtil.intToByte(temp, 0, KVMUtil.translateToUSBCode(e));
    this.keyData[i] = temp[0];      // 取低字节
    break;
}
```
释放（`PackData.java:660-678`）：在槽 2..7 里找到值相等的槽清零。

> **实践怪癖**：`KeyHandler.keyPressed`（`KeyHandler.java:112-116`）在每次发送后
> 把槽 2..7 全部清零：
> ```java
> keyData = this.imagePane.getPack().getKeyData();
> for (i = 2; i < keyData.length; ++i) keyData[i] = 0;
> this.imagePane.getPack().setKeyData(keyData);
> ```
> 所以这个客户端**实际每次只发一个非修饰键**（总在槽 2），
> 修饰键组合只能靠 `keyData[0]` 表达。多键同时按下的场景（比如按住 A 再按 B）
> 不走这条路径 —— 组合键有专门的命令，见 §1.4。

### 1.2 修饰键位图（`PackData.virtualKey`，`PackData.java:96-119`）

```java
public static int virtualKey(KeyEvent e) {
    int location = 0, keyState = 0;
    location = e.getKeyLocation();
    if (65406 == e.getKeyCode()) { keyState |= 0x40; }              // VK_ALT_GRAPH
    if (e.isControlDown()) { keyState = location == 3 ? (keyState |= 0x10) : (keyState |= 1); }
    if (e.isShiftDown())   { keyState = location == 3 ? (keyState |= 0x20) : (keyState |= 2); }
    if (e.isAltDown()) {
        if (location == 3 && KVMUtil.isWindowsOS()) { keyState &= 0xEE; }
        keyState = location == 3 || location == 1 && !KVMUtil.isMacOS()
                 ? (keyState |= 0x40) : (keyState |= 4);
    }
    if (e.isMetaDown() || 524 == e.getKeyCode()) {
        keyState = location == 3 ? (keyState |= 0x80) : (keyState |= 8);
    }
    return keyState;
}
```

`KeyEvent.getKeyLocation()`：`1` = STANDARD，`2` = LEFT，`3` = RIGHT，`4` = NUMPAD。

| bit | 值 | 含义 |
|---|---|---|
| 0 | `0x01` | 左 Ctrl |
| 1 | `0x02` | 左 Shift |
| 2 | `0x04` | 左 Alt |
| 3 | `0x08` | 左 GUI / Meta / Cmd / Win |
| 4 | `0x10` | 右 Ctrl |
| 5 | `0x20` | 右 Shift |
| 6 | `0x40` | 右 Alt（也用于 AltGr） |
| 7 | `0x80` | 右 GUI |

关键行为：

- **Ctrl / Shift**：`location == 3`（RIGHT）走高位（`0x10`/`0x20`），否则走低位。
- **AltGr（VK_ALT_GRAPH = 65406）**：无条件先置 `0x40`。
- **Alt 的 Windows 特殊处理**：Windows 把 AltGr 上报为「Ctrl + Alt，位置 RIGHT」，
  所以代码先 `keyState &= 0xEE` 清掉两个 Ctrl 位，再置 `0x40`。
- **STANDARD 位置的 Alt**：非 Mac 也映射成 `0x40`（右 Alt）；Mac 上映射成 `0x04`。
- **Meta**：`isMetaDown()` 或 `VK_WINDOWS(524)`。
- **Mac 特例**：`keyPressedPack` 在 Mac 上**每次按键都重算修饰字节**
  （`PackData.java:621-624`），非 Mac 只在按键本身是修饰键时才重算。
- 已知小瑕疵：`keyReleasedPack` 的判断列表（`PackData.java:664`）**漏了 524**，
  所以松开 Win 键时 meta 位不会被清除。

### 1.3 完整 USB HID 码表

`KVMUtil.keyCode`（`KVMUtil.java:93`）—— Java `VK_*` → USB HID Usage ID：

```
VK   VK 名称        USB   hex   HID 用途
 10  ENTER           40   0x28  Enter
  8  BACK_SPACE      42   0x2A  Backspace
  9  TAB             43   0x2B  Tab
  3  CANCEL         155   0x9B  小键盘 ,
 12  CLEAR          156   0x9C  小键盘 =
 16  SHIFT          225   0xE1  左 Shift   （右 Shift 用修饰位 0x20 表达）
 17  CONTROL        224   0xE0  左 Ctrl    （右 Ctrl 用修饰位 0x10）
 18  ALT            226   0xE2  左 Alt     （右 Alt 用修饰位 0x40）
 19  PAUSE           72   0x48  Pause
 20  CAPS_LOCK       57   0x39  Caps Lock
 27  ESCAPE          41   0x29  Esc
 32  SPACE           44   0x2C  空格
 33  PAGE_UP         75   0x4B  PgUp
 34  PAGE_DOWN       78   0x4E  PgDn
 35  END             77   0x4D  End
 36  HOME            74   0x4A  Home
 37  LEFT            80   0x50  左方向
 38  UP              82   0x52  上方向
 39  RIGHT           79   0x4F  右方向
 40  DOWN            81   0x51  下方向
 44  COMMA           54   0x36  , <
 45  MINUS           45   0x2D  - _
 46  PERIOD          55   0x37  . >
 47  SLASH           56   0x38  / ?
 48  '0'             39   0x27  0 )
 49  '1'             30   0x1E  1 !
 50  '2'             31   0x1F  2 @
 51  '3'             32   0x20  3 #
 52  '4'             33   0x21  4 $
 53  '5'             34   0x22  5 %
 54  '6'             35   0x23  6 ^
 55  '7'             36   0x24  7 &
 56  '8'             37   0x25  8 *
 57  '9'             38   0x26  9 (
192  BACK_QUOTE      53   0x35  ` ~
 59  SEMICOLON       51   0x33  ; :
222  QUOTE           52   0x34  ' "
 61  EQUALS          46   0x2E  = +
 65..90  A..Z     4..29  0x04..0x1D  a..z
                                        (A=4 B=5 C=6 D=7 E=8 F=9 G=10 H=11 I=12 J=13
                                         K=14 L=15 M=16 N=17 O=18 P=19 Q=20 R=21 S=22 T=23
                                         U=24 V=25 W=26 X=27 Y=28 Z=29)
 96  NUMPAD0         98   0x62  小键盘 0
 97  NUMPAD1         89   0x59  小键盘 1
 98  NUMPAD2         90   0x5A  小键盘 2
 99  NUMPAD3         91   0x5B  小键盘 3
100  NUMPAD4         92   0x5C  小键盘 4
101  NUMPAD5         93   0x5D  小键盘 5
102  NUMPAD6         94   0x5E  小键盘 6
103  NUMPAD7         95   0x5F  小键盘 7
104  NUMPAD8         96   0x60  小键盘 8
105  NUMPAD9         97   0x61  小键盘 9
106  MULTIPLY        85   0x55  小键盘 *
107  ADD             87   0x57  小键盘 +
109  SUBTRACT        86   0x56  小键盘 -
110  DECIMAL         99   0x63  小键盘 .
111  DIVIDE          84   0x54  小键盘 /
127  DELETE          76   0x4C  Delete
144  NUM_LOCK        83   0x53  Num Lock
145  SCROLL_LOCK     71   0x47  Scroll Lock
112..123  F1..F12  58..69  0x3A..0x45
                              (F1=58 F2=59 F3=60 F4=61 F5=62 F6=63 F7=64 F8=65
                               F9=66 F10=67 F11=68 F12=69)
154  PRINTSCREEN     70   0x46  PrintScreen
155  INSERT          73   0x49  Insert
 91  OPEN_BRACKET    47   0x2F  [ {
 92  BACK_SLASH      49   0x31  \ |
 93  CLOSE_BRACKET   48   0x30  ] }
525  CONTEXT_MENU   101   0x65  Application / Menu
263  (JVM 专有)     138   0x8A  国际键 4/5
243  (JVM 专有)      53   0x35  ` ~（回退）
244  (JVM 专有)      53   0x35  ` ~（回退）
240  (JVM 专有)      57   0x39  Caps Lock（回退）
242  (JVM 专有)     136   0x88  国际键 2
245  (JVM 专有)     136   0x88  国际键 2
 28  CONVERT        138   0x8A  国际键 4（Henkan 变换）
 29  NONCONVERT     139   0x8B  国际键 5（Muhenkan 无变换）
```

**小键盘处理**：`javaCodeToUSB` 会先把 NUMPAD 位置的键换算成
「NumLock 打开」时的等效 VK（`numKey`，`KVMUtil.java:301-358`），
再查表：`VK_INSERT(155)→96`、`VK_END(35)→97`、`VK_DOWN(40/225)→98`、
`VK_PGDN(34)→99`、`VK_LEFT(37/226)→100`、`VK_CLEAR(12/65368)→101`、
`VK_RIGHT(39/227)→102`、`VK_HOME(36)→103`、`VK_UP(38/224)→104`、
`VK_PGUP(33)→105`、`VK_DELETE(127)→110`。

**日语键盘**用 `KVMUtil.keyCodeforJapan`（`KVMUtil.java:94`），与上表的差异：

- 移除：`{12,156}`、`{192,53}`、`{222,52}`、`{92,49}`
- 改：`{91,47}` → `{91,48}`、`{93,48}` → `{93,49}`（`[`/`]`/`\` 三键按 JIS 轮换）
- 新增：`{512,47}`、`{514,46}`、`{513,52}`
- 另有两处硬编码（`KVMUtil.java:292-295`）：
  `keyValue == 92` → `e.getKeyChar()=='_' ? 135 : 137`；
  `keyValue == 48 && keyChar == '~'` → 返回 0（丢弃）

**法语布局**（`Base.keyboardLayout == 3`）**复用英语表** —— 代码里只有
`== 2`（日语）走不同分支。

### 1.4 明文 vs 加密载荷

`PackData.keyDataProc`（`PackData.java:384-393`）：

```java
private int keyDataProc(int bladeNo, byte[] key, byte[] data) {
    byte[] keyEnData = new byte[16];
    if (((BladeThread) ... get(String.valueOf(bladeNo))).isNew()) {
        this.encry(key, keyEnData, 8, bladeNo);
        System.arraycopy(keyEnData, 0, data, 2, 16);
        return 18;
    }
    System.arraycopy(key, 0, data, 2, 8);
    return 10;
}
```

`data[0] = 3`（KEY_PACK），`data[1] = bladeNo`。故：

| 形态 | payload | 线长 |
|---|---|---|
| 明文 | `03 | blade | k0..k7`（10 字节） | 20 |
| 加密 | `03 | blade | <16 字节 AES>`（18 字节） | 28 |

**加密用的密钥**（`PackData.encry`，`PackData.java:759-778`）：

```java
if (Base.getCompress() == 0) {
    temDes = AESHandler.encry(src, keyCode, 8);                    // 数据密钥 = codeKey
} else {
    temDes = AESHandler.secure_encry(src, Base.getKvm_key(), 8);   // 数据密钥 = kvm_key[16..31]
}
```

- `compress == 0`：`AESHandler.encry(src, codeKey, 8)` —— key = `codeKey`(4B) + 12 字节常量，
  IV = 全 0（见 02 章 §3.3）
- `compress == 1`（本机型）：`AESHandler.secure_encry(src, kvm_key, 8)` ——
  **key = `kvm_key[16..31]`，IV = `kvm_key[32..47]`**，明文零填充到 16 字节
- `isNew` 是 `BladeThread` 的字段，默认 `true`（`BladeThread.java:42`）

> ⚠️ `clearKey`（`PackData.java:538-552`）把加密结果又写了一遍到
> `bladeThread.keyEnData`，而该字段全代码库无人读取 —— 死代码。

### 1.5 组合键命令

`PackData` 里预置的组合（`PackData.java:395-483`），
均为「直接构造 8 字节 keyData」：

| 方法 | keyData（前若干字节） | 含义 |
|---|---|---|
| `combinKeyCS` | `{3, 0, 0,...}` | Ctrl + Shift |
| `combinKeyCE` | `{1, 0, 41,...}` | Ctrl + Esc |
| `combinKeyCAD` | `{5, 0, 76,...}` | Ctrl + Alt + Del |
| `combinKeyAT` | `{4, 0, 43,...}` | Alt + Tab |
| `combinKeyCSP` | `{1, 0, 44,...}` | Ctrl + Space |
| `combinKeyT` | `{0, 0, 43,...}` | Tab |
| `combinKeyNum` | `{0, 0, 83,...}` | Num Lock |
| `combinKeyCtrl` | `{1, 0, 0,...}` | Ctrl |
| `combinKeyCtrlAlt` | `{5, 0, 0,...}` | Ctrl + Alt |
| `combinKeyCtrlAltDel` | `{5, 0, 76,...}` | Ctrl + Alt + Del |
| `resetKey` | 当前 keyData | 全部松开 |
| `clearKey` | 全 0 | 复位键盘 |

`customKey(int usbCode)`（`PackData.java:121-135`）把 HID 修饰键码换算成修饰位：
`224→bit0`、`225→bit1`、`226→bit2`，`meta != 0 → bit3`。

`KEY_STATE(0x04)` 用于查询/上报键盘锁定灯，payload `{4, blade, 1}`，
响应 `KEY_STATE(0x04)` 的 `payload[4]` 是 Num/Caps/Scroll 状态位
（`UnPackData.keySate` → `{4, sourceData[3], sourceData[4]}`）。

---

## 2. 鼠标

### 2.1 `mousData[6]` 字段含义（`PackData.java:20`）

| 索引 | 含义 | 写入点 |
|---|---|---|
| `mousData[0]` | **按键位图**：bit0 = 左键，bit1 = 右键，bit2 = 中键 | `mousePressedPack` / `mouseReleasedPack` |
| `mousData[1]` | **ΔX**（有符号字节，相对模式） | `mousePackNew` |
| `mousData[2]` | **ΔY** | `mousePackNew` |
| `mousData[3]` | 原生钩子鼠标结构体的第 4 字节（用途不明） | `MouseTimerTask.java:39` |
| `mousData[4]` | **未使用** | — |
| `mousData[5]` | **滚轮**：`(byte)e.getWheelRotation()`，负 = 向上 | `mouseWheelMovedPack` |

按键位图确认（`PackData.java:573-595`）：

```java
mousePressedPack:  button==1 → |=0x01 ;  button==2 → |=0x04 ;  button==3 → |=0x02
mouseReleasedPack: button==1 → &=0x06 ;  button==2 → &=0x03 ;  button==3 → &=0x05
```
AWT 的 `getButton()`：1 = 左，2 = 中，3 = 右 → 与上表一致。

### 2.2 三种鼠标报文

**(A) `mousePack(x, y, bladeNo)` —— 绝对坐标（旧路径）**，`PackData.java:275-310`

明文 payload 8 字节：

| 偏移 | 值 |
|---|---|
| 0 | `0x05` |
| 1 | bladeNo |
| 2 | `mousData[0]` 按键 |
| 3 | `(x >> 8) & 0xFF` ← x **大端** |
| 4 | `x & 0xFF` |
| 5 | `(y >> 8) & 0xFF` |
| 6 | `y & 0xFF` |
| 7 | `mousData[5]` 滚轮 |

加密形态：payload 18 字节 = `05 | blade | <16 字节 AES(6 字节明文)>`，明文 =
`{buttons, xH, xL, yH, yL, wheel}`，用 `secure_encry(..., 6)`。

**(B) `mousePackNew(byte x, byte y, bladeNo)` —— 相对位移**，`PackData.java:312-341`

明文 payload 6 字节：

| 偏移 | 值 |
|---|---|
| 0 | `0x05` |
| 1 | bladeNo |
| 2 | `mousData[0]` 按键 |
| 3 | ΔX（有符号） |
| 4 | ΔY（有符号） |
| 5 | `mousData[3]` |

加密形态：payload 18 = `05 | blade | <AES(4 字节: buttons, Δx, Δy, mousData[3])>`。
**不含滚轮**。调用方按 ±120 像素/包限幅，大位移拆成多包
（`ImagePane.sentMstscMouse`，`ImagePane.java:1085-1140`）。

**(C) `mousePackNew_abs(x, y, bladeNo)` —— 归一化绝对坐标**，`PackData.java:343-382`

```java
x = x * 3000 / this.kvmInterface.getKvmUtil().getImagePane(bladeNo).getImagePaneWidth();
y = y * 3000 / this.kvmInterface.getKvmUtil().getImagePane(bladeNo).getImagePaneHeight();
```
后续字节布局与 (A) 完全相同。坐标系被归一化到 **0..3000 整数**（不是 0..65535），
3000 对应远端整屏宽/高。**不做上限截断**。

**(D) `mousePackMstsc(x, y, bladeNo)`**，`PackData.java:638-649`
明文与 (B) 相同，但**没有 compress 分支**，永远明文。全代码库**无调用者** —— 死代码；
M.S.T.S.C. 实际走 (B)。

### 2.3 特殊坐标

- `(65535, 65535)` = `0xFFFF,0xFFFF`：**重同步/离开**哨兵值
  （`SynMouseAction.java:26`、`MouseTimerTask.java:46-49`）
- 相对模式下 M.S.T.S.C. 重同步发 15 次 `(-127, -127)`
  （`SynMouseAction.java:33`）

### 2.4 鼠标模式协商

命令 `MOUSE_MODE_SET(0x24)`，响应 `MOUSE_MODE(0x25)`。

请求（`PackData.java:744-747`）：
```java
byte[] data = new byte[]{cmd, 0, mode, 0, 0};   // ← 第 2 字节硬编码 0，不是刀片号
```
payload = `24 00 mode 00 00`（5 字节，线长 15）。

响应：`payload[4]` = 状态（`UnPackData.mouseModeSate` → `{37, sourceData[3], sourceData[4]}`）。

| 值 | 方向 | 含义 |
|---|---|---|
| **0** | 双向 | **相对模式**（非同步）。客户端 `setIsSynMouse(false)`，启动相对轮询定时器 |
| **1** | 双向 | **绝对/同步模式**。`setIsSynMouse(true)`，禁用 M.S.T.S.C. |
| **2** | 仅客户端 → BMC | **连接时初始化**。客户端每次连接/重连后无条件发送，代码里**没有 case 2 的响应处理** —— 语义应为「让 BMC 决定/重置模式」⚠️ |
| 3 | — | 代码中不存在 |

> ✅ 实测：客户端发 `0x24` payload `24 00 02 00 00`（mode=2），
> BMC 回 `0x25` payload `00 00 25 **02** **01** 00 00 00`。
> 即 `payload[3] = 0x02`（疑似请求模式的回显）、`payload[4] = 0x01`（生效模式 = 同步/绝对）。
> 注意 **`payload[3]` 不是刀片号**（此处为 2，而刀片号是 0），
> 客户端也只读 `payload[4]`。该字节语义未定论。

客户端 UI 映射（📖 但标签与语义有出入）：

- 菜单项 `mouse_mode_switch`（标签是「鼠标加速 / Mouse Acceleration」）实际绑定
  `Base.isSynMouse`，勾选发 **1**、取消发 **0**
- 菜单项 `single_mouse`（「单鼠标」）勾选时 `setSingleMouse(true)`，
  **且仅当当前是同步模式时发 0** 把 BMC 拉回相对模式
- 全屏「鼠标模式」按钮切换 `Base.setMstsc(...)`，只是本地选择走哪条报文路径，
  不发 `0x24`

**三种报文的使用条件**（`ImagePane.java:636-1002`）：

| 条件 | 报文 |
|---|---|
| `!imagePane.isNew()` | (A) 绝对坐标 |
| `isNew && (isLinuxOS() \|\| Base.isMstsc()) && !Base.getIsSynMouse()` | (B) 相对 |
| `isNew && Base.getIsSynMouse()` | (C) 归一化绝对 |

> ⚠️ **早期版本此处声称「实测：连接后客户端发 `mouseModeControl(0x24, 2)`，抓包…」是过度声称。**
> 那只是本地发送日志：`CONNECT_BLADE` 被拒后 socket 很快关闭，
> 该发送与 `socket closed` 存在竞态。实际成功会话里确实发了 `0x24` 并**收到了
> `0x25` 应答**（见上面的实测记录），但 `0x1C` 帧率命令是否被 BMC 收到未验证。

---

## 3. 其它相关命令

| 命令 | 值 | payload | 作用 |
|---|---|---|---|
| `REPLAY_SMM` | 26 | `{26, blade, number}` | 回显/重放（收到 `0x02`/`0x04` 时回） |
| `DELETE_USER` | 25 | `{25}` | 注销当前用户 —— **写操作，谨慎使用** |
| `INTERRUPT_BLADE` | 7 | `{7, blade}` / `{7, blade, 1, 1}` | 断开刀片连接 |
| `REQ_BLADE_MONITOR` | 23 | `{23, blade, 1}` | 监视刀片状态 |
| `INTERRUPT_MONITOR` | 24 | `{24, blade, 1}` | 停止监视 |
| `KVM_CMD_USBRESET` | 48 | 见 `USBResetAction` | 复位远端 USB（会影响键鼠） |
| `KVM_CMD_SECURITY` | 51 | `{51, 0, <AES(16 字节, 末字节=命令)>}` | **compress=1 时的开关机控制**（见 06 章） |
