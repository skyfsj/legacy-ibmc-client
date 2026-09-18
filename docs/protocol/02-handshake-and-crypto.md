# 02 — 连接时序与密钥链


> **注**：本文档中的会话相关取值（`verifyValue` / `verifyValueExt` / `decrykey` / 派生密钥）已脱敏 —— 它们来自真实设备的 JNLP，属于凭证。

## 1. JNLP 参数 → 会话材料

JNLP（`com.kvm.KVMApplet` 的 applet 参数）解析在 `KVMApplet.java:249-360`。

| JNLP 参数 | 用途 | 代码位置 |
|---|---|---|
| `port` | KVM 通道 TCP 端口（2198） | `KVMApplet.java:351` |
| `vmmPort` | 虚拟介质端口（8208） | `KVMApplet.java:332-337` |
| `verifyValue` | **KVM codeKey**（会话号，截断为 i32） | `KVMApplet.java:285-325` |
| `verifyValueExt` | **PBKDF2 口令**（用于 `encodeKey`） | `KVMApplet.java:287` |
| `mmVerifyValue` | **VMM codeKey** → `Base.setVmmCodeKey` | `KVMApplet.java:326-331` |
| `decrykey` | 32 字节十六进制的密钥材料 | `KVMApplet.java:262-279` |
| `compress` | 是否启用 KVM 通道加密（本机型 `1`） | `KVMApplet.java:256-261` |
| `vmm_compress` | VMM 通道是否加密（缺省为 **1**） | `KVMApplet.java:249-254` |
| `privilege` | 权限等级（4 = 管理员） | — |
| `bladesize` | 刀片数量 | — |

### 1.1 `decrykey` 的拆分

```java
// KVMApplet.java:262-279
this.skey = this.getParameter("decrykey");
byte[] decry_key = this.hexStringToBytes(this.skey);
if (decry_key.length != 32) return false;
byte[] tempBuff = new byte[16];
System.arraycopy(decry_key, 0, tempBuff, 0, 16);
Base.setUser_key(tempBuff);        // user_key = decrykey[0..15]
System.arraycopy(decry_key, 16, tempBuff, 0, 16);
Base.setUser_iv(tempBuff);         // user_iv  = decrykey[16..31]
```

所以 `decrykey` 是 **AES-128 的密钥 + IV**，用于：
1. 计算 `encodeKey` 的 PBKDF2 **salt**（用 `user_iv`）
2. 解密 BMC 下发的 `KVM_KEY_SET`(0x40) 报文

### 1.2 `codeKey` 的截断

```java
// KVMApplet.java:309-325
long tempLong = Long.parseLong(codeKey);
if (tempLong > Integer.MAX_VALUE) {
    this.kvmInterface.setCodeKey((int)(0L - (this.i - tempLong)));
} else {
    this.kvmInterface.setCodeKey(Integer.parseInt(codeKey));
}
```

其中 `private final long i = Long.valueOf("4294967296").intValue();`（`KVMApplet.java:55`）——
`2^32` 转成 `int` 后**溢出为 0**，所以那个分支等价于 `(int) tempLong`。
净效果：**`codeKey` = `verifyValue` 截断为 32 位有符号整数**。✅
（实测 `1000000001` → `0x4A7DA307` 原样上线）

---

## 2. 完整连接时序

```
① TCP 连接 BMC:2198

② TX  HEART_BEAT      payload {09, 00}                        会话级 codeKey
③ TX  GET_SUITE(0x42) payload {42, blade}                     会话级 codeKey
④ RX  KVM_SUITE_LIST(0x43)
        payload = 00 00 | 43 | blade | count | (algo:1 + iterations:u32be) × count
⑤    选一个套件：
         algo 2 → PBKDF2WithHmacSHA1   （JDK < 8 时优先）
         algo 3 → PBKDF2WithHmacSHA256 （JDK ≥ 8 时优先，本机型实际选它）
         代码只认 2 和 3；都不匹配则回落 {5000, SHA1}
⑥    算 encodeKey（见 §3）
⑦ TX  SET_SUITE(0x44) payload {44, blade, algo, iterations(4B 大端)}
⑧ TX  CONNECT_BLADE(0x06)  ← 走 §2.2 的「连接帧」格式，携带 24 字节 encodeKey
        payload {06, blade, colorBit, 01, 01}
⑨ RX  CONNECT_STATE(0x08)  payload = 00 00 | 08 | blade | state | ...
        state = 0 → 接受；其它值见 §4
⑩ TX  MOUSE_MODE_SET(0x24) payload {24, 00, 02, 00, 00}     ← 注意第 2 字节是 0
⑪ TX  FRAME_COMM(0x1C)     payload {1C, 35}                 ← 视频帧率
⑫ 之后：BMC 开始推 IMAGE_DATA(0x02)；客户端按需发心跳(0x09)、重传请求(0x08)
```

**实测结果**（旧 JNLP）：

```
tx HEARTBEAT   fef60004 4a7da307 ba98 0900
tx GET_SUITE   fef60004 4a7da307 6bae 4200
rx 00 00 43 00 03 | 01 00001388 | 02 00002710 | 03 00002710    ← 3 档套件
tx SET_SUITE   fef60009 4a7da307 7fb8 44 00 03 00002710
tx CONNECT     fef68007 （已脱敏）...25310622 80f5 06 00 02 01 01
rx 00 00 08 00 03 00 00 00     ← state = 3，拒绝，随后 FIN
```

解读：套件协商**不需要认证**，所以旧会话能走到第 ⑧ 步；
但 `CONNECT_BLADE` 携带的 24 字节证明对应的是一个**已过期的会话**，因此被拒。✅

---

## 3. 密钥派生

### 3.1 `encodeKey`（24 字节，连接证明）

```java
// KVMApplet.java:293-307  （BladeThread.java:282-305 是同逻辑的第二处）
this.kvmInterface.setEncodeKey(
    AESHandler.getcodekey(codeKey, 24, Base.getUser_iv(),
                          this.kvmInterface.getHmac(),
                          this.kvmInterface.getIterations()));
// 然后：把 24 字节按每 4 字节一组整体反序
for (int i = 0; i < 6; ++i) {
    j = i * 4;
    tmp[0] = ek[j]; ek[j] = ek[j+3]; ek[j+3] = tmp[0];
    tmp[0] = ek[j+1]; ek[j+1] = ek[j+2]; ek[j+2] = tmp[0];
}
```

`AESHandler.getcodekey`（`AESHandler.java:20-28`）：

```java
byte[] salt = new byte[16];
System.arraycopy(kvm_salt, 0, salt, 0, 16);      // salt = user_iv
PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, len * 8);
SecretKeyFactory skf = SecretKeyFactory.getInstance(hmac);   // "PBKDF2WithHmacSHA256"
return skf.generateSecret(spec).getEncoded();
```

注意两处细节：

- **口令是 `verifyValueExt` 字符串本身**（`KVMApplet.java:294` 传的是 `codeKey` 变量，
  但该变量在第 287 行被 `verifyValueExt` 覆盖——
  `BladeThread.java:284` 更清楚，直接传 `getVerifyValueExt()`）。
  实测 `verifyValueExt = （已脱敏）`（32 个 ASCII 字符）。
- **salt 是 `user_iv`**，不是 `user_key`。

等价的 JS：

```js
let k = crypto.pbkdf2Sync(Buffer.from(verifyValueExt, "utf8"), userIv, iterations, 24, "sha256");
for (let i = 0; i < 6; i++) {          // 每 4 字节反序
  const j = i * 4;
  [k[j], k[j+3]] = [k[j+3], k[j]];
  [k[j+1], k[j+2]] = [k[j+2], k[j+1]];
}
```

**这个 24 字节就是 `CONNECT_BLADE` 帧里偏移 4..27 的内容。** ✅

### 3.2 `kvm_key`（48 字节，连接后由 BMC 下发）

服务器在连接建立后发 `KVM_KEY_SET`(0x40/十进制 64)（`BladeThread.distributeKVMSetKey`，
`BladeThread.java:407-465`）：

```java
if (data_len == 48) {                                   // 常规：48 字节
    byte[] decryted_data = AESHandler.aes_cbc_128_decrypt(encryted_data,
                                                          Base.getUser_key(), Base.getUser_iv());
    String de_str = BladeThread.convert(decryted_data, 32);   // 前 32 字节按 ASCII 当口令
    System.arraycopy(decryted_data, 32, salt, 0, 16);         // 后 16 字节当 salt
    Base.setKvm_key(AESHandler.getcodekey(de_str, 48, salt, hmac, iterations));
    // 再按每 4 字节一组反序（12 组）
} else if (128 == data_len) {                           // 重连密钥，见 §5
    ...
}
```

即：

```
明文 = AES-128-CBC 解密( 密文, key=user_key, iv=user_iv )
明文[0..31]  = 32 个 ASCII 字符 → PBKDF2 口令
明文[32..47] = 16 字节 salt
kvm_key = PBKDF2(口令, salt, iterations, 48 字节)  然后每 4 字节反序（共 12 组）
```

**`kvm_key` 的 48 字节被切成三段使用**（这是理解整个加密的钥匙）：

```
kvm_key[ 0..15]  → KVM 数据密钥   （AESHandler.decry / kvm_encry）
kvm_key[16..31]  → 键盘/鼠标密钥  （AESHandler.secure_encry）
kvm_key[32..47]  → AES-CBC IV     （所有上面几处共用同一个 IV）
```

对应 `AESHandler.java`：

```java
public static byte[] decry(byte[] src, byte[] key_data, int len) {
    System.arraycopy(key_data, 0,  key_kvm, 0, 16);   // key = kvm_key[0..15]
    System.arraycopy(key_data, 32, iv,      0, 16);   // iv  = kvm_key[32..47]
    return aes_cbc_128_decrypt(src, key_kvm, iv);
}
public static byte[] secure_encry(byte[] src, byte[] key_data, int len) {
    System.arraycopy(key_data, 16, keyboard_key, 0, 16);  // key = kvm_key[16..31]
    System.arraycopy(key_data, 32, iv,          0, 16);   // iv  = kvm_key[32..47]
    return aes_cbc_128_encrypt(src, keyboard_key, iv);
}
public static byte[] kvm_encry(byte[] src, byte[] key_data, int len) {
    System.arraycopy(key_data, 0,  keyboard_key, 0, 16);  // key = kvm_key[0..15]
    System.arraycopy(key_data, 32, iv,          0, 16);   // iv  = kvm_key[32..47]
    return aes_cbc_128_encrypt(src, keyboard_key, iv);
}
```

### 3.3 老路径（`compress == 0`）

`compress = 0` 时不用 `kvm_key`，而是用 `AESHandler.encry(src, codekey, len)`
（`AESHandler.java:37-55`）：

```java
byte[] key = {1,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8};
key[0] = codekey >> 24; key[1] = codekey >> 16; key[2] = codekey >> 8; key[3] = codekey;
// IV = 全 0
```

即 **AES-128-CBC，密钥前 4 字节来自 `codeKey`，后 12 字节是硬编码常量
`05 06 07 08 01 02 03 04 05 06 07 08`，IV 全 0**。⚠️ 这是弱设计（只有 32 位熵），
但本机型 `compress=1`，不走这条。

### 3.4 AES 细节

- 算法串：`"AES/CBC/NOPadding"`（`AESHandler.java:18`）——**NoPadding**
- 所以调用方必须自己把明文零填充到 16 的倍数（`srcLen = (len+15)/16*16`），
  接收方必须自己知道真实长度（长度在协议里显式携带）
- 解密后**不去填充**

---

## 4. `CONNECT_STATE`(0x08) 状态码

`BladeThread.distributeConnectStateData`（`BladeThread.java:308-342`）：

| state | 常量名 | 含义 |
|---|---|---|
| 0 | — | **成功** |
| 2 | `over_userconnect` | 已有其他用户占用 |
| 3 | `str_errorname` | 通用错误（**实测旧会话过期就是这个**） |
| 4 | `SIGNAL_OUT_RANGE` | 分辨率超出范围 |
| 5 | `Server_Disabled` | 服务器被禁用 |
| 7 | `User_Delect` | 用户被删除 |
| 17 | `session_timeout` | 会话超时 |

---

## 5. 重连

- 客户端定期发心跳 `HEART_BEAT(0x09)`（`BladeHeartTimer` 驱动，
  `BladeHeartTimer.java:23`）。会话级心跳 payload 是 `{09, 00}`，刀片级是 `{09, blade}`。
- 断线重连走 `BladeReconnect`（`BladeReconnect.java:24-42`）：
  先发 `GET_SUITE`(0x42)，**sleep 1000ms**，再发 `CONNECT_BLADE`(0x06)。
  只有当 `isNeedConsultation()` 为真才重发套件请求。
- `BladeCommu.reConnBlade`（`BladeCommu.java:87-132`）最多重试 50 次，
  重连后立刻补发 `MOUSE_MODE_SET(0x24, 2)`。
- BMC 用 128 字节的 `KVM_KEY_SET` 下发**重连密钥**（`BladeThread.java:444-464`）：
  同样是 AES-CBC 解密，但明文 128 字节，存进 `setReconnKey`，
  之后 `connectBlade` 会把它附在 payload 偏移 5 处（`PackData.java:225-228`），
  长度变成 `5 + 128 = 133` 字节。
- 若本地还挂着虚拟介质，会触发 `VirtualMediaLink` 重新点击挂载
  （`BladeThread.java:451-462`）。

---

## 6. 密码套件协商细节

`BladeThread.distributeConsultation`（`BladeThread.java:253-306`）：

```java
int count = unPackData[2];
if (count * 5 + 3 != unPackData.length) {        // ← 长度自校验
    Debug.println("consultation failed.");
    return;
}
for (k = 0; k < count; ++k) {
    if (unPackData[k*5+3] == 2 && !isSupportSha256) {   // algo 2 = SHA1
        iterations = unPackData[k*5+4] << 24 | ... ;
        this.kvmInterface.setHmac("PBKDF2WithHmacSHA1");
        sentData(setSuitePack(bladeNO, iterations, 2));
        break;
    }
    if (unPackData[k*5+3] != 3 || !isSupportSha256) continue;   // algo 3 = SHA256
    iterations = unPackData[k*5+4] << 24 | ... ;
    this.kvmInterface.setHmac("PBKDF2WithHmacSHA256");
    sentData(setSuitePack(bladeNO, iterations, 3));
    break;
}
if (k == count) {                                 // 一个都没匹配上
    sentData(setSuitePack(bladeNO, 5000, 1));     // 回落 5000 次 / algo 1
}
```

- 套件表条目 = **5 字节**：`algo(1) + iterations(u32 大端)`
- `count * 5 + 3 == len`，其中 `len = dlen - 2`（因为 `UnPackData` 会砍掉 payload 头 2 字节）
- 实测 `dlen = 20`、`count = 3` → `3*5+3 = 18 = 20-2` ✅ 完全吻合
- 本机型返回：`algo=1/5000`、`algo=2/10000`、`algo=3/10000`
- 客户端优先选 **algo 3 (SHA-256)**；`algo 1` 的含义代码里没有明说，
  只在「全不匹配」的兜底路径里和 5000 次一起出现 ⚠️

`SET_SUITE(0x44)` 的 payload（`PackData.java:210-213`）：

```java
byte[] data = {68, (byte)bladeNO, (byte)hmac,
               (iter >> 24), (iter >> 16), (iter >> 8), iter};
```
→ 7 字节，总帧长 17 字节。✅ 实测 `fef60009 ... 44 00 03 00002710`

---

## 7. 实测数据（本机型）

| 参数 | 值 |
|---|---|
| BMC | Huawei 5288 V3 @ `192.168.1.100` |
| KVM 端口 / VMM 端口 | 2198 / 8208 |
| 套件表 | `algo1=5000`, `algo2=10000`, `algo3=10000` |
| 实测选中 | **algo 3 = PBKDF2WithHmacSHA256, 10000 次** |
| `verifyValue` | `1000000001` (`0x4A7DA307`) — 另一个 JNLP 为 `00000001` (`0x04B7A978`) |
| `verifyValueExt` | `（已脱敏）` / `（已脱敏）` |
| `decrykey` | `（已脱敏）b2abbd1467068f0123d8f6c4` + `f12105045f804b8af9443888ed5875a4` |
| 派生的 `encodeKey` | `（会话值已脱敏）` |
| 结果 | 套件协商成功，`CONNECT_BLADE` 被拒（state=3），会话已过期 |

> 两个 JNLP 的 `verifyValue`/`verifyValueExt`/`decrykey` 与 JAR 文件名
> `vconsole1555733171728880755.jar` 都不同，但指向同一设备同一 SN，
> 说明它们是**两次不同登录**产生的会话描述符，都已在 2026-08 之后失效。
