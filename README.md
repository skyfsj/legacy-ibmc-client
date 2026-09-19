# Huawei iBMC KVM — native client & protocol notes

A from-scratch, **Java-free** remote console client for older Huawei iBMC / FusionServer
BMCs, plus the community protocol documentation it was reverse-engineered into.

The vendor ships a Java applet (`com.kvm.KVMApplet`). It needs a JRE, Java Web Start is
gone from modern JDKs, and the applet itself crashes on current runtimes. This project
replaces it with a native client that speaks the BMC's own private protocol directly.

```
BMC ──HTTPS──> login + session JNLP
    └─raw TCP:2198──> video, keyboard, mouse   (private protocol, no TLS)
       raw TCP:8208──> virtual media            (SCSI over a private wrapper)
```

> **中文摘要**：老华为 iBMC 的远程控制台依赖已废弃的 Java 小程序。本仓库用原生客户端
> 直连它自己的私有协议（裸 TCP，非 VNC/RDP/IPMI-SOL），并附完整协议文档。
> 提供两个实现：**Go + 系统 webview**（6.6 MB，推荐）和 **Electron**（多平台打包现成）。
> 文档在 [`docs/protocol/`](docs/protocol/)。

---

## Features

- **Native console** — video, keyboard, mouse, over the BMC's own protocol. No Java.
- **Virtual media** — mount a local ISO as a CD-ROM or an `.img` as a floppy.
- **Power control** — power on/off, restart, safe restart, save-and-shutdown, USB reset
  (each confirmed before it is sent).
- **Session manager** — saved machines, optional password storage in the OS keychain,
  renameable entries.
- **Quality and zoom** — JPEG quality slider, and a lossless integer zoom mode.
- **Two builds** — Go + system webview (6.6 MB) or Electron (cross-platform packaging).

## Downloads

[Releases](https://github.com/skyfsj/legacy-ibmc-client/releases) carry prebuilt archives
for macOS (arm64 / amd64), Windows (amd64) and Linux (amd64 / arm64), in two flavours:

| archive | what it is |
|---|---|
| `ibmc-kvm-<platform>` | the Go client — ~3 MB, uses the system webview, nothing to install beyond it |
| `ibmc-kvm-full-<platform>` | the Electron client — bundles its own Chromium (~200 MB unpacked), for machines with no usable system webview |

The Electron archives are ad-hoc signed on macOS and unsigned on Windows, so the system
warns about an unidentified developer the first time you open one (on macOS: right-click →
Open, or `xattr -dr com.apple.quarantine`).

## Build from source

### Go + system webview (recommended — ~6.6 MB, ~200 MB RAM)

```bash
cd clients/go
GOPROXY=https://goproxy.cn,direct go build -ldflags="-s -w" -o ibmc-kvm .
./ibmc-kvm
```

Uses the OS webview (WKWebView / WebView2 / WebKitGTK). If none is usable it falls back
to driving an installed Chromium-family browser in `--app` mode, then to the default
browser — see [`clients/go/README.md`](clients/go/README.md).

### Electron (cross-platform packaging, more UI polish — ~330 MB)

```bash
cd clients/electron
ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ npm install
npm start
```

Both clients share the same config file and the same password storage, so saved machines
and credentials carry over between them.

---

## Layout

```
docs/protocol/      protocol specification, command tables, verification record
docs/protocol/tools/read-only capture / analysis / decode tools
clients/go/         Go + system webview client (protocol in Go, UI reused from the renderer)
clients/electron/   Electron client (same renderer, Node transport)
```

## Testing

```bash
cd clients/go       && GOPROXY=https://goproxy.cn,direct go test -count=1 ./...
cd clients/electron && npm test
```

The tests assert **measured byte values** (CRC results, rebuilt frames, block counts), not
just internal consistency. They also cover the credential storage: a password must never
appear in plaintext on disk.

> The test fixtures are **synthetic**. The author's original fixtures were derived from a
> real device session and have been replaced, so running the live-capture checks now requires
> your own capture — see [`docs/protocol/tools/README.md`](docs/protocol/tools/README.md).

---

## Legal & scope

- **No vendor code is included.** This repository contains no decompiled sources, no JARs,
  and no firmware. It is an independent, clean-room-style reimplementation plus interface
  documentation produced for interoperability. *Reverse-engineering for interoperability is
  permitted in many jurisdictions, but you are responsible for checking your own.*
- **For your own equipment.** Use it on hardware you own or are authorised to administer.
  Huawei and iBMC are trademarks of their respective owner; this project is not affiliated
  with or endorsed by Huawei.
- **Session values are redacted.** Values in `docs/` that came from a real JNLP
  (`verifyValue`, `verifyValueExt`, `decrykey`, derived keys) are replaced with placeholders —
  they are credentials. Never commit your own.
- **Credentials** are stored via the OS keychain (or the platform's `safeStorage` equivalent)
  and encrypted; the app never writes a password in plaintext.
- The BMC uses a self-signed certificate; the client does not verify it, matching the vendor
  applet's behaviour. **Treat the management network as trusted.**

## License

[Apache-2.0](LICENSE).

## Acknowledgements

Built by reverse-engineering the vendor's own client for interoperability. Thanks to
everyone who documented Huawei iBMC behaviour in public before this, and to the
maintainers of the Go standard library, Electron and the `webview` binding.
