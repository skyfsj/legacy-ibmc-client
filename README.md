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

## How it is verified

The protocol work is backed by a real device capture, and the tests assert **measured byte
values** rather than internal consistency: CRC results, rebuilt frames, chunk boundaries,
INQUIRY payloads, block counts.

The strongest single check: a real captured frame decodes to **130/130 blocks, 5129/5129
bytes consumed, 0 JPEG errors**, and four independent implementations (Go, Node,
Chromium's JPEG decoder, Python/Pillow) agree on the result.

Also confirmed against a live BMC: the HTTPS login flow, the TCP handshake and suite
negotiation, and that a password written by the Electron build decrypts in the Go build.

### Not yet done

- **The virtual media channel is ported from the vendor client's logic but has never run
  against a device.** The byte layouts are pinned by tests; the first real mount may need
  iteration.
- **Keyboard/mouse events are captured and transmitted, but their effect on the remote
  OS is untested** (no live session was available with credentials).
- **RLE video blocks** are implemented from source; the captured frames only ever
  contained JPEG and copy blocks.
- Only one blade is supported (fine for the single-blade model this was built for).

### Gotchas worth knowing

- **Use the `整数倍（无损）` zoom.** Any fractional downscale must either blur the image or
  (with nearest-neighbour) drop whole pixel rows, which slices thin console text.
- **JNLP sessions are single-use** and the console port allows one client at a time — both
  clients re-login on every connect for this reason.
- **Power commands are encrypted inside a `0x33` frame**, so they cannot be identified from
  a capture. They are sent only after an explicit confirmation.

## Quick start

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

## Why not a web page?

The console channel is **raw TCP on port 2198**. Browsers expose no arbitrary-socket API,
so a pure web page cannot speak it — and WASM does not change that:

- WASM has **no I/O of its own**; it can only call what the host imports, and in a browser
  the host offers exactly the Web APIs JS already has. Its capability ceiling is JS's.
- WASI defines sockets, but **browsers do not implement them** — only standalone runtimes
  (Wasmtime, Node) do, which is a native process again.
- The one real exception is Chrome's **Direct Sockets API**, and it is restricted to
  *Isolated Web Apps* (signed bundles installed by policy). Verified on Chrome 152: the
  constructors appear behind `--enable-features=IsolatedWebApps,IsolatedWebAppDevMode`,
  but a plain page that touches `TCPSocket` wedges immediately.

Hence a desktop app. The Go build keeps the footprint small by using the system webview
instead of bundling a browser engine.

---

## Protocol highlights

The interesting parts, all documented with byte layouts in [`docs/protocol/`](docs/protocol/):

- **The two directions use different framings.** Client→BMC is
  `FE F6 | len | codeKey(4B) | CRC16 | payload`; BMC→client is `FE F6 00 | len(1B≤250) | payload`
  with **no CRC and no key**. Frames tile byte-exactly.
- **Key chain**: the JNLP `decrykey` (32 B) splits into an AES key and IV; suite negotiation
  derives a 24-byte `encodeKey` (PBKDF2, then each 4-byte group reversed); after connecting the
  BMC sends a 48-byte secret that becomes `kvm_key` — sliced into a data key, a keyboard key,
  and a shared IV.
- **Video is 64×64 blocks.** Each block is one descriptor byte: RLE (4 variants), a JPEG block
  carrying **raw entropy-coded scan data only** (the client synthesises the JPEG headers from
  10 built-in quantization tables), or a "copy the block above / to the left" reference which
  is how unchanged regions cost one byte.
- **The keyboard is a USB HID boot report** (modifier byte + 6 usage IDs).
- **The BMC does not validate the client frame's CRC or codeKey** for suite negotiation, but
  frames must be written one-per-`write()` — it does not reassemble TCP splits.

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
