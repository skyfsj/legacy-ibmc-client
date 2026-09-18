# Notice

## No vendor code

This repository contains **no decompiled vendor sources, no JAR files, and no firmware
images**. It is an independent reimplementation of a wire protocol, plus interface
documentation written for interoperability. The protocol description (message layouts,
command codes, framing, key derivation) is factual interface information produced by
observing a device the author owns.

## Trademarks

Huawei, iBMC, FusionServer and other product names are trademarks of their respective
owners. This project is unaffiliated with and not endorsed by Huawei.

## Redacted values

Several documents quote values taken from a real device session JNLP:
`verifyValue`, `verifyValueExt`, `decrykey`, and derived keys. Those are **credentials**
and have been replaced with placeholders. Do not commit your own — `.gitignore` excludes
`*.jnlp` and captured streams for this reason.

## Test fixtures

`clients/*/test*` and `docs/protocol/tools/` were originally validated against a capture
from a real device (`session-server-stream.bin`, `frame-2.bin`). Those files are **not**
included — they contain a real screen image and session material. The shipped fixtures are
synthetic. Re-running the capture-based checks requires your own capture; the tools in
`docs/protocol/tools/` are read-only and never inject input, power commands, or virtual
media writes.

## Responsible use

Intended for hardware you own or are authorised to administer. The client does not verify
the BMC's self-signed TLS certificate (matching the vendor applet), so use it only on a
management network you trust.
