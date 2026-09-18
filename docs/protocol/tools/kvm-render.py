#!/usr/bin/env python3
"""Rebuild the 800x600 screen from a reassembled Huawei iBMC KVM frame.

Constants (DQT/DHT/SOF) are extracted directly from the decompiled Java source so
there is no transcription error.
"""
import json, re, sys, os
from io import BytesIO
from PIL import Image

DECOMP = "<decompiled-vendor-sources>/com/library/decoder"
frame_path = sys.argv[1]
blocks_path = sys.argv[2]
out_png = sys.argv[3]
dqttags = int(sys.argv[4]) if len(sys.argv) > 4 else 6

def java_bytes(path, name):
    src = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r"\b" + name + r"\s*=\s*new byte\[\]\s*\{(.*?)\}", src, re.S)
    if not m:
        raise SystemExit(f"找不到 {name} in {path}")
    vals = [int(x) for x in re.findall(r"-?\d+", m.group(1))]
    return bytes((v + 256) % 256 for v in vals)

JP = os.path.join(DECOMP, "JPEGData.java")
DQ = os.path.join(DECOMP, "DQTZData.java")

SOI_APP0 = java_bytes(JP, "HEAD_SYN_SOI_APPO")
SOF_444  = java_bytes(JP, "HEAD_SYN_SOF_444")
SOF_420  = java_bytes(JP, "HEAD_SYN_SOF_420")
DHT_SOS  = java_bytes(JP, "HEAD_SYN_SOF_SOS")
TAIL     = java_bytes(JP, "TAIL")
DQT_Y = java_bytes(DQ, f"HEAD_SYN_DQT_Y_{dqttags*10+10}")
DQT_U = java_bytes(DQ, f"HEAD_SYN_DQT_U_{dqttags*10+10}")
DQT_V = java_bytes(DQ, f"HEAD_SYN_DQT_V_{dqttags*10+10}")

print(f"dqttags={dqttags} → 量化表后缀 _{dqttags*10+10}")
print(f"SOI/APP0={SOI_APP0.hex()}  ({len(SOI_APP0)}B)")
print(f"DQT_Y={len(DQT_Y)}B DQT_U={len(DQT_U)}B DQT_V={len(DQT_V)}B")
print(f"SOF_444={SOF_444.hex()} ({len(SOF_444)}B)   SOF_420={SOF_420.hex()}")
print(f"DHT+DRI+SOS={len(DHT_SOS)}B  TAIL={TAIL.hex()}")

def syn_head(sof):
    return SOI_APP0 + DQT_Y + DQT_U + DQT_V + sof + DHT_SOS

HEAD = syn_head(SOF_444)

buf = open(frame_path, "rb").read()
blocks = json.load(open(blocks_path))
W, H = 800, 600
blockX = (W + 63) // 64
canvas = Image.new("RGB", (W, H), (0, 0, 0))
decoded = {}          # blocknum -> Image (64x64)
fail = 0
jpgbytes = []

for bl in blocks:
    n, off, zt, rz, syclen = bl["n"], bl["i"], bl["zipType"], bl["rZipType"], bl["syclen"]
    col, row = n % blockX, n // blockX
    if zt in (2, 3):
        raw = buf[off + 3: off + syclen]
        full = HEAD + raw + TAIL
        try:
            im = Image.open(BytesIO(full)); im.load()
            im = im.convert("RGB")
            decoded[n] = im
            if len(jpgbytes) < 3:
                jpgbytes.append((n, len(full), im.size, im.getpixel((0, 0)), im.getpixel((32, 32))))
        except Exception as e:
            fail += 1
            if fail <= 5: print(f"  块#{n} JPEG 解码失败: {type(e).__name__}: {e}  (scan {len(raw)}B)")
            continue
        canvas.paste(im, (col * 64, row * 64))
    elif zt == 5:            # 复制上一行同列（blocknum - blockXcount）
        src = n - blockX
        if src in decoded: canvas.paste(decoded[src], (col * 64, row * 64)); decoded[n] = decoded[src]
    elif zt == 6:            # 复制左邻（blocknum - 1）
        src = n - 1
        if src in decoded: canvas.paste(decoded[src], (col * 64, row * 64)); decoded[n] = decoded[src]

canvas.save(out_png)
print(f"\nJPEG 块解码成功 {len(decoded)}/{len(blocks)}，失败 {fail}")
for n, sz, size, p0, p32 in jpgbytes:
    print(f"  块#{n}: 合成 JPEG {sz}B 解码为 {size}  左上像素={p0} 中心像素={p32}")
print(f"\n输出 {out_png}")
print("画面非黑像素占比: %.2f%%" % (100.0 * sum(1 for p in canvas.getdata() if p != (0, 0, 0)) / (W * H)))
