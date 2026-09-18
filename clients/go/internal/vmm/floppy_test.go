package vmm

// UFI (virtual floppy) tests against a synthetic 1.44 MB .img file.
//
// The expectations are UFIProcessor.java's fixed answers plus FloppyDriver's
// geometry: 2880 blocks of 512 bytes, medium type code 148.

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

// UFIProcessor.inquiryData, byte for byte:
// 00 80 00 01 1F 00 00 00 "Virtual FLOPPY VM 1.1.0" + 5 spaces (36 bytes).
const floppyInquiryHex = "008000011f0000005669727475616c20464c4f50505920564d20312e312e302020202020"

func newFloppyHandler(t *testing.T, writeProtect bool, compress bool) (*ufiHandler, *fakeWire, *Floppy) {
	t.Helper()
	path := writePatternImage(t, "test.img", floppyTotalBlocks, floppyBlockLength)
	f, err := OpenFloppy(path, writeProtect)
	if err != nil {
		t.Fatalf("OpenFloppy: %v", err)
	}
	w := &fakeWire{compress: compress}
	if compress {
		w.key = bytes.Repeat([]byte{0x11}, 16)
		w.iv = bytes.Repeat([]byte{0x22}, 16)
	}
	h := newUFIHandler(w, f)
	t.Cleanup(func() { _ = f.close() })
	return h, w, f
}

func TestFloppyGeometryConstants(t *testing.T) {
	if floppyTotalBlocks != 2880 || floppyBlockLength != 512 || floppyMediumTypeCode != 148 {
		t.Fatalf("几何参数应为 2880 x 512、介质码 148，实际 %d x %d、%d",
			floppyTotalBlocks, floppyBlockLength, floppyMediumTypeCode)
	}
	if FloppyImageSize != 1474560 {
		t.Fatalf("镜像大小应为 1474560，实际 %d", FloppyImageSize)
	}
}

func TestFloppyInquiryBytes(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbInquiry(), 0x0C)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 36 {
		t.Fatalf("INQUIRY 应为一个 36 字节数据帧，实际 %d 帧", len(dfs))
	}
	want, _ := hex.DecodeString(floppyInquiryHex)
	assertBytes(t, "INQUIRY 应答", dfs[0].body, want)
	if dfs[0].op != OpUFIData {
		t.Fatalf("软驱数据帧操作码应为 3，实际 %d", dfs[0].op)
	}
	cmpl := completionOf(t, frames, OpUFIComplete)
	if cmpl == nil || cmpl[1] != CmdOK || cmpl[3] != 0x0C {
		t.Fatalf("完成帧不对: % x", cmpl)
	}
}

func TestFloppyReadCapacity(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbReadCapacity(), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 8 {
		t.Fatalf("READ_CAPACITY 应为一个 8 字节帧，实际 %d", len(dfs))
	}
	// Last block index 2879 = 0x00000B3F, block length 512 = 0x00000200.
	want := []byte{0x00, 0x00, 0x0B, 0x3F, 0x00, 0x00, 0x02, 0x00}
	assertBytes(t, "READ_CAPACITY", dfs[0].body, want)
}

// READ_FORMAT_CAPACITY returns the 20-byte template with the block count written
// at bytes 4..7 and the block length at bytes 9..11 (note the stale tail the
// Java's mutable capacityList keeps).
func TestFloppyReadFormatCapacity(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbReadFormatCapacity(), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 20 {
		t.Fatalf("READ_FORMAT_CAPACITY 应为 20 字节，实际 %d", len(dfs))
	}
	want := []byte{
		0x00, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x0B, 0x40,
		0x02, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x0B, 0x40,
		0x00, 0x00, 0x02, 0x00,
	}
	assertBytes(t, "READ_FORMAT_CAPACITY", dfs[0].body, want)
}

// A 16-block READ_10 (8192 bytes) is read in one 32768-byte window and then
// fragmented into 4096-byte frames: continue, then end.
func TestFloppyReadChunking(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbRead10(0, 16), 5)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 2 {
		t.Fatalf("8192 字节应分 2 帧 (4096/帧)，实际 %d", len(dfs))
	}
	if got := len(dfs[0].body); got != FloppyPacketSize {
		t.Fatalf("第一帧应为 %d 字节，实际 %d", FloppyPacketSize, got)
	}
	if dfs[0].state != SubContinue {
		t.Fatalf("第一帧 state 应为 1，实际 %d", dfs[0].state)
	}
	if dfs[1].state != SubEnd {
		t.Fatalf("最后一帧 state 应为 3，实际 %d", dfs[1].state)
	}
	body := concatBodies(dfs)
	if len(body) != 16*floppyBlockLength {
		t.Fatalf("数据总量应为 8192，实际 %d", len(body))
	}
	assertBytes(t, "第 0 块", body[:floppyBlockLength], expectedBlock(0, floppyBlockLength))
	assertBytes(t, "第 15 块", body[15*floppyBlockLength:], expectedBlock(15, floppyBlockLength))
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("完成帧应为成功: % x", cmpl)
	}
}

// A read longer than one 32 KiB window walks the image in windows and fragments
// each window into 4096-byte frames; the very last frame is the END one.
func TestFloppyReadMultiWindow(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	const blocks = 100 // 51200 bytes = 32768 + 18432
	h.handle(cdbRead10(0, blocks), 1)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	// 32768 -> 8 frames; 18432 -> 4 full frames + 2048 -> 5 frames. Total 13.
	if len(dfs) != 13 {
		t.Fatalf("51200 字节应为 13 帧，实际 %d", len(dfs))
	}
	for i, f := range dfs[:len(dfs)-1] {
		if f.state != SubContinue || len(f.body) != FloppyPacketSize {
			t.Fatalf("第 %d 帧应为 4096 字节 CONTINUE，实际 %d/%d", i, len(f.body), f.state)
		}
	}
	last := dfs[len(dfs)-1]
	if last.state != SubEnd || len(last.body) != 2048 {
		t.Fatalf("最后一帧应为 2048 字节 END，实际 %d/%d", len(last.body), last.state)
	}
	if got := len(concatBodies(dfs)); got != blocks*floppyBlockLength {
		t.Fatalf("数据总量应为 %d，实际 %d", blocks*floppyBlockLength, got)
	}
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("完成帧应为成功: % x", cmpl)
	}
}

func TestFloppyRead12(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbRead12(2879, 1), 1) // the last block
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != floppyBlockLength {
		t.Fatalf("READ_12 应返回一块: %d 帧", len(dfs))
	}
	assertBytes(t, "最后一块", dfs[0].body, expectedBlock(2879, floppyBlockLength))
}

// A read that starts inside the medium but runs past its end: the short read is
// sent with the END state and the command fails with LBA OUT OF RANGE.
func TestFloppyReadTruncatedAtEnd(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbRead10(2879, 2), 1) // only the last block exists

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != floppyBlockLength {
		t.Fatalf("应只送出可读的一块，实际 %d 帧", len(dfs))
	}
	if dfs[0].state != SubEnd {
		t.Fatalf("短读帧应为 END，实际 %d", dfs[0].state)
	}
	assertBytes(t, "最后一块", dfs[0].body, expectedBlock(2879, floppyBlockLength))
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("越过末尾的读应失败: % x", cmpl)
	}
	if h.senseData[2] != 5 || h.senseData[12] != 33 {
		t.Fatalf("sense 应为 5/33，实际 %d/%d", h.senseData[2], h.senseData[12])
	}
}

func TestFloppyReadPastEnd(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbRead10(2880, 1), 1)
	frames := w.take()
	if dfs := decodeDataFrames(t, frames, false, nil, nil); len(dfs) != 0 {
		t.Fatalf("越界读不应发送数据，实际 %d", len(dfs))
	}
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("越界读应失败: % x", cmpl)
	}
	if h.senseData[2] != 5 || h.senseData[12] != 33 {
		t.Fatalf("sense 应为 5/33，实际 %d/%d", h.senseData[2], h.senseData[12])
	}
}

// WRITE_10 on a protected medium is DATA PROTECT (7/0x27) and fails.
//
// Note the order inside UFIProcessor.doWrite: the data element is consumed
// *before* the write-protect check, so the BMC's data has to be present (that is
// what the real exchange looks like too — the CDB arrives first, then the data).
func TestFloppyWriteProtected(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.queue.addData(bytes.Repeat([]byte{0x01}, floppyBlockLength))
	h.handle(cdbWrite10(0, 1), 1)
	frames := w.take()
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("写保护介质上的写应失败: % x", cmpl)
	}
	if h.senseData[2] != 7 || h.senseData[12] != 39 {
		t.Fatalf("sense 应为 7/0x27，实际 %d/%#x", h.senseData[2], h.senseData[12])
	}
}

// WRITE_10 on an unprotected image consumes the queued data element and writes
// it through to the file.
func TestFloppyWrite(t *testing.T) {
	h, w, f := newFloppyHandler(t, false, false)
	if f.isWriteProtect() {
		t.Fatal("写保护标志为 false 且文件可写时不应判定为写保护")
	}
	payload := bytes.Repeat([]byte{0xAB}, floppyBlockLength)
	h.queue.addData(payload) // the BMC sends the data, then the CDB is processed
	h.handle(cdbWrite10(2, 1), 1)

	frames := w.take()
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("写应成功: % x", cmpl)
	}
	got, err := os.ReadFile(f.Path())
	if err != nil {
		t.Fatalf("读回镜像: %v", err)
	}
	assertBytes(t, "写入的块", got[2*floppyBlockLength:3*floppyBlockLength], payload)
}

// The encrypted write path (vmm_compress == 1) unwraps
// `4-byte length || AES-CBC ciphertext` before writing.
func TestFloppyWriteEncrypted(t *testing.T) {
	h, w, f := newFloppyHandler(t, false, true)
	plain := bytes.Repeat([]byte{0xCD}, floppyBlockLength)
	wire, err := WrapPayload(plain, w.key, w.iv)
	if err != nil {
		t.Fatalf("WrapPayload: %v", err)
	}
	h.queue.addData(wire)
	h.handle(cdbWrite10(3, 1), 2)

	frames := w.take()
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("加密写应成功: % x", cmpl)
	}
	got, err := os.ReadFile(f.Path())
	if err != nil {
		t.Fatalf("读回镜像: %v", err)
	}
	assertBytes(t, "加密写入的块", got[3*floppyBlockLength:4*floppyBlockLength], plain)
}

// UFIProcessor's INQUIRY rejects the EVPD bit with 5/0x24 and the reserved bits
// with 5/0x25.
func TestFloppyInquiryRejects(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	evpd := cdbInquiry()
	evpd[1] = 0x01
	h.handle(evpd, 1)
	frames := w.take()
	if dfs := decodeDataFrames(t, frames, false, nil, nil); len(dfs) != 0 {
		t.Fatal("EVPD 位为 1 时不应返回数据")
	}
	if h.senseData[2] != 5 || h.senseData[12] != 36 {
		t.Fatalf("EVPD 应为 5/0x24，实际 %d/%#x", h.senseData[2], h.senseData[12])
	}
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("EVPD 的完成帧应失败: % x", cmpl)
	}

	reserved := cdbInquiry()
	reserved[1] = 0x20
	h.handle(reserved, 1)
	w.take()
	if h.senseData[2] != 5 || h.senseData[12] != 37 {
		t.Fatalf("保留位应为 5/0x25，实际 %d/%#x", h.senseData[2], h.senseData[12])
	}
}

// MODE_SENSE returns the 8-byte header plus the selected pages; page 0x3F
// selects all four (12+32+12+8 = 64 additional bytes) and byte 1 carries
// size-2.
func TestFloppyModeSense(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	h.handle(cdbModeSense6(0, 0x3F), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 {
		t.Fatalf("MODE_SENSE 应有一个数据帧，实际 %d", len(dfs))
	}
	body := dfs[0].body
	if len(body) != 72 {
		t.Fatalf("page 0x3F 应返回 8+64=72 字节，实际 %d", len(body))
	}
	if body[1] != 70 {
		t.Fatalf("byte 1 应为 size-2 = 70，实际 %d", body[1])
	}
	if body[2] != floppyMediumTypeCode {
		t.Fatalf("介质类型码应为 148，实际 %d", body[2])
	}
	if body[3] != 0x80 {
		t.Fatalf("写保护位置位时应为 0x80，实际 %#x", body[3])
	}
	// Page codes in order: 1 (12 bytes), 5 (32), 27 (12), 28 (8).
	if body[8] != 1 || body[20] != 5 || body[52] != 27 || body[64] != 28 {
		t.Fatalf("页顺序不对: % x", body)
	}

	// A single page (28 decimal = 0x1C) keeps the 8-byte header only.
	h.handle(cdbModeSense6(0, 28), 1)
	dfs = decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 16 {
		t.Fatalf("page 28 应返回 16 字节，实际 %d", len(dfs[0].body))
	}
}

func TestFloppyUnsupportedOpcode(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, false)
	cdb := make([]byte, 12)
	cdb[0] = 0x1A // MODE_SENSE_10: not dispatched by UFIProcessor
	h.handle(cdb, 1)
	frames := w.take()
	if cmpl := completionOf(t, frames, OpUFIComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("未支持的命令应失败: % x", cmpl)
	}
	if h.senseData[2] != 5 || h.senseData[12] != 0x24 {
		t.Fatalf("sense 应为 5/0x24，实际 %d/%#x", h.senseData[2], h.senseData[12])
	}
}

// FloppyImage.validCapacity: anything other than 2880 * 512 bytes is rejected
// with code 335 before the device is created.
func TestFloppyCapacityValidation(t *testing.T) {
	bad := writePatternImage(t, "bad.img", 100, 512)
	if _, err := OpenFloppy(bad, false); errCodeOf(err) != ErrCapacity {
		t.Fatalf("尺寸不符应报 335，实际 %v", err)
	}
	if _, err := OpenFloppy("/nonexistent/vmm.img", false); errCodeOf(err) != ErrImageMissing {
		t.Fatalf("不存在的镜像应报 320，实际 %v", err)
	}
	// A protected image stays protected even if the file is writable.
	h, _, _ := newFloppyHandler(t, true, false)
	if !h.floppy.isWriteProtect() {
		t.Fatal("writeProtect=true 应判定为写保护")
	}
	// A read-only file is protected regardless of the flag: ImageIO falls back
	// to read-only mode, and isWriteProtect ORs that in.
	ro := writePatternImage(t, "ro.img", floppyTotalBlocks, floppyBlockLength)
	if err := os.Chmod(ro, 0o444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	rof, err := OpenFloppy(ro, false)
	if err != nil {
		t.Fatalf("只读镜像应能打开: %v", err)
	}
	defer rof.close()
	if !rof.isWriteProtect() {
		t.Fatal("只读文件应判定为写保护")
	}
	if rof.wp {
		t.Fatal("writeProtect 入参为 false 时不应设置该标志")
	}
}

// The encrypted data framing for the floppy: length field = ciphertext+4 and the
// 4-byte prefix keeps the plaintext length.
func TestFloppyEncryptedDataFrames(t *testing.T) {
	h, w, _ := newFloppyHandler(t, true, true)
	h.handle(cdbRead10(0, 1), 0x33)

	frames := w.take()
	var raw []byte
	for _, f := range frames {
		if f[0] == OpUFIData && f[1]&0x0F == SubData {
			raw = f
		}
	}
	if raw == nil {
		t.Fatal("找不到数据帧")
	}
	if got := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7]); got != 4+512 {
		t.Fatalf("长度字段应为 516，实际 %d", got)
	}
	if got := int(raw[12])<<24 | int(raw[13])<<16 | int(raw[14])<<8 | int(raw[15]); got != 512 {
		t.Fatalf("明文长度前缀应为 512，实际 %d", got)
	}
	dfs := decodeDataFrames(t, frames, true, w.key, w.iv)
	if len(dfs) != 1 {
		t.Fatalf("应有 1 个数据帧，实际 %d", len(dfs))
	}
	assertBytes(t, "加密读回的块", dfs[0].body, expectedBlock(0, floppyBlockLength))
}
