package vmm

// SFF-8020i (virtual CD-ROM) tests against a synthetic ISO file.
//
// The expectations are the fixed payloads of SFF8020iProcessor.java and
// CDROMDriver/CDROMImage, plus the chunking rules of sendData
// (CDROM_PACKET_SIZE = 32768, state 1 = continue, 3 = end).

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

// SFF8020iProcessor.inquiryData, byte for byte:
// 05 80 00 21 1F 00 00 00 "Virtual DVD-ROM VM 1.1.0 225".
const cdromInquiryHex = "058000211f0000005669727475616c204456442d524f4d20564d20312e312e3020323235"

func newCDROMHandler(t *testing.T, blocks int, compress bool) (*sffHandler, *fakeWire, *CDROM) {
	t.Helper()
	path := writePatternImage(t, "test.iso", blocks, blockLength)
	cd, err := OpenISO(path)
	if err != nil {
		t.Fatalf("OpenISO: %v", err)
	}
	w := &fakeWire{compress: compress}
	if compress {
		w.key = bytes.Repeat([]byte{0x11}, 16)
		w.iv = bytes.Repeat([]byte{0x22}, 16)
	}
	h := newSFFHandler(w, cd)
	t.Cleanup(func() { _ = cd.close() })
	return h, w, cd
}

func TestCDROMInquiryBytes(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	h.handle(cdbInquiry(), 0x42)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 1 {
		t.Fatalf("INQUIRY 应只有一个数据帧，实际 %d", len(dfs))
	}
	want, _ := hex.DecodeString(cdromInquiryHex)
	if !bytes.Equal(dfs[0].body, want) {
		t.Fatalf("INQUIRY 应答:\n got %s\nwant %s", hex.EncodeToString(dfs[0].body), cdromInquiryHex)
	}
	if len(dfs[0].body) != 36 {
		t.Fatalf("INQUIRY 应为 36 字节，实际 %d", len(dfs[0].body))
	}
	if dfs[0].state != SubEnd {
		t.Fatalf("单个数据帧应为 END(3)，实际 %d", dfs[0].state)
	}
	if dfs[0].id != 0x42 {
		t.Fatalf("事务 ID 应回填 CDB 的字节 3，实际 0x%02x", dfs[0].id)
	}
	if dfs[0].op != OpSFFData {
		t.Fatalf("光驱数据帧操作码应为 4，实际 %d", dfs[0].op)
	}
	cmpl := completionOf(t, frames, OpSFFComplete)
	if cmpl == nil {
		t.Fatal("缺少 SFF 完成帧")
	}
	if cmpl[1] != CmdOK {
		t.Fatalf("INQUIRY 成功时结果应为 0，实际 %d", cmpl[1])
	}
	if cmpl[3] != 0x42 {
		t.Fatalf("完成帧应带同一事务 ID，实际 0x%02x", cmpl[3])
	}
}

func TestCDROMReadCapacity(t *testing.T) {
	// 100 blocks -> last LBA 99, block length 2048 (bytes 6..7 = 08 00).
	h, w, _ := newCDROMHandler(t, 100, false)
	h.handle(cdbReadCapacity(), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 8 {
		t.Fatalf("READ_CAPACITY 应返回 8 字节，实际 %d 帧", len(dfs))
	}
	want := []byte{0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x08, 0x00}
	assertBytes(t, "READ_CAPACITY", dfs[0].body, want)
}

// A 64-block READ_10 fills exactly one 128 KiB buffer and is sent as four
// 32768-byte frames, the last marked END, followed by a success completion.
func TestCDROMReadChunking(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 200, false)
	h.handle(cdbRead10(0, 64), 7)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 4 {
		t.Fatalf("64 块的 READ_10 应分 4 帧 (32768 字节/帧)，实际 %d", len(dfs))
	}
	for i, f := range dfs {
		if len(f.body) != CDROMPacketSize {
			t.Fatalf("第 %d 帧长度应为 %d，实际 %d", i, CDROMPacketSize, len(f.body))
		}
		wantState := byte(SubContinue)
		if i == len(dfs)-1 {
			wantState = SubEnd
		}
		if f.state != wantState {
			t.Fatalf("第 %d 帧 state 应为 %d，实际 %d", i, wantState, f.state)
		}
	}
	// The concatenated body is blocks 0..63, including block 64 read ahead for
	// the next request.
	body := concatBodies(dfs)
	if len(body) != 64*blockLength {
		t.Fatalf("数据总量应为 %d，实际 %d", 64*blockLength, len(body))
	}
	assertBytes(t, "第一块", body[:blockLength], expectedBlock(0, blockLength))
	assertBytes(t, "第 63 块", body[63*blockLength:], expectedBlock(63, blockLength))

	cmpl := completionOf(t, frames, OpSFFComplete)
	if cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("完成帧应为成功: % x", cmpl)
	}
	// The Java's read-ahead leaves the next window in the cache.
	if h.cacheBlockNum != 64 || h.cacheLba != 64 {
		t.Fatalf("预读缓存应为 (lba=64, blocks=64)，实际 (lba=%d, blocks=%d)", h.cacheLba, h.cacheBlockNum)
	}
}

// The Java reads at most one dataBuffer2 (128 KiB = 64 blocks) per READ and
// raises an address error inside read() for anything longer — but doRead then
// calls setSenseKeys(0,0,0,0) unconditionally after a non-zero read, wiping that
// error, so the command still completes successfully with a truncated transfer.
// The quirk is reproduced here.
func TestCDROMReadLargerThanBuffer(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 200, false)
	h.handle(cdbRead10(0, 96), 9)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 4 {
		t.Fatalf("应只发送一个缓冲区的数据（4 帧），实际 %d", len(dfs))
	}
	if got := len(concatBodies(dfs)); got != 131072 {
		t.Fatalf("应发送 131072 字节，实际 %d", got)
	}
	cmpl := completionOf(t, frames, OpSFFComplete)
	if cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("doRead 会用 setSenseKeys(0,0,0,0) 覆盖读错误，完成帧应为成功: % x", cmpl)
	}
	if h.senseData[2] != 0 || h.senseData[12] != 0 {
		t.Fatalf("sense 应被 doRead 清零，实际 %d/%d", h.senseData[2], h.senseData[12])
	}
}

// READ_12 takes its block count from bytes 6..9.
func TestCDROMRead12(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 200, false)
	h.handle(cdbRead12(128, 1), 3)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != blockLength {
		t.Fatalf("READ_12 应返回一块: %d 帧", len(dfs))
	}
	assertBytes(t, "READ_12 第 128 块", dfs[0].body, expectedBlock(128, blockLength))
}

// The cache is a real read-ahead: after serving (lba=0, 64 blocks) the handler
// has the next window buffered, so a sequential request is answered from memory.
// Rewriting those blocks in the file must not change the answer.
func TestCDROMReadAheadCache(t *testing.T) {
	h, w, cd := newCDROMHandler(t, 400, false)
	h.handle(cdbRead10(0, 64), 1)
	w.take()

	// Corrupt blocks 64..127 on disk.
	junk := bytes.Repeat([]byte{0xEE}, 64*blockLength)
	f, err := os.OpenFile(cd.Path(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("打开镜像: %v", err)
	}
	if _, err := f.WriteAt(junk, 64*blockLength); err != nil {
		t.Fatalf("改写镜像: %v", err)
	}
	_ = f.Close()

	h.handle(cdbRead10(64, 64), 2)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	body := concatBodies(dfs)
	if len(body) != 64*blockLength {
		t.Fatalf("缓存命中应返回 64 块，实际 %d 字节", len(body))
	}
	assertBytes(t, "缓存中第 64 块（磁盘上已被改写）", body[:blockLength], expectedBlock(64, blockLength))
	if bytes.Equal(body[:16], junk[:16]) {
		t.Fatal("第二个请求走了磁盘而不是预读缓存")
	}
}

func TestCDROMReadPastEnd(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	h.handle(cdbRead10(8, 1), 1) // LBA 8 does not exist in an 8-block image

	frames := w.take()
	if dfs := decodeDataFrames(t, frames, false, nil, nil); len(dfs) != 0 {
		t.Fatalf("越界读不应发送数据，实际 %d 帧", len(dfs))
	}
	cmpl := completionOf(t, frames, OpSFFComplete)
	if cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("越界读应以失败完成: % x", cmpl)
	}
	if h.senseData[2] != 5 || h.senseData[12] != 33 {
		t.Fatalf("sense 应为 5/33，实际 %d/%d", h.senseData[2], h.senseData[12])
	}
}

func TestCDROMZeroLengthRead(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	h.handle(cdbRead10(0, 0), 1)
	frames := w.take()
	if dfs := decodeDataFrames(t, frames, false, nil, nil); len(dfs) != 0 {
		t.Fatalf("0 块的读不应发送数据帧，实际 %d", len(dfs))
	}
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("0 块的读应以成功完成: % x", cmpl)
	}
}

// Unsupported opcodes answer ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE
// (sense 5/0x24) and fail the completion; REQUEST_SENSE then returns the 18-byte
// template with that key and ASC.
func TestCDROMUnsupportedOpcodeAndSense(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	write := cdbWrite10(0, 1) // the CD-ROM has no write path
	h.handle(write, 0x11)

	frames := w.take()
	if dfs := decodeDataFrames(t, frames, false, nil, nil); len(dfs) != 0 {
		t.Fatalf("不支持的写命令不应发送数据，实际 %d", len(dfs))
	}
	cmpl := completionOf(t, frames, OpSFFComplete)
	if cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("不支持的写命令应失败: % x", cmpl)
	}
	if h.senseData[2] != 5 || h.senseData[12] != 0x24 {
		t.Fatalf("sense 应为 5/0x24，实际 %d/%#x", h.senseData[2], h.senseData[12])
	}

	// REQUEST_SENSE returns the template unchanged (result stays 0 because the
	// Java excludes REQUEST_SENSE from the failure rule).
	h.handle(cdbRequestSense(), 0x12)
	frames = w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != senseLength {
		t.Fatalf("REQUEST_SENSE 应返回 18 字节: %d 帧", len(dfs))
	}
	want := []byte{0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00}
	assertBytes(t, "REQUEST_SENSE", dfs[0].body, want)
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("REQUEST_SENSE 的完成帧应成功: % x", cmpl)
	}
}

func TestCDROMModeSense(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	h.handle(cdbModeSense6(0, 0x3F), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != 8 {
		t.Fatalf("CDROMImage.modeSense 应返回 8 字节: %d 帧", len(dfs))
	}
	// Ready unit (testUnitReady == 3) -> byte 2 = 1, byte 1 = 6.
	want := []byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	assertBytes(t, "MODE_SENSE", dfs[0].body, want)
}

func TestCDROMReadTOC(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 100, false)
	h.handle(cdbReadTOC(0, 0), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 {
		t.Fatalf("READ_TOC 应有一个数据帧，实际 %d", len(dfs))
	}
	body := dfs[0].body
	if len(body) < 20 {
		t.Fatalf("READ_TOC 应答太短: % x", body)
	}
	// First track (1) and the lead-out (0xAA = 170) with the last LBA 99.
	if body[2] != 1 || body[3] != 1 {
		t.Fatalf("TOC 头不对: % x", body[:4])
	}
	if body[6] != 1 {
		t.Fatalf("第一个描述符的 track 号应为 1: % x", body[4:12])
	}
	if body[14] != 0xAA {
		t.Fatalf("第二个描述符应为 lead-out (0xAA): % x", body[12:20])
	}
	if got := int(body[16])<<24 | int(body[17])<<16 | int(body[18])<<8 | int(body[19]); got != 100 {
		t.Fatalf("lead-out 的 LBA 应为 100，实际 %d", got)
	}
	// bytes 0..1 carry the descriptor length minus 2 (len 20 -> 18).
	if int(body[0])<<8|int(body[1]) != 18 {
		t.Fatalf("TOC 长度字段应为 18，实际 %d", int(body[0])<<8|int(body[1]))
	}
}

// Start/stop unit: eject unloads, eject+start reloads, anything else is
// ILLEGAL REQUEST (CDROMImage.startStopUnit raises VMException(252)).
func TestCDROMStartStopUnit(t *testing.T) {
	h, w, cd := newCDROMHandler(t, 8, false)

	stopEject := make([]byte, 12)
	stopEject[0] = 0x1B
	stopEject[4] = 0x02 // eject, not start
	h.handle(stopEject, 1)
	w.take()
	if cd.mediaState() != stateMediumNotPresent {
		t.Fatalf("eject 后介质状态应为 0，实际 %d", cd.mediaState())
	}

	load := make([]byte, 12)
	load[0] = 0x1B
	load[4] = 0x03 // eject + start
	h.handle(load, 1)
	w.take()
	if cd.mediaState() != stateMediumReady {
		t.Fatalf("装载后介质状态应为 3，实际 %d", cd.mediaState())
	}

	neither := make([]byte, 12)
	neither[0] = 0x1B
	h.handle(neither, 1)
	frames := w.take()
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("既非 eject 也非 start 应失败: % x", cmpl)
	}
}

// With vmm_compress == 1 each data frame carries `4-byte plaintext length ||
// AES-CBC ciphertext`, and the frame's length field is the ciphertext length
// plus four.
func TestCDROMEncryptedDataFrames(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, true)
	h.handle(cdbInquiry(), 0x21)

	frames := w.take()
	dfs := decodeDataFrames(t, frames, true, w.key, w.iv)
	if len(dfs) != 1 {
		t.Fatalf("应有一个数据帧，实际 %d", len(dfs))
	}
	if len(dfs[0].body) != 36 {
		t.Fatalf("解出的 INQUIRY 应为 36 字节，实际 %d", len(dfs[0].body))
	}
	want, _ := hex.DecodeString(cdromInquiryHex)
	assertBytes(t, "加密模式的 INQUIRY", dfs[0].body, want)

	// Inspect the raw frame: length field = 4 + padded(36) = 4 + 48.
	var raw []byte
	for _, f := range frames {
		if f[0] == OpSFFData && f[1]&0x0F == SubData {
			raw = f
		}
	}
	if raw == nil {
		t.Fatal("找不到数据帧")
	}
	if got := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7]); got != 4+48 {
		t.Fatalf("加密帧长度字段应为 52，实际 %d", got)
	}
	if len(raw) != HeaderSize+52 {
		t.Fatalf("加密帧总长应为 %d，实际 %d", HeaderSize+52, len(raw))
	}
	if got := int(raw[12])<<24 | int(raw[13])<<16 | int(raw[14])<<8 | int(raw[15]); got != 36 {
		t.Fatalf("明文长度前缀应为 36，实际 %d", got)
	}
}

// A zero-length READ_TOC still emits a 12-byte END frame with length 0
// (SFF8020iProcessor.sendData's special case).
func TestCDROMZeroLengthEndFrame(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	toc := cdbReadTOC(0, 0)
	toc[8], toc[9] = 0, 0 // allocation length 0 -> tocDataLen is truncated to 0
	h.handle(toc, 4)

	frames := w.take()
	found := false
	for _, f := range frames {
		hdr, _ := DecodeHeader(f)
		if hdr.Op == OpSFFData && hdr.Length == 0 && len(f) == HeaderSize {
			if hdr.DataState() != SubEnd || hdr.DataKind() != SubData {
				t.Fatalf("零长度帧应带 state=END/data=1: 0x%02x", hdr.Sub)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少零长度 END 帧: %v", w.hexFrames())
	}
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("完成帧应为成功: % x", cmpl)
	}
}

// TEST_UNIT_READY_EXP (74) always reports failure, even with no sense key.
func TestCDROMTestUnitReadyExp(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	cdb := make([]byte, 12)
	cdb[0] = 0x4A
	h.handle(cdb, 1)
	cmpl := completionOf(t, w.take(), OpSFFComplete)
	if cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("TEST_UNIT_READY_EXP 应无条件失败: % x", cmpl)
	}
}

// The start track byte is signed in the Java (`byte startTrack = command[6]`),
// so 0xAA (= the lead-out track, -86 as a byte) still takes the "startTrack <= 1"
// path and produces both descriptors. This pins that quirk.
func TestCDROMReadTOCSignedStartTrack(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 100, false)
	h.handle(cdbReadTOC(0, 0xAA), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 {
		t.Fatalf("READ_TOC 应有一个数据帧，实际 %d", len(dfs))
	}
	body := dfs[0].body
	if len(body) != 20 {
		t.Fatalf("0xAA 起始轨道应给出两个描述符（20 字节），实际 %d", len(body))
	}
	if body[6] != 1 || body[14] != 0xAA {
		t.Fatalf("应同时含 track 1 与 lead-out: % x", body)
	}

	// A start track of 2 is not supported by the Java's format 0 branch.
	h.handle(cdbReadTOC(0, 2), 1)
	frames := w.take()
	if h.senseData[2] != 2 || h.senseData[12] != 58 {
		t.Fatalf("startTrack=2 的 catch 落点应为 2/58，实际 %d/%d", h.senseData[2], h.senseData[12])
	}
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdFail {
		t.Fatalf("startTrack=2 应失败: % x", cmpl)
	}
}

// A read that starts inside the medium but crosses its end: read() reports the
// address error, doRead then wipes it with setSenseKeys(0,0,0,0) and still sends
// the bytes it got (with a success completion). Ported as-is.
func TestCDROMReadTruncatedAtEnd(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	h.handle(cdbRead10(7, 2), 1) // only block 7 exists

	frames := w.take()
	dfs := decodeDataFrames(t, frames, false, nil, nil)
	if len(dfs) != 1 || len(dfs[0].body) != blockLength {
		t.Fatalf("应只送出可读的一块，实际 %d 帧", len(dfs))
	}
	assertBytes(t, "第 7 块", dfs[0].body, expectedBlock(7, blockLength))
	if cmpl := completionOf(t, frames, OpSFFComplete); cmpl == nil || cmpl[1] != CmdOK {
		t.Fatalf("doRead 会清掉读错误，完成帧应为成功: % x", cmpl)
	}
	if h.senseData[2] != 0 {
		t.Fatalf("sense 应被清为 0，实际 %d", h.senseData[2])
	}
}

// Swapping the image (the vendor UI's "change disk") is picked up by the next
// command: checkChangeDisk -> insert() makes the new file current.
func TestCDROMChangeDisk(t *testing.T) {
	h, w, _ := newCDROMHandler(t, 8, false)
	bigger := writePatternImage(t, "bigger.iso", 32, blockLength)

	if err := h.cdrom.changeDisk(bigger); err != nil {
		t.Fatalf("changeDisk: %v", err)
	}
	if !h.cdrom.isChangeDisk() {
		t.Fatal("changeDisk 应置位换盘标志")
	}
	h.handle(cdbReadCapacity(), 1)
	dfs := decodeDataFrames(t, w.take(), false, nil, nil)
	if len(dfs) != 1 {
		t.Fatalf("READ_CAPACITY 应有一帧，实际 %d", len(dfs))
	}
	// 32 blocks -> last LBA 31 = 0x1f.
	want := []byte{0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x08, 0x00}
	assertBytes(t, "换盘后的容量", dfs[0].body, want)

	// Ejecting then reloading uses the old path again.
	if err := h.cdrom.changeDisk(""); err != nil {
		t.Fatalf("changeDisk(\"\"): %v", err)
	}
	h.handle(cdbRequestSense(), 1)
	w.take()
	if h.cdrom.mediaState() != stateMediumNotPresent {
		t.Fatalf("弹出后介质状态应为 0，实际 %d", h.cdrom.mediaState())
	}
}

func TestCDROMMissingImage(t *testing.T) {
	_, err := OpenISO("/nonexistent/vmm-test.iso")
	if err == nil {
		t.Fatal("不存在的镜像应报错")
	}
	if code := errCodeOf(err); code != ErrImageMissing {
		t.Fatalf("错误码应为 320，实际 %d", code)
	}
	if _, err := OpenISO(t.TempDir()); errCodeOf(err) != ErrImageIsDir {
		t.Fatalf("目录应报 321，实际 %d", errCodeOf(err))
	}
}
