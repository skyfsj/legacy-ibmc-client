package kvm

// Regression test: replay a REAL captured BMC stream through the client's
// protocol code and check the decoded results against values established during
// the reverse-engineering.
//
// This is the Go port of test/replay.test.js. Every assertion that existed there
// is kept with the same measured value; the additions are marked "port addition"
// and come from the protocol notes (02-handshake-and-crypto.md §7,
// 03-video-channel.md §3-5, 07-live-verification.md §6).
//
// Fixtures live in the sibling reference repository:
//   ../../huawei-ibmc-kvm-protocol/evidence/session-server-stream.bin  (5946 B, 38 frames)
//   ../../huawei-ibmc-kvm-protocol/evidence/frame-2.bin               (5129 B reassembled frame)

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Fixture-based checks need a capture from YOUR device (the author's contains a real
// screen image and session material, so it is not shipped — see NOTICE.md). When the
// fixture is absent the dependent tests skip instead of failing, so `go test ./...`
// is green in a fresh clone.
func fixtureAvailable(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"../../../docs/protocol/evidence/session-server-stream.bin",
		"../../evidence/session-server-stream.bin",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("未找到抓包固件；这些检查需要你自己的抓包（见 NOTICE.md）")
	return ""
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const (
	streamLen    = 5946
	streamFrames = 38
	frame2Len    = 5129
)

func evidenceDir() string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "..", "huawei-ibmc-kvm-protocol", "evidence")
}

// loadEvidence reads a fixture, skipping the test when the reference repository
// is not checked out next to this one.
func loadEvidence(t *testing.T, name string, wantLen int) []byte {
	t.Helper()
	path := filepath.Join(evidenceDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("找不到证据文件 %s：%v", path, err)
	}
	if len(data) != wantLen {
		t.Fatalf("%s 长度 %d，期望 %d", path, len(data), wantLen)
	}
	return data
}

// parseStream splits a captured stream into wire payloads (each frame's payload
// starts with 00 00 <cmd>).
func parseStream(t *testing.T, stream []byte) [][]byte {
	t.Helper()
	return NewServerFrameParser().Push(stream)
}

func commandHistogram(frames [][]byte) map[byte]int {
	by := map[byte]int{}
	for _, f := range frames {
		by[f[2]]++
	}
	return by
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// ---------------------------------------------------------------------------
// 1. CRC-16/CCITT-FALSE
// ---------------------------------------------------------------------------

func TestCRC16MeasuredValues(t *testing.T) {
	// From the live capture: heartbeat payload {09 00} carried CRC 0xba98
	if got := CRC16([]byte{0x09, 0x00}); got != 0xba98 {
		t.Errorf("CRC16({09 00}) = 0x%04x，期望 0xba98（实测值）", got)
	}
	if got := CRC16([]byte{0x42, 0x00}); got != 0x6bae {
		t.Errorf("CRC16({42 00}) = 0x%04x，期望 0x6bae（实测值）", got)
	}
}

// ---------------------------------------------------------------------------
// 2. Client frame construction must match the capture byte for byte
// ---------------------------------------------------------------------------

func TestBuildFrameMatchesCapture(t *testing.T) {
	// Captured heartbeat: fe f6 0004 6c713278 ba98 0900
	got := BuildFrame(1000000002, []byte{0x09, 0x00})
	if want := "fef600043b9aca02ba980900"; hexOf(got) != want {
		t.Errorf("心跳帧 = %s，期望 %s", hexOf(got), want)
	}
	// Captured GET_SUITE: fe f6 0004 6c713278 6bae 4200
	got = BuildFrame(1000000002, []byte{0x42, 0x00})
	if want := "fef600043b9aca026bae4200"; hexOf(got) != want {
		t.Errorf("GET_SUITE 帧 = %s，期望 %s", hexOf(got), want)
	}
}

// ---------------------------------------------------------------------------
// 3. CONNECT_BLADE encrypted frame layout
// ---------------------------------------------------------------------------

func TestBuildEncryptedFrameLayout(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 24)
	payload := ConnectBladePayload(0, 2)
	if hexOf(payload) != "0600020101" {
		t.Fatalf("ConnectBladePayload(0,2) = %s，期望 0600020101", hexOf(payload))
	}
	f := BuildEncryptedFrame(key, payload, 0x8000|len(payload))
	if len(f) != 35 {
		t.Errorf("帧长 = %d，期望 35", len(f))
	}
	if got := binary.BigEndian.Uint16(f[2:]); got != 0x8007 {
		t.Errorf("长度字段 = 0x%04x，期望 0x8007", got)
	}
	if got := hexOf(f[4:28]); got != hexOf(key) {
		t.Errorf("4..27 的密钥头 = %s，期望 %s", got, hexOf(key))
	}
	if got := hexOf(f[30:]); got != "0600020101" {
		t.Errorf("payload = %s，期望 0600020101", got)
	}
}

// ---------------------------------------------------------------------------
// 4. Parse the real stream frame by frame
// ---------------------------------------------------------------------------

func TestParseRealStream(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	stream := loadEvidence(t, "session-server-stream.bin", streamLen)
	frames := parseStream(t, stream)

	if len(frames) != streamFrames {
		t.Fatalf("解析出 %d 帧，期望 %d", len(frames), streamFrames)
	}
	used := 0
	for _, f := range frames {
		used += len(f) + 4
	}
	if used != len(stream) {
		t.Errorf("消耗 %d / %d 字节（应完全贴合）", used, len(stream))
	}

	got := commandHistogram(frames)
	want := map[byte]int{0x43: 1, 0x40: 2, 0x28: 1, 0x25: 2, 0x02: 30, 0x04: 2}
	if fmt.Sprint(sortedHistogram(got)) != fmt.Sprint(sortedHistogram(want)) {
		t.Errorf("命令分布 = %v，期望 %v", sortedHistogram(got), sortedHistogram(want))
	}
}

// TestParserResyncsAcrossReads feeds the same stream one byte at a time: a real
// TCP socket does not preserve frame boundaries, and the protocol notes require
// half frames to be joined across reads.
func TestParserResyncsAcrossReads(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	stream := loadEvidence(t, "session-server-stream.bin", streamLen)
	want := parseStream(t, stream)

	p := NewServerFrameParser()
	var got [][]byte
	for i := 0; i < len(stream); i++ {
		got = append(got, p.Push(stream[i:i+1])...)
	}
	if len(got) != len(want) {
		t.Fatalf("逐字节喂入得到 %d 帧，整体喂入得到 %d 帧", len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("第 %d 帧不一致:\n 逐字节 %s\n 整体   %s", i, hexOf(got[i]), hexOf(want[i]))
		}
	}
}

// sortedHistogram makes map comparison deterministic in failure messages.
func sortedHistogram(m map[byte]int) []string {
	out := make([]string, 0, len(m))
	for k := 0; k <= 0xff; k++ {
		if v, ok := m[byte(k)]; ok {
			out = append(out, fmt.Sprintf("0x%02x:%d", k, v))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 5. Suite list
// ---------------------------------------------------------------------------

func TestParseSuiteListFromStream(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	frames := parseStream(t, loadEvidence(t, "session-server-stream.bin", streamLen))
	var p []byte
	for _, f := range frames {
		if f[2] == RspKvmSuiteList {
			p = f
			break
		}
	}
	if p == nil {
		t.Fatal("流里没有 0x43 套件表")
	}
	sl := ParseSuiteList(p)
	if sl.Count != 3 {
		t.Errorf("count = %d，期望 3", sl.Count)
	}
	if !sl.LengthOK {
		t.Errorf("长度自校验失败（count*5+3 == dlen-2 应成立）")
	}
	want := []Suite{{Algo: 1, Iterations: 5000}, {Algo: 2, Iterations: 10000}, {Algo: 3, Iterations: 10000}}
	if fmt.Sprint(sl.Suites) != fmt.Sprint(want) {
		t.Errorf("套件表 = %v，期望 %v", sl.Suites, want)
	}
	if su, ok := sl.Find(3); !ok || su.Iterations != 10000 {
		t.Errorf("Find(3) = %v/%v，期望 algo=3 iterations=10000", su, ok)
	}
}

// ---------------------------------------------------------------------------
// 6. kvm_key derivation (structural: the capture's JNLP is not in this repo)
// ---------------------------------------------------------------------------

func TestDeriveKvmKeyMatchesPBKDF2(t *testing.T) {
	plain := make([]byte, 48)
	copy(plain, []byte("0123456789abcdef0123456789abcdef")) // 32B password
	salt, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	copy(plain[32:], salt)

	got, err := DeriveKvmKey(plain, 10000, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 48 {
		t.Fatalf("kvm_key 长度 = %d，期望 48", len(got))
	}
	raw, err := pbkdf2.Key(sha256.New, "0123456789abcdef0123456789abcdef", salt, 10000, 48)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(got) != hexOf(Reverse4(raw)) {
		t.Errorf("kvm_key = %s，期望 Reverse4(PBKDF2-SHA256) = %s", hexOf(got), hexOf(Reverse4(raw)))
	}
}

func TestReverse4IsAnInvolution(t *testing.T) {
	b, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	if hexOf(Reverse4(Reverse4(b))) != hexOf(b) {
		t.Errorf("Reverse4(Reverse4(x)) != x（%s）", hexOf(Reverse4(Reverse4(b))))
	}
	// and it must not modify the input
	orig := hexOf(b)
	_ = Reverse4(b)
	if hexOf(b) != orig {
		t.Errorf("Reverse4 修改了输入：%s -> %s", orig, hexOf(b))
	}
}

// NOTE: a test asserting encodeKey against the live capture was removed for the public
// repo — that value is derived from a real session's JNLP and is a credential.
// Derivation correctness is still covered by the synthetic round-trip tests above.

// TestDeriveEncodeKeyAlgoSelection checks the HMAC choice: algo 2 = SHA-1,
// algo 3 and the unknown fallback = SHA-256.
func TestDeriveEncodeKeyAlgoSelection(t *testing.T) {
	salt := []byte("0123456789abcdef")
	sha1Raw, err := pbkdf2.Key(sha1.New, "secret", salt, 1000, 24)
	if err != nil {
		t.Fatal(err)
	}
	sha256Raw, err := pbkdf2.Key(sha256.New, "secret", salt, 1000, 24)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := DeriveEncodeKey("secret", salt, 1000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(got2) != hexOf(Reverse4(sha1Raw)) {
		t.Errorf("algo 2 应使用 HMAC-SHA1：%s", hexOf(got2))
	}
	got3, err := DeriveEncodeKey("secret", salt, 1000, 3)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(got3) != hexOf(Reverse4(sha256Raw)) {
		t.Errorf("algo 3 应使用 HMAC-SHA256：%s", hexOf(got3))
	}
	got1, err := DeriveEncodeKey("secret", salt, 1000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(got1) != hexOf(got3) {
		t.Errorf("未知 algo 应回落到 SHA-256（JS `HMAC_NAME[algo] || 'sha256'`）")
	}
}

// ---------------------------------------------------------------------------
// 6b. AES-128-CBC without padding (port addition: NIST SP 800-38A vector F.2.1)
// ---------------------------------------------------------------------------

func TestAESCBCNoPaddingNISTVector(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	want := "7649abac8119b246cee98e9b12e9197d"

	ct, err := AESEncryptNoPad(pt, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(ct) != want {
		t.Errorf("AES-128-CBC 密文 = %s，期望 %s", hexOf(ct), want)
	}
	back, err := AESDecryptNoPad(ct, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(back) != hexOf(pt) {
		t.Errorf("解密结果 = %s，期望 %s", hexOf(back), hexOf(pt))
	}
	// no padding is added by the primitive: a 20-byte input must be rejected
	if _, err := AESEncryptNoPad(bytes.Repeat([]byte{1}, 20), key, iv); err == nil {
		t.Errorf("非 16 倍数输入应报错，而不是自动填充")
	}
	if pad := ZeroPad(bytes.Repeat([]byte{1}, 20)); len(pad) != 32 {
		t.Errorf("ZeroPad(20) 长度 = %d，期望 32", len(pad))
	}
}

// ---------------------------------------------------------------------------
// 7. Frame-header sub-packet of the real frame
// ---------------------------------------------------------------------------

// realStream returns the parsed frames plus the header sub-packets of every
// 0x02 frame, which is what the session's onImage() sees after the 4-byte
// payload prefix is stripped.
func realStream(t *testing.T) (frames [][]byte, headers [][]byte) {
	t.Helper()
	frames = parseStream(t, loadEvidence(t, "session-server-stream.bin", streamLen))
	for _, f := range frames {
		if f[2] == RspImageData && binary.BigEndian.Uint16(f[4:6]) == 0 {
			headers = append(headers, sub(f, 4, len(f)))
		}
	}
	return frames, headers
}

func TestRealFrameHeaderFields(t *testing.T) {
	_, headers := realStream(t)

	var real []byte
	for _, h := range headers {
		if int(binary.BigEndian.Uint32(sub(h, 3, 7))) > 0 {
			real = h
			break
		}
	}
	if real == nil {
		t.Fatal("应存在 packLenght > 0 的真实帧")
	}
	total := int(binary.BigEndian.Uint32(sub(real, 3, 7)))
	flags := real[7]
	width := (int(flags&0x7f) << 8) | int(real[8])
	height := int(binary.BigEndian.Uint16(sub(real, 9, 11)))

	if width != 800 || height != 600 {
		t.Errorf("分辨率 = %dx%d，期望 800x600", width, height)
	}
	if blockX, blockY := (width+63)/64, (height+63)/64; blockX != 13 || blockY != 10 {
		t.Errorf("块网格 = %dx%d，期望 13x10", blockX, blockY)
	}
	if got := real[16] & 0x0f; got != 7 {
		t.Errorf("帧头 DQT 索引 = %d，期望 7", got)
	}
	if got := (real[16] >> 7) & 1; got != 0 {
		t.Errorf("I 帧标志 = %d，期望 0（非 I 帧）", got)
	}
	if got := binary.BigEndian.Uint16(sub(real, 12, 14)); got != 0xffff {
		t.Errorf("光标 X = 0x%04x，期望 0xffff（隐藏哨兵）", got)
	}
	if got := binary.BigEndian.Uint16(sub(real, 14, 16)); got != 0xffff {
		t.Errorf("光标 Y = 0x%04x，期望 0xffff（隐藏哨兵）", got)
	}
	if total != 5128 {
		t.Errorf("packLenght = %d，期望 5128", total)
	}
	if got := (flags >> 7) & 1; got != 0 {
		t.Errorf("差分标志 = %d，期望 0（该真实帧应非差分帧）", got)
	}

	// The frame header sub-packet (seq 0) is not encrypted: every header field is
	// readable straight off the wire.
	if got := real[2]; got != 2 {
		t.Errorf("帧号 = %d，期望 2", got)
	}
	if got := real[11]; got != 0xdc {
		t.Errorf("buf[11] = 0x%02x，期望 0xdc（实测恒为 220）", got)
	}
	if real[7] != 0x03 {
		t.Errorf("flags = 0x%02x，期望 0x03（非差分 + 宽度高 3 位）", real[7])
	}
}

func TestNoChangeFrames(t *testing.T) {
	_, headers := realStream(t)
	var noChange [][]byte
	for _, h := range headers {
		if binary.BigEndian.Uint32(sub(h, 3, 7)) == 0 {
			noChange = append(noChange, h)
		}
	}
	if len(noChange) != 5 {
		t.Fatalf("「无变化」帧头 %d 个，期望 5 个", len(noChange))
	}
	for i, d := range noChange {
		if (d[7]>>7)&1 != 1 {
			t.Errorf("第 %d 个无变化帧的差分标志应为 1", i)
		}
		if (d[16]>>7)&1 != 1 {
			t.Errorf("第 %d 个无变化帧的 I 帧标志应为 1", i)
		}
	}
}

func TestImageSubpacketAccounting(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	frames, _ := realStream(t)
	byFrame := map[int][]int{}
	for _, f := range frames {
		if f[2] != RspImageData {
			continue
		}
		no := int(f[6])
		byFrame[no] = append(byFrame[no], int(binary.BigEndian.Uint16(f[4:6])))
	}
	if len(byFrame) != 6 {
		t.Fatalf("图像帧数 = %d，期望 6", len(byFrame))
	}
	f2 := byFrame[2]
	if len(f2) != 25 {
		t.Fatalf("帧 2 子包数 = %d，期望 25", len(f2))
	}
	for i, seq := range f2 {
		if seq != i {
			t.Fatalf("帧 2 序号不连续：位置 %d 是 %d", i, seq)
		}
	}
	for no, seqs := range byFrame {
		if no == 2 {
			continue
		}
		if len(seqs) != 1 {
			t.Errorf("帧 %d 应只有帧头子包，实际 %d 个", no, len(seqs))
		}
	}
}

// ---------------------------------------------------------------------------
// 8. Reassembled frame fixture (port addition — frame-2.bin is the buffer the
//    protocol notes measured at 5129 = packLenght+1 bytes)
// ---------------------------------------------------------------------------

type blockInfo struct {
	index   int
	offset  int
	zipType int
	syclen  int
}

// walkBlockStream walks the reassembled buffer with the vendor ImageDecoder's
// stepping rules (03-video-channel.md §3-5). Only the block types that occur in
// this fixture are implemented; anything else fails loudly.
func walkBlockStream(buf []byte, blockX, blockY int) ([]blockInfo, error) {
	nBlocks := blockX * blockY
	if len(buf) < 2 {
		return nil, fmt.Errorf("缓冲区只有 %d 字节", len(buf))
	}
	var blocks []blockInfo
	i := 1 // 块流从索引 1 开始（buf[0] = 差分标志）
	for n := 0; n < nBlocks; n++ {
		if i >= len(buf) {
			return nil, fmt.Errorf("块 %d 越界：offset %d，缓冲 %d 字节", n, i, len(buf))
		}
		desc := buf[i]
		zipType := int((desc & 0xe0) >> 5)
		var syclen int
		switch zipType {
		case 2, 3: // 裸 JPEG 扫描数据：描述符 + 长度 u16be + 数据
			if i+2 >= len(buf) {
				return nil, fmt.Errorf("块 %d 的 JPEG 长度字段越界", n)
			}
			syclen = 3 + int(binary.BigEndian.Uint16(buf[i+1:i+3]))
		case 4, 5, 6: // 空操作 / 复制上一行 / 复制左邻：单字节
			syclen = 1
		case 0, 1:
			return nil, fmt.Errorf("块 %d 是 RLE 块（zipType=%d）—— 本样本不含 RLE 块，测试未实现其步进", n, zipType)
		default:
			return nil, fmt.Errorf("块 %d 的 zipType=%d 未知", n, zipType)
		}
		if i+syclen > len(buf) {
			return nil, fmt.Errorf("块 %d（zip=%d）需要 %d 字节，只剩 %d", n, zipType, syclen, len(buf)-i)
		}
		blocks = append(blocks, blockInfo{index: n, offset: i, zipType: zipType, syclen: syclen})
		i += syclen
	}
	if i != len(buf) {
		return nil, fmt.Errorf("块流结束于 offset %d，缓冲长度 %d（差 %d 字节）", i, len(buf), len(buf)-i)
	}
	return blocks, nil
}

func TestReassembledFrameBuffer(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	frame := loadEvidence(t, "frame-2.bin", frame2Len)
	if frame[0] != 0 {
		t.Errorf("buf[0] = %d，期望 0（该帧为非差分帧）", frame[0])
	}

	blocks, err := walkBlockStream(frame, 13, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 130 {
		t.Fatalf("块数 = %d，期望 130", len(blocks))
	}

	hist := map[string]int{}
	for _, b := range blocks {
		hist[fmt.Sprintf("%d", b.zipType)]++
	}
	want := map[string]int{"2": 10, "3": 3, "5": 96, "6": 21}
	if fmt.Sprint(hist) != fmt.Sprint(want) {
		t.Errorf("块类型分布 = %v，期望 %v（07 章 §6 实测）", hist, want)
	}
	maxScan := 0
	for _, b := range blocks {
		if b.zipType == 2 || b.zipType == 3 {
			if scan := b.syclen - 3; scan > maxScan {
				maxScan = scan
			}
		}
	}
	if maxScan != 600 {
		t.Errorf("最大 JPEG 裸扫描长度 = %d，期望 600（远大于 250 的子包上限）", maxScan)
	}
}

// TestFrame2MatchesStreamHeaderLength ties the two fixtures together: the
// reassembled buffer must be exactly packLenght+1 bytes long.
func TestFrame2MatchesStreamHeaderLength(t *testing.T) {
	fixtureAvailable(t) // skips when the capture is not present
	frame := loadEvidence(t, "frame-2.bin", frame2Len)
	_, headers := realStream(t)
	var packLenght = -1
	for _, h := range headers {
		if total := int(binary.BigEndian.Uint32(sub(h, 3, 7))); total > 0 {
			packLenght = total
			break
		}
	}
	if packLenght < 0 {
		t.Fatal("流里没有非零 packLenght 的帧头")
	}
	if len(frame) != packLenght+1 {
		t.Errorf("frame-2.bin 长度 %d，期望 packLenght+1 = %d", len(frame), packLenght+1)
	}
}

// ---------------------------------------------------------------------------
// 9. codeKey parsing (JNLP verifyValue -> int32, JS parseInt(...) | 0)
// ---------------------------------------------------------------------------

func TestParseCodeKey(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"1000000002", 1000000002},
		{"1000000001", 1000000001},
		{"4294967296", 0},              // 2^32 wraps to 0, exactly like JS `| 0`
		{"", 0},                        // missing parameter
		{"abc", 0},                     // not a number
		{"1000000002junk", 1000000002}, // parseInt stops at the first non-digit
	}
	for _, tc := range cases {
		if got := jsParseInt32(tc.in); got != tc.want {
			t.Errorf("jsParseInt32(%q) = %d，期望 %d", tc.in, got, tc.want)
		}
	}
}
