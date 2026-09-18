package vmm

// Shared test harness for the device (SCSI) tests: a recording wire that stands
// in for the session, synthetic images and CDB builders.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeWire is the SCSI layer's view of a session: it records every frame instead
// of writing to a socket.
type fakeWire struct {
	mu       sync.Mutex
	frames   [][]byte
	compress bool
	key      []byte
	iv       []byte
	stopped  bool
	logs     []string
}

func (w *fakeWire) send(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, append([]byte(nil), frame...))
	return nil
}

func (w *fakeWire) isStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

func (w *fakeWire) encryptPayloads() bool { return w.compress }

func (w *fakeWire) secret() (key, iv []byte) { return w.key, w.iv }

func (w *fakeWire) logf(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = append(w.logs, format)
}

func (w *fakeWire) take() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.frames
	w.frames = nil
	return out
}

func (w *fakeWire) hexFrames() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, len(w.frames))
	for i, f := range w.frames {
		out[i] = hex.EncodeToString(f)
	}
	return out
}

// dataFrame is one decoded UFI/SFF data frame.
type dataFrame struct {
	op     byte
	state  byte
	id     byte
	length uint32
	body   []byte
}

// decodeDataFrames keeps only the data frames (low nibble 1), decoding each body
// with the wire's key material when the payload is encrypted.
func decodeDataFrames(t *testing.T, frames [][]byte, compress bool, key, iv []byte) []dataFrame {
	t.Helper()
	var out []dataFrame
	for _, raw := range frames {
		h, ok := DecodeHeader(raw)
		if !ok || (h.Op != OpUFIData && h.Op != OpSFFData) {
			continue
		}
		if h.DataKind() != SubData {
			continue
		}
		body := raw[HeaderSize:]
		if compress {
			pt, err := UnwrapPayload(body, key, iv)
			if err != nil {
				t.Fatalf("解密数据帧失败: %v", err)
			}
			body = pt
		}
		out = append(out, dataFrame{op: h.Op, state: h.DataState(), id: h.ID, length: h.Length, body: body})
	}
	return out
}

// completionOf returns the last completion frame (0xFE/0xFF), if any.
func completionOf(t *testing.T, frames [][]byte, wantOp byte) []byte {
	t.Helper()
	for i := len(frames) - 1; i >= 0; i-- {
		if frames[i][0] == wantOp {
			return frames[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Synthetic media
// ---------------------------------------------------------------------------

// writePatternImage writes a file of blocks*blockLen bytes where byte i of block
// b is byte(b+i), so a test can tell which block came back.
func writePatternImage(t *testing.T, name string, blocks, blockLen int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	buf := make([]byte, blocks*blockLen)
	for b := 0; b < blocks; b++ {
		for i := 0; i < blockLen; i++ {
			buf[b*blockLen+i] = byte(b + i)
		}
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("写测试镜像失败: %v", err)
	}
	return path
}

func expectedBlock(block, blockLen int) []byte {
	out := make([]byte, blockLen)
	for i := range out {
		out[i] = byte(block + i)
	}
	return out
}

// ---------------------------------------------------------------------------
// CDB builders
// ---------------------------------------------------------------------------

func cdbInquiry() []byte {
	// 12-bit allocation length 36 (SFF/UFI both answer with 36 bytes).
	return []byte{0x12, 0x00, 0x00, 0x00, 36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func cdbRequestSense() []byte {
	return []byte{0x03, 0x00, 0x00, 0x00, 18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func cdbReadCapacity() []byte {
	return []byte{0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// cdbRead10 builds a READ_10: LBA in bytes 2..5, block count in bytes 7..8.
func cdbRead10(lba, blocks int) []byte {
	c := make([]byte, 12)
	c[0] = 0x28
	c[2] = byte(lba >> 24)
	c[3] = byte(lba >> 16)
	c[4] = byte(lba >> 8)
	c[5] = byte(lba)
	c[7] = byte(blocks >> 8)
	c[8] = byte(blocks)
	return c
}

// cdbRead12 builds a READ_12: LBA in bytes 2..5, block count in bytes 6..9.
func cdbRead12(lba, blocks int) []byte {
	c := make([]byte, 12)
	c[0] = 0xA8
	c[2] = byte(lba >> 24)
	c[3] = byte(lba >> 16)
	c[4] = byte(lba >> 8)
	c[5] = byte(lba)
	c[6] = byte(blocks >> 24)
	c[7] = byte(blocks >> 16)
	c[8] = byte(blocks >> 8)
	c[9] = byte(blocks)
	return c
}

func cdbWrite10(lba, blocks int) []byte {
	c := cdbRead10(lba, blocks)
	c[0] = 0x2A
	return c
}

func cdbModeSense6(pc, page byte) []byte {
	c := make([]byte, 12)
	c[0] = 0x5A
	c[2] = pc<<6 | page&0x3F
	c[4] = 0xFF
	return c
}

func cdbReadTOC(format byte, startTrack byte) []byte {
	c := make([]byte, 12)
	c[0] = 0x43
	c[2] = format & 7
	c[6] = startTrack
	c[7] = 0x00
	c[8] = 0xFF // allocation length 0x00FF (little-endian)
	return c
}

func cdbReadFormatCapacity() []byte {
	return []byte{0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00}
}

// concatBodies joins the bodies of the data frames.
func concatBodies(frames []dataFrame) []byte {
	var out []byte
	for _, f := range frames {
		out = append(out, f.body...)
	}
	return out
}

func assertBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s:\n got % x\nwant % x", what, got, want)
	}
}

// hexDecodeString decodes a test vector (panicking-free: a bad literal yields
// nil, and the comparison then fails loudly).
func hexDecodeString(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
