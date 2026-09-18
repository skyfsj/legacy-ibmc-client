package vmm

// Byte-layout tests for the 12-byte VMM frame header and the frame builders.
//
// The expected values come from ProtocolCode.java / ProtocolProcessor.java and
// from docs/protocol/05-virtual-media.md §2; they are written out as literals so
// a porting mistake fails here rather than on a device.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{
		Op:      OpSFFData,
		Sub:     0x31,
		Code:    0x00,
		ID:      0x42,
		Length:  0x00012345,
		Version: [4]byte{3, 1, 1, 1},
	}
	raw := h.Encode()
	if len(raw) != HeaderSize {
		t.Fatalf("header 应为 12 字节，实际 %d", len(raw))
	}
	want := "043100420001234503010101"
	if got := hex.EncodeToString(raw); got != want {
		t.Fatalf("header 字节不对:\n got %s\nwant %s", got, want)
	}
	got, ok := DecodeHeader(raw)
	if !ok {
		t.Fatal("DecodeHeader 失败")
	}
	if got != h {
		t.Fatalf("往返不一致: %+v != %+v", got, h)
	}
	if _, ok := DecodeHeader(raw[:11]); ok {
		t.Fatal("短缓冲应返回 false")
	}
}

func TestHeaderNibbles(t *testing.T) {
	if got := (Header{Sub: 0x11}).DataKind(); got != SubData {
		t.Fatalf("低半字节应为 1，实际 %d", got)
	}
	if got := (Header{Sub: 0x11}).DataState(); got != SubContinue {
		t.Fatalf("高半字节应为 1，实际 %d", got)
	}
	if got := (Header{Sub: 0x31}).DataState(); got != SubEnd {
		t.Fatalf("高半字节应为 3，实际 %d", got)
	}
	if got := (Header{Sub: 0x30}).DataKind(); got != SubCommand {
		t.Fatalf("低半字节应为 0，实际 %d", got)
	}
}

// The CLOSE_VM asymmetry: the client writes the device type in the low two bits
// (ProtocolProcessor.vmLinkClosePak) while the inbound parser reads the high
// nibble (ProtocolProcessor.parsePak case 5). Both directions are pinned here so
// nobody "harmonises" them.
func TestCloseVMNibbleAsymmetry(t *testing.T) {
	pack := VMLinkClosePak(CloseTypeCDROM, 5)
	if pack[0] != OpCloseVM {
		t.Fatalf("操作码应为 5，实际 %d", pack[0])
	}
	if pack[1] != 0x02 {
		t.Fatalf("客户端构建器应把设备类型写在低 2 位（0x02），实际 0x%02x", pack[1])
	}
	if pack[2] != 5 {
		t.Fatalf("原因字节应为 5，实际 %d", pack[2])
	}

	// The inbound parser reads the high nibble.
	if got := CloseVMTypeIn(0x20); got != CloseTypeCDROM {
		t.Fatalf("入站解析应读高 4 位: 0x20 -> %d", got)
	}
	if got := CloseVMTypeIn(0x10); got != CloseTypeFloppy {
		t.Fatalf("入站解析应读高 4 位: 0x10 -> %d", got)
	}
	// Feeding the client's own frame to the inbound parser yields 0 (link) —
	// the asymmetry, reproduced on purpose.
	if got := CloseVMTypeIn(pack[1]); got != CloseTypeLink {
		t.Fatalf("客户端帧自解析应为 0（不对称），实际 %d", got)
	}
}

func TestConnectPakLayout(t *testing.T) {
	sessionID := make([]byte, SessionIDSize)
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	ip := []byte{192, 0, 2, 10}
	pack, err := ConnectPak(sessionID, ip, "3.01.01.01")
	if err != nil {
		t.Fatalf("ConnectPak: %v", err)
	}
	if len(pack) != 41 {
		t.Fatalf("CERTIFY_ID 必须恰好 41 字节，实际 %d", len(pack))
	}
	if pack[0] != OpCertifyID {
		t.Fatalf("op 应为 1，实际 %d", pack[0])
	}
	if !bytes.Equal(pack[1:4], []byte{0, 0, 0}) {
		t.Fatalf("偏移 1..3 应为保留 0，实际 % x", pack[1:4])
	}
	if got := binary.BigEndian.Uint32(pack[4:8]); got != 29 {
		t.Fatalf("payload 长度应为 29，实际 %d", got)
	}
	if !bytes.Equal(pack[8:12], []byte{3, 1, 1, 1}) {
		t.Fatalf("版本应为 03 01 01 01，实际 % x", pack[8:12])
	}
	if !bytes.Equal(pack[12:36], sessionID) {
		t.Fatalf("偏移 12..35 应为 24 字节 session id")
	}
	if pack[36] != 0 {
		t.Fatalf("IPv4 的地址类型字节应为 0，实际 %d", pack[36])
	}
	if !bytes.Equal(pack[37:41], ip) {
		t.Fatalf("偏移 37..40 应为本地 IP，实际 % x", pack[37:41])
	}

	// IPv6 uses the 16-byte address and the type byte 1.
	pack6, err := ConnectPak(sessionID, bytes.Repeat([]byte{0xab}, 16), "3.01.01.01")
	if err != nil {
		t.Fatalf("ConnectPak(ipv6): %v", err)
	}
	if len(pack6) != 53 {
		t.Fatalf("IPv6 CERTIFY_ID 应为 12+24+1+16=53 字节，实际 %d", len(pack6))
	}
	if got := binary.BigEndian.Uint32(pack6[4:8]); got != 41 {
		t.Fatalf("IPv6 payload 长度应为 41，实际 %d", got)
	}
	if pack6[36] != 1 {
		t.Fatalf("IPv6 的地址类型字节应为 1，实际 %d", pack6[36])
	}

	if _, err := ConnectPak(sessionID, ip, "3.01"); err == nil {
		t.Fatal("版本段少于 4 个应报错（Java 会抛 ArrayIndexOutOfBounds）")
	}
}

func TestDevicesPak(t *testing.T) {
	for _, tc := range []struct {
		device int
		want   byte
	}{{DeviceFloppy, 1}, {DeviceCDROM, 2}} {
		pack := DevicesPak(tc.device)
		if len(pack) != HeaderSize {
			t.Fatalf("DEVICE_TYPE 应为 12 字节，实际 %d", len(pack))
		}
		if pack[0] != OpDeviceType || pack[1] != tc.want {
			t.Fatalf("DEVICE_TYPE(%d) = % x", tc.device, pack)
		}
	}
}

func TestHeartbeatFrame(t *testing.T) {
	f := HeartbeatFrame()
	if len(f) != HeaderSize || f[0] != OpHeartbeat {
		t.Fatalf("心跳帧不对: % x", f)
	}
	for i := 1; i < len(f); i++ {
		if f[i] != 0 {
			t.Fatalf("心跳帧第 %d 字节应为 0: % x", i, f)
		}
	}
}

func TestDataPakBuilders(t *testing.T) {
	// SFF: dataType 1 (data), state 1 (continue), 32768 bytes, id 0x42.
	cont := SFFDataPak(SubData, SubContinue, CDROMPacketSize, 0x42)
	want := "0411004200008000" + "00000000"
	if got := hex.EncodeToString(cont); got != want {
		t.Fatalf("SFF continue 帧:\n got %s\nwant %s", got, want)
	}
	end := SFFDataPak(SubData, SubEnd, 0, 0x42)
	if end[1] != 0x31 {
		t.Fatalf("END 帧高半字节应为 3、低半字节 1，实际 0x%02x", end[1])
	}
	if binary.BigEndian.Uint32(end[4:8]) != 0 {
		t.Fatalf("零长度 END 帧的长度字段应为 0")
	}

	// UFI writes into a caller-owned buffer and zeroes bytes 8..11.
	buf := bytes.Repeat([]byte{0xff}, HeaderSize+8)
	UFIDataPak(buf, 0, SubData, SubEnd, 4096, 7)
	if buf[0] != OpUFIData || buf[1] != 0x31 || buf[2] != 0 || buf[3] != 7 {
		t.Fatalf("UFI 头不对: % x", buf[:4])
	}
	if got := binary.BigEndian.Uint32(buf[4:8]); got != 4096 {
		t.Fatalf("UFI 长度字段应为 4096，实际 %d", got)
	}
	if !bytes.Equal(buf[8:12], []byte{0, 0, 0, 0}) {
		t.Fatalf("UFI 字节 8..11 应清零，实际 % x", buf[8:12])
	}
}

func TestCompletionPakBuilders(t *testing.T) {
	ufi := make([]byte, HeaderSize)
	UFICmpltPak(ufi, 0, CmdFail, 9)
	if ufi[0] != OpUFIComplete || ufi[1] != CmdFail || ufi[3] != 9 {
		t.Fatalf("UFI 完成帧不对: % x", ufi)
	}
	if !bytes.Equal(ufi[2:3], []byte{0}) || !bytes.Equal(ufi[4:], make([]byte, 8)) {
		t.Fatalf("UFI 完成帧其余字节应为 0: % x", ufi)
	}
	sff := make([]byte, HeaderSize)
	SFFCmpltPak(sff, 0, CmdOK, 3)
	if sff[0] != OpSFFComplete || sff[1] != CmdOK || sff[3] != 3 {
		t.Fatalf("SFF 完成帧不对: % x", sff)
	}
}

func TestFrameEncodeDecode(t *testing.T) {
	f := Frame{Header: Header{Op: OpSFFData, Sub: 0x31, ID: 5}, Payload: []byte{1, 2, 3}}
	raw := f.Encode()
	if len(raw) != HeaderSize+3 {
		t.Fatalf("帧长不对: %d", len(raw))
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 3 {
		t.Fatalf("长度字段应由 payload 推导")
	}
	got, err := DecodeFrame(raw)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if !bytes.Equal(got.Payload, f.Payload) || got.Op != f.Op {
		t.Fatalf("往返不一致: %+v", got)
	}
	if _, err := DecodeFrame(raw[:len(raw)-1]); err == nil {
		t.Fatal("长度不符应报错")
	}
}

// The integer helpers are 1-based like ProtocolCode's, which is what makes the
// SCSI CDB parsing byte-exact: LBA at bytes 2..5 is getInt32bits(cmd, 3), the
// READ_10 block count at bytes 7..8 is getInt16bits(cmd, 8).
func TestIntHelpers(t *testing.T) {
	b := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}
	// getInt32bits(b, 3) reads b[2..5] — the READ_10 LBA.
	if got := GetInt32Bits(b, 3); got != 0x33445566 {
		t.Fatalf("getInt32bits(b,3) = %#x，应为 0x33445566 (b[2..5])", got)
	}
	// getInt32bits(b, 7) reads b[6..9] — the READ_12 block count.
	if got := GetInt32Bits(b, 7); got != 0x778899AA {
		t.Fatalf("getInt32bits(b,7) = %#x，应为 0x778899AA (b[6..9])", got)
	}
	if got := GetInt32Bits(b, 5); got != 0x55667788 {
		t.Fatalf("getInt32bits(b,5) = %#x，应为 0x55667788 (b[4..7])", got)
	}
	// getInt16bits(b, 8) reads b[7..8] — the READ_10 block count.
	if got := GetInt16Bits(b, 8); got != 0x8899 {
		t.Fatalf("getInt16bits(b,8) = %#x，应为 0x8899 (b[7..8])", got)
	}
	if got := GetInt24Bits(b, 10); got != 0xAABBCC {
		t.Fatalf("getInt24bits(b,10) = %#x，应为 0xAABBCC (b[9..11])", got)
	}
	if got := GetInt32Bits(b[:2], 3); got != 0 {
		t.Fatalf("越界应返回 0（Java 会抛 AIOOBE），实际 %d", got)
	}
	dst := make([]byte, 8)
	IntToByte(dst, 0, 0x0B40)
	if !bytes.Equal(dst[0:4], []byte{0x00, 0x00, 0x0B, 0x40}) {
		t.Fatalf("intToByte 大端写入不对: % x", dst[0:4])
	}
}
