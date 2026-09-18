// Package vmm implements the Huawei iBMC virtual-media (VMM) channel: the
// separate TCP channel that presents a local ISO / IMG file to the remote
// server as a CD-ROM or floppy drive.
//
// It is a faithful port of the vendor's decompiled Java client
// (com/huawei/vm/console/** and the VMM part of com/kvm/VirtualMedia.java);
// every function carries the Java method it mirrors in its doc comment so the
// port can be audited line by line. Where the Java does something surprising the
// oddity is reproduced and called out in a comment — nothing was "fixed".
//
// Layout of this package:
//
//	protocol.go  the 12-byte frame header, opcodes and frame builders
//	crypto.go    the 56-byte PBKDF2 key split and the AES payload framing
//	device.go    shared SCSI plumbing (sense data, element queue, devices)
//	cdrom.go     ISO-backed CD-ROM + SFF-8020i command set
//	floppy.go    IMG-backed floppy + UFI command set
//	session.go   the connection / certify / device / active state machine
//	bootstrap.go the KVM-channel side that fetches the code key and port
//
// The channel is NOT verified against real hardware (the protocol notes say so
// for the Java original as well); the tests pin the byte layouts that the Java
// source specifies.
package vmm

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Constants (ProtocolCode.java)
// ---------------------------------------------------------------------------

const (
	// HeaderSize is the fixed size of every frame header.
	HeaderSize = 12
	// IPTypeSize / IPv4Size are the CERTIFY_ID address field sizes.
	IPTypeSize = 1
	IPv4Size   = 4
	// SessionIDSize is the length of the PBKDF2-derived session id.
	SessionIDSize = 24
	// SecretKeySize / IVSize are the AES-128 key and IV lengths.
	SecretKeySize = 16
	IVSize        = 16
)

// Frame opcodes (the first header byte).
const (
	OpACK          = 0x00 // BMC -> client acknowledgement
	OpCertifyID    = 0x01 // client -> BMC authentication
	OpDeviceType   = 0x02 // client -> BMC device registration
	OpUFIData      = 0x03 // floppy SCSI traffic (both directions)
	OpSFFData      = 0x04 // CD-ROM SFF-8020i traffic (both directions)
	OpCloseVM      = 0x05 // close one device / the whole link
	OpHeartbeat    = 0x06
	OpShutdown     = 0x07 // BMC -> client shutdown notice
	OpConsolePrint = 0xF0 // BMC -> client print level
	OpUFIComplete  = 0xFE // UFI command completion
	OpSFFComplete  = 0xFF // SFF command completion
	OpMICFile      = 0xFC // declared but referenced nowhere in the Java: legacy
)

// ACK codes (the third header byte of an OpACK frame).
const (
	AckCertifyPass      = 0  // certified -> the client sends DEVICE_TYPE
	AckCertifyIDFail    = 1  // session id / PBKDF2 mismatch
	AckCertifyVerNotSup = 2  // client version not supported
	AckDeviceCreat      = 16 // device created -> ACTIVE, heartbeat starts
	AckDeviceFailEnum   = 17 // device enumeration failed
	AckCloseUpdate      = 34 // fatal reason on teardown
	AckCloseIPConfig    = 35 // fatal reason on teardown
	CnExist             = 49 // device already used by another user -> error 401
)

// UFI/SFF sub-code nibbles (header byte 1).
//
// The low nibble selects command vs data; the high nibble is the continuation
// state. Note that the Java reuses the value 1 for two different constants
// (UFI_SFF_DATA_DATA and UFI_SFF_DATA_CONTINUE); the nibbles are separate.
const (
	SubCommand  = 0x0 // low nibble 0: 12-byte SCSI CDB follows
	SubData     = 0x1 // low nibble 1: data follows
	SubContinue = 0x1 // high nibble 1: more fragments follow
	SubEnd      = 0x3 // high nibble 3: last fragment
)

// Device types (DEVICE_TYPE frame byte 1, CLOSE_VM type).
const (
	DeviceNone   = 0
	DeviceFloppy = 1
	DeviceCDROM  = 2
)

// CLOSE_VM types (used by the client-side builder only).
const (
	CloseTypeLink   = 0
	CloseTypeFloppy = 1
	CloseTypeCDROM  = 2
)

// Command completion results (header byte 1 of OpUFIComplete / OpSFFComplete).
const (
	CmdOK   = 0
	CmdFail = 1
)

// Transfer sizes and timings. The Java reads these from
// vmconfigResource.properties at class-initialisation time; the values below are
// the ones shipped in the JAR.
const (
	// CDROMPacketSize / FloppyPacketSize cap one data fragment.
	CDROMPacketSize  = 32768
	FloppyPacketSize = 4096
	// HeartbeatTick is the timer granularity (VMTimerTask.TASK_INTERVAL, the
	// literal 1000 in VMConsole.processAck).
	HeartbeatTickMs = 1000
	// HeartbeatEvery is the client heartbeat period (HEARTBIT_INTERVAL).
	HeartbeatEveryMs = 10000
	// HeartbeatTimeout is the "no traffic in either direction" drop threshold:
	// heartBitCount counts down from 4 * (HEARTBIT_INTERVAL/1000) = 40 ticks.
	HeartbeatTimeoutMs = 4 * (HeartbeatEveryMs / 1000) * HeartbeatTickMs
	// BusinessOvertimeMs is the read timeout for a frame payload.
	BusinessOvertimeMs = 20000
	// CertifyTimeoutMs / DeviceTimeoutMs are the handshake watchdogs.
	CertifyTimeoutMs = 10000
	DeviceTimeoutMs  = 10000
	// ConnectTimeoutMs is the TCP connect timeout.
	ConnectTimeoutMs = 20000
)

// ---------------------------------------------------------------------------
// Header codec
// ---------------------------------------------------------------------------

// Header is the 12-byte fixed frame header. All multi-byte fields are
// big-endian.
//
//	offset 0  opcode
//	offset 1  subtype / status      (per-opcode meaning)
//	offset 2  ACK code / close reason / print level (client frames: 0)
//	offset 3  transaction id: the CDB frames carry it, the BMC echoes it back
//	offset 4  payload length, u32 big-endian
//	offset 8  version, used by CERTIFY_ID only; zeros everywhere else
type Header struct {
	Op      byte
	Sub     byte
	Code    byte
	ID      byte
	Length  uint32
	Version [4]byte
}

// DecodeHeader parses the 12-byte header. The bool is false when b is short.
func DecodeHeader(b []byte) (Header, bool) {
	if len(b) < HeaderSize {
		return Header{}, false
	}
	var h Header
	h.Op = b[0]
	h.Sub = b[1]
	h.Code = b[2]
	h.ID = b[3]
	h.Length = binary.BigEndian.Uint32(b[4:8])
	copy(h.Version[:], b[8:12])
	return h, true
}

// Encode renders the header. The result is always HeaderSize bytes.
func (h Header) Encode() []byte {
	b := make([]byte, HeaderSize)
	b[0], b[1], b[2], b[3] = h.Op, h.Sub, h.Code, h.ID
	binary.BigEndian.PutUint32(b[4:8], h.Length)
	copy(b[8:12], h.Version[:])
	return b
}

// DataKind returns the low nibble of the subtype byte: SubCommand (0) for a CDB,
// SubData (1) for data.
func (h Header) DataKind() byte { return h.Sub & 0x0F }

// DataState returns the high nibble of the subtype byte: SubContinue (1) means
// more fragments follow, SubEnd (3) marks the last one.
func (h Header) DataState() byte { return h.Sub >> 4 & 0x0F }

// Frame is one complete frame: the header plus its payload.
type Frame struct {
	Header
	Payload []byte
}

// Encode renders header + payload; the header length field is regenerated from
// the payload so a Frame can never disagree with itself.
func (f Frame) Encode() []byte {
	h := f.Header
	h.Length = uint32(len(f.Payload))
	out := make([]byte, HeaderSize+len(f.Payload))
	copy(out, h.Encode())
	copy(out[HeaderSize:], f.Payload)
	return out
}

// DecodeFrame parses one complete frame from b. It requires exactly
// HeaderSize+Length bytes and rejects anything else, which is what the hardened
// port wants in place of the Java's implicit "the reader already gave me the
// right number of bytes".
func DecodeFrame(b []byte) (Frame, error) {
	h, ok := DecodeHeader(b)
	if !ok {
		return Frame{}, fmt.Errorf("vmm: frame shorter than %d bytes: %d", HeaderSize, len(b))
	}
	want := HeaderSize + int(h.Length)
	if len(b) != want {
		return Frame{}, fmt.Errorf("vmm: frame length %d does not match header length %d", len(b), want)
	}
	return Frame{Header: h, Payload: b[HeaderSize:]}, nil
}

// ReadFrame reads one whole frame. Deadlines are the caller's business: the
// session sets them (10s for a header, 20s for a payload) the way
// ProtocolProcessor does with soTimeout.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	h, _ := DecodeHeader(hdr[:])
	f := Frame{Header: h}
	if h.Length > 0 {
		f.Payload = make([]byte, h.Length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Integer helpers (ProtocolCode.getXXXbits)
// ---------------------------------------------------------------------------

// GetInt32Bits reads a big-endian u32 whose last byte is at b[position+2]; the
// position argument is 1-based, exactly like ProtocolCode.getInt32bits(b, 5)
// reading b[4..7]. Out-of-range reads yield 0 instead of the Java's
// ArrayIndexOutOfBoundsException (which would kill the processor thread).
func GetInt32Bits(b []byte, position int) int {
	i := position - 1
	if i < 0 || i+4 > len(b) {
		return 0
	}
	return int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
}

// GetInt24Bits reads a big-endian 24-bit value ending at b[position+1].
func GetInt24Bits(b []byte, position int) int {
	i := position - 1
	if i < 0 || i+3 > len(b) {
		return 0
	}
	return int(b[i])<<16 | int(b[i+1])<<8 | int(b[i+2])
}

// GetInt16Bits reads a big-endian u16 ending at b[position].
func GetInt16Bits(b []byte, position int) int {
	i := position - 1
	if i < 0 || i+2 > len(b) {
		return 0
	}
	return int(b[i])<<8 | int(b[i+1])
}

// IntToByte writes a big-endian u32 into dst at offset (ProtocolCode.intToByte).
func IntToByte(dst []byte, offset, v int) {
	if offset < 0 || offset+4 > len(dst) {
		return
	}
	dst[offset] = byte(v >> 24)
	dst[offset+1] = byte(v >> 16)
	dst[offset+2] = byte(v >> 8)
	dst[offset+3] = byte(v)
}

// ---------------------------------------------------------------------------
// Client -> BMC frame builders
// ---------------------------------------------------------------------------

// ConnectPak builds the CERTIFY_ID frame (ProtocolProcessor.connectPak).
//
// With the 24-byte session id produced by the key derivation this is the only
// reachable branch, and the frame is exactly 41 bytes:
//
//	0      1   OpCertifyID
//	1..3   3   00 00 00
//	4..7   4   payload length = len(id) + 1 + len(ip) = 29 (u32be)
//	8..11  4   client version, one byte per dot-separated component
//	12..   24  session id
//	36     1   0 = IPv4, 1 = IPv6 (ipLen == 4 ? 0 : 1)
//	37..   4   local IP address
//
// The Java also has a branch for a session id that is not 24 bytes long: it
// writes the id at offset 4, leaves the length field zero and still writes the
// version at offset 8..11. It is unreachable here (the derived id is always 24
// bytes) but it is ported so the two implementations agree byte for byte.
func ConnectPak(sessionID, ip []byte, version string) ([]byte, error) {
	dataLen := len(sessionID) + 1 + len(ip)
	pack := make([]byte, HeaderSize+dataLen)
	pack[0] = OpCertifyID
	if len(sessionID) == SessionIDSize {
		binary.BigEndian.PutUint32(pack[4:8], uint32(dataLen))
		pos := HeaderSize
		pos += copy(pack[pos:], sessionID)
		if len(ip) == IPv4Size {
			pack[pos] = 0
		} else {
			pack[pos] = 1
		}
		pos++
		copy(pack[pos:], ip)
	} else {
		copy(pack[4:], sessionID)
	}
	vers := strings.Split(version, ".")
	if len(vers) < 4 {
		return nil, fmt.Errorf("vmm: version %q needs 4 dot-separated components", version)
	}
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(strings.TrimSpace(vers[i]))
		if err != nil {
			return nil, fmt.Errorf("vmm: version component %q is not a number", vers[i])
		}
		pack[8+i] = byte(n & 0xFF)
	}
	return pack, nil
}

// DevicesPak builds the 12-byte DEVICE_TYPE frame (ProtocolProcessor.devicesPak).
// The device type sits in the low nibble of byte 1.
func DevicesPak(deviceType int) []byte {
	pack := make([]byte, HeaderSize)
	pack[0] = OpDeviceType
	pack[1] = byte(deviceType & 0x0F)
	return pack
}

// HeartBitPak sets the heartbeat opcode in an existing buffer
// (ProtocolProcessor.heartBitPak). The rest of the frame stays zeroed.
func HeartBitPak(pack []byte, startPos int) []byte {
	if startPos >= 0 && startPos < len(pack) {
		pack[startPos] = OpHeartbeat
	}
	return pack
}

// HeartbeatFrame returns a fresh 12-byte heartbeat frame.
func HeartbeatFrame() []byte { return HeartBitPak(make([]byte, HeaderSize), 0) }

// VMLinkClosePak builds the client's CLOSE_VM frame
// (ProtocolProcessor.vmLinkClosePak): opcode, then the device type in the LOW
// two bits of byte 1, then the reason.
//
// The receive side of the Java reads the device type from the HIGH nibble
// (ProtocolProcessor.parsePak case 5: packet[1] >> 4 & 0xF). The asymmetry is in
// the original and is preserved here: see CloseVMTypeIn for the inbound view.
func VMLinkClosePak(deviceType, reason byte) []byte {
	pack := make([]byte, HeaderSize)
	pack[0] = OpCloseVM
	pack[1] = deviceType & 3
	pack[2] = reason
	return pack
}

// CloseVMTypeIn decodes the device type of an inbound CLOSE_VM frame. The Java
// reads packet[1] >> 4 & 0xF here while its own builder writes the type in the
// low bits (VMLinkClosePak); the two directions do not agree and both are
// reproduced as they are.
func CloseVMTypeIn(sub byte) int { return int(sub >> 4 & 0x0F) }

// SFFDataPak builds a 12-byte SFF (CD-ROM) data header
// (ProtocolProcessor.sffDataPak). dataType is the low nibble (1 = data), state
// the high nibble (1 = continue, 3 = end); dataLength is the payload length and
// ID the transaction id. Bytes 2 and 8..11 are left zero.
func SFFDataPak(dataType, state, dataLength, id int) []byte {
	pack := make([]byte, HeaderSize)
	pack[0] = OpSFFData
	pack[1] = byte((state&0x0F)<<4 | dataType&0x0F)
	pack[3] = byte(id)
	binary.BigEndian.PutUint32(pack[4:8], uint32(dataLength))
	return pack
}

// UFIDataPak writes a UFI (floppy) data header into src at startPos
// (ProtocolProcessor.ufiDataPak). Byte 2 is explicitly zeroed and so are bytes
// 8..11. The caller has already sized src for header + payload.
func UFIDataPak(src []byte, startPos, dataType, state, dataLength, id int) {
	if startPos < 0 || startPos+HeaderSize > len(src) {
		return
	}
	src[startPos] = OpUFIData
	src[startPos+1] = byte((state&0x0F)<<4 | dataType&0x0F)
	src[startPos+2] = 0
	src[startPos+3] = byte(id)
	binary.BigEndian.PutUint32(src[startPos+4:startPos+8], uint32(dataLength))
	for i := 8; i < HeaderSize; i++ {
		src[startPos+i] = 0
	}
}

// UFICmpltPak writes a UFI completion frame (ProtocolProcessor.ufiCmpltPak):
// opcode 0xFE, result in the low nibble of byte 1, transaction id in byte 3,
// everything else zero.
func UFICmpltPak(pack []byte, startPos, result, id int) {
	writeCmpltPak(pack, startPos, OpUFIComplete, result, id)
}

// SFFCmpltPak writes an SFF completion frame (ProtocolProcessor.sffCmpltPak):
// opcode 0xFF, result in the low nibble of byte 1, transaction id in byte 3.
//
// Note the Java's sffCmpltPak writes the opcode to pack[0] unconditionally while
// the other fields honour startPos. That difference is unobservable here because
// every caller passes startPos == 0; this port writes the opcode at startPos,
// exactly like the UFI builder.
func SFFCmpltPak(pack []byte, startPos, result, id int) {
	writeCmpltPak(pack, startPos, OpSFFComplete, result, id)
}

func writeCmpltPak(pack []byte, startPos int, op byte, result, id int) {
	if startPos < 0 || startPos+HeaderSize > len(pack) {
		return
	}
	pack[startPos] = op
	pack[startPos+1] = byte(result & 0x0F)
	pack[startPos+2] = 0
	pack[startPos+3] = byte(id)
	for i := 4; i < HeaderSize; i++ {
		pack[startPos+i] = 0
	}
}

// DeviceTypeName renders a device type for logs.
func DeviceTypeName(t int) string {
	switch t {
	case DeviceFloppy:
		return "floppy"
	case DeviceCDROM:
		return "cdrom"
	case DeviceNone:
		return "link"
	}
	return fmt.Sprintf("type%d", t)
}
