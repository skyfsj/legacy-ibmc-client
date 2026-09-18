// Package kvm implements the Huawei iBMC KVM protocol: the frame codec, CRC,
// key derivation (this file) and the TCP session state machine (session.go).
//
// It is a faithful port of the JavaScript reference implementation:
//
//	src/main/protocol.js  -> protocol.go
//	src/main/session.js   -> session.go
//
// Byte layouts were validated against a real BMC; see the protocol notes in
// huawei-ibmc-kvm-protocol/ (01-transport-and-frames.md,
// 02-handshake-and-crypto.md).
package kvm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// ---------------------------------------------------------------------------
// CRC-16/CCITT-FALSE: poly 0x1021, init 0, no reflection, no final xor
// ---------------------------------------------------------------------------

var crc16Table = func() [256]uint16 {
	var t [256]uint16
	for i := 0; i < 256; i++ {
		w := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if w&0x8000 != 0 {
				w = (w << 1) ^ 0x1021
			} else {
				w <<= 1
			}
		}
		t[i] = w
	}
	return t
}()

// CRC16 is CRC-16/CCITT-FALSE over buf. The protocol covers only the payload,
// never the frame header.
func CRC16(buf []byte) uint16 {
	var c uint16
	for _, b := range buf {
		c = crc16Table[byte(c>>8)^b] ^ (c << 8)
	}
	return c
}

// ---------------------------------------------------------------------------
// AES-128-CBC with NO padding (protocol uses zero padding, length is explicit)
// ---------------------------------------------------------------------------

// AESEncryptNoPad encrypts src with AES-CBC and does not touch the padding:
// src must already be a multiple of the 16-byte block size (see ZeroPad).
// Go's cipher.NewCBCEncrypter never adds padding, which is exactly what the
// protocol wants.
func AESEncryptNoPad(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("kvm: AES-CBC IV must be %d bytes, got %d", block.BlockSize(), len(iv))
	}
	if len(src)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("kvm: AES-CBC input must be a multiple of %d bytes, got %d", block.BlockSize(), len(src))
	}
	out := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, src)
	return out, nil
}

// AESDecryptNoPad decrypts src with AES-CBC and strips nothing: the protocol
// carries the real plaintext length out of band. src must be a multiple of the
// 16-byte block size.
func AESDecryptNoPad(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("kvm: AES-CBC IV must be %d bytes, got %d", block.BlockSize(), len(iv))
	}
	if len(src) == 0 || len(src)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("kvm: AES-CBC ciphertext must be a non-zero multiple of %d bytes, got %d", block.BlockSize(), len(src))
	}
	out := make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, src)
	return out, nil
}

// ZeroPad zero-pads to the next 16-byte boundary (the vendor client does this
// before every encrypt).
func ZeroPad(buf []byte) []byte {
	n := (len(buf) + 15) / 16 * 16
	out := make([]byte, n)
	copy(out, buf)
	return out
}

// Reverse4 reverses the bytes inside each 4-byte group. The protocol applies
// this to every PBKDF2 result. The input is not modified.
func Reverse4(buf []byte) []byte {
	k := make([]byte, len(buf))
	copy(k, buf)
	for i := 0; i+4 <= len(k); i += 4 {
		k[i], k[i+3] = k[i+3], k[i]
		k[i+1], k[i+2] = k[i+2], k[i+1]
	}
	return k
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// hmacHash mirrors the JS HMAC_NAME table: algo 2 -> SHA-1, everything else
// (including the unknown "algo 1" fallback) -> SHA-256.
func hmacHash(algo int) func() hash.Hash {
	if algo == 2 {
		return sha1.New
	}
	return sha256.New
}

// DeriveEncodeKey derives the 24-byte encodeKey (the CONNECT_BLADE proof):
// PBKDF2(verifyValueExt, salt=userIV, iterations, 24) then 4-byte-group
// reversed. algo 2 selects HMAC-SHA1, algo 3 (and anything else) HMAC-SHA256.
func DeriveEncodeKey(verifyValueExt string, userIV []byte, iterations, algo int) ([]byte, error) {
	raw, err := pbkdf2.Key(hmacHash(algo), verifyValueExt, userIV, iterations, 24)
	if err != nil {
		return nil, err
	}
	return Reverse4(raw), nil
}

// DeriveKvmKey builds the 48-byte kvm_key from the 48-byte KVM_KEY_SET plaintext:
//
//	[0..31]  = 32 ASCII chars -> PBKDF2 password (raw bytes, latin1 round-trip)
//	[32..47] = 16 bytes       -> salt
//
// result = PBKDF2(pwd, salt, iterations, 48) then 4-byte-group reversed.
// Layout: [0:16] data key, [16:32] keyboard key, [32:48] shared IV.
func DeriveKvmKey(plain48 []byte, iterations, algo int) ([]byte, error) {
	if len(plain48) < 48 {
		return nil, fmt.Errorf("kvm: KVM_KEY_SET plaintext must be 48 bytes, got %d", len(plain48))
	}
	// The JS does Buffer.from(subarray(0,32).toString('latin1'), 'latin1'), which
	// is the identity on the raw bytes; Node then hashes those bytes. A Go string
	// holds exactly those bytes, so this is equivalent.
	password := string(plain48[0:32])
	salt := plain48[32:48]
	raw, err := pbkdf2.Key(hmacHash(algo), password, salt, iterations, 48)
	if err != nil {
		return nil, err
	}
	return Reverse4(raw), nil
}

// ---------------------------------------------------------------------------
// Client -> BMC frames
// ---------------------------------------------------------------------------

const (
	magic0 = 0xfe
	magic1 = 0xf6
)

// BuildFrame builds a regular client frame:
//
//	FE F6 | len(payload+2) u16be | codeKey i32be | crc16 u16be | payload
func BuildFrame(codeKey int32, payload []byte) []byte {
	buf := make([]byte, len(payload)+10)
	buf[0], buf[1] = magic0, magic1
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)+2))
	binary.BigEndian.PutUint32(buf[4:], uint32(codeKey))
	binary.BigEndian.PutUint16(buf[8:], CRC16(payload))
	copy(buf[10:], payload)
	return buf
}

// BuildEncryptedFrame builds the CONNECT_BLADE / "compressed" variant:
//
//	FE F6 | (length+2) u16be, 0x8000 set | 24-byte encodeKey | crc16 u16be | payload
//
// length is the un-masked value (e.g. 0x8005), so the length field becomes
// 0x8007; the real payload length is length & 0x7fff.
func BuildEncryptedFrame(encodeKey24, payload []byte, length int) []byte {
	n := length & 0x7fff
	buf := make([]byte, n+30)
	buf[0], buf[1] = magic0, magic1
	binary.BigEndian.PutUint16(buf[2:], uint16((length+2)&0xffff))
	copy(buf[4:28], sub(encodeKey24, 0, 24))
	binary.BigEndian.PutUint16(buf[28:], CRC16(sub(payload, 0, n)))
	copy(buf[30:], sub(payload, 0, n))
	return buf
}

// ---------------------------------------------------------------------------
// BMC -> client frame parser: FE F6 00 | dlen(1B, 3..250) | payload
// ---------------------------------------------------------------------------

var serverMagic = []byte{magic0, magic1, 0x00}

// ServerFrameParser is the incremental parser for the receive direction. Unlike
// the send direction it carries no codeKey and no CRC: the three-byte magic is
// followed by a one-byte payload length.
type ServerFrameParser struct {
	buf []byte
}

// NewServerFrameParser returns an empty parser.
func NewServerFrameParser() *ServerFrameParser { return &ServerFrameParser{} }

// Push feeds a chunk of TCP data and returns every complete frame it contains.
// The returned payloads are freshly allocated copies; the parser keeps its own
// buffer, so the caller may reuse chunk.
func (p *ServerFrameParser) Push(chunk []byte) [][]byte {
	p.buf = append(p.buf, chunk...)
	var out [][]byte
	for {
		if len(p.buf) < 4 {
			break
		}
		if !(p.buf[0] == magic0 && p.buf[1] == magic1 && p.buf[2] == 0x00) {
			// Resynchronise on the 3-byte magic (searching from index 1 so a
			// partial magic at offset 0 is not re-matched).
			j := bytes.Index(p.buf[1:], serverMagic)
			if j < 0 {
				// Keep the last two bytes: they may be the start of a magic
				// split across two reads.
				keep := len(p.buf) - 2
				if keep < 0 {
					keep = 0
				}
				p.buf = append(p.buf[:0], p.buf[keep:]...)
				break
			}
			p.buf = p.buf[j+1:]
			continue
		}
		dlen := int(p.buf[3])
		if dlen < 3 || dlen > 250 {
			// Out of sync: the parser drops one byte and rescans.
			p.buf = p.buf[1:]
			continue
		}
		if len(p.buf) < 4+dlen {
			break // half a frame: wait for more data
		}
		out = append(out, append([]byte(nil), p.buf[4:4+dlen]...))
		p.buf = p.buf[4+dlen:]
	}
	if len(p.buf) == 0 {
		p.buf = nil // do not pin a large backing array
	}
	return out
}

// Suite is one entry of the BMC's suite list.
type Suite struct {
	Algo       int
	Iterations uint32
}

// SuiteList is the parsed KVM_SUITE_LIST(0x43) payload:
//
//	00 00 | 43 | blade | count | (algo:1 + iterations:u32be) * count
type SuiteList struct {
	Count    int
	Suites   []Suite
	LengthOK bool // count*5+3 == dlen-2
}

// Find returns the entry with the given algo, if present.
func (s SuiteList) Find(algo int) (Suite, bool) {
	for _, su := range s.Suites {
		if su.Algo == algo {
			return su, true
		}
	}
	return Suite{}, false
}

// ParseSuiteList parses a KVM_SUITE_LIST payload. Short or truncated payloads
// yield LengthOK=false instead of panicking.
func ParseSuiteList(p []byte) SuiteList {
	if len(p) < 5 {
		return SuiteList{}
	}
	count := int(p[4])
	sl := SuiteList{Count: count, LengthOK: count*5+3 == len(p)-2}
	for k := 0; k < count; k++ {
		off := 5 + k*5
		if off+5 > len(p) {
			sl.LengthOK = false
			break
		}
		sl.Suites = append(sl.Suites, Suite{
			Algo:       int(p[off]),
			Iterations: binary.BigEndian.Uint32(p[off+1 : off+5]),
		})
	}
	return sl
}

// ConnectBladePayload builds the CONNECT_BLADE payload:
// {0x06, blade, colorBit, 0x01, 0x01}; the length field is 0x8005 when compress=1.
func ConnectBladePayload(blade, colorBit int) []byte {
	return []byte{CmdConnectBlade, byte(blade), byte(colorBit), 0x01, 0x01}
}

// sub clamps like JS Buffer.subarray: out-of-range bounds are clamped instead
// of panicking. This keeps the port's behaviour identical for short or empty
// inputs (a malformed JNLP yields a short decrykey, for example).
func sub(b []byte, from, to int) []byte {
	if from < 0 {
		from = 0
	}
	if from > len(b) {
		from = len(b)
	}
	if to < from {
		to = from
	}
	if to > len(b) {
		to = len(b)
	}
	return b[from:to]
}

// ---------------------------------------------------------------------------
// Command codes (untyped constants, mirroring the JS CMD / RSP tables)
// ---------------------------------------------------------------------------

// Client -> BMC command codes (JS `CMD`).
const (
	CmdKeyPack          = 0x03
	CmdKeyState         = 0x04
	CmdMousePack        = 0x05
	CmdConnectBlade     = 0x06
	CmdInterruptBlade   = 0x07
	CmdIReq             = 0x08
	CmdHeartBeat        = 0x09
	CmdReqBladePresent  = 0x0b
	CmdReqBladeState    = 0x14
	CmdReqBladeMonitor  = 0x17
	CmdInterruptMonitor = 0x18
	CmdDeleteUser       = 0x19
	CmdReplaySMM        = 0x1a
	CmdColorBit         = 0x1b
	CmdFrameComm        = 0x1c
	CmdRetryConn        = 0x1e
	CmdPowerOff         = 0x20
	CmdPowerOn          = 0x21
	CmdRestart          = 0x22
	CmdSafetyRestart    = 0x23
	CmdMouseModeSet     = 0x24
	CmdSavePowerOff     = 0x25
	CmdDqtModeSet       = 0x27
	CmdUSBReset         = 0x30
	CmdReqVmmCodeKey    = 0x31
	CmdSecurity         = 0x33
	CmdReqVmmPort       = 0x35
	CmdVideoOn          = 0x40
	CmdVideoOff         = 0x41
	CmdGetSuite         = 0x42
	CmdSetSuite         = 0x44
)

// BMC -> client command codes (JS `RSP`); the command byte sits at payload[2].
const (
	RspPresentBlade  = 0x01
	RspImageData     = 0x02
	RspKeyState      = 0x04
	RspConnectState  = 0x08
	RspBladeState    = 0x15
	RspChannelSwitch = 0x1d
	RspRapConnect    = 0x21
	RspMouseMode     = 0x25
	RspDqtMode       = 0x28
	RspVmmCodeKey    = 0x32
	RspVmmPort       = 0x36
	RspKvmKeySet     = 0x40
	RspKvmSuiteList  = 0x43
	RspNotPri        = 0x51
)
