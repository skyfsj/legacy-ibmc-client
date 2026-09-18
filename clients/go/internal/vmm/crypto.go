package vmm

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"unicode/utf8"

	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/kvm"
)

// ---------------------------------------------------------------------------
// Key derivation (VMConsole.createSecretCertifyCode + AESHandler.getvmmcodekey)
// ---------------------------------------------------------------------------

// KeyMaterial is the 56-byte PBKDF2 output split into its three uses:
//
//	[0:24]  session id, sent as the CERTIFY_ID payload
//	[24:40] AES-128 key ("secretKey") for the VM data plane
//	[40:56] AES-CBC IV ("secretIv")
type KeyMaterial struct {
	SessionID []byte
	SecretKey []byte
	SecretIV  []byte
}

// PBKDF2 PRF names, spelled the way java.security.SecretKeyFactory takes them.
// The VMM console receives them from the KVM suite negotiation
// (VirtualMedia.createVMLink -> setPbkdf2Params(kvmInterface.getHmac(), ...)).
const (
	PRFSHA1   = "PBKDF2WithHmacSHA1"
	PRFSHA256 = "PBKDF2WithHmacSHA256"
)

// DefaultIterations and DefaultPRF are ConsoleControllers' initial values,
// used when the KVM channel never negotiated a suite.
const (
	DefaultIterations = 5000
	DefaultPRF        = PRFSHA1
)

// PRFForAlgo maps a KVM suite algorithm number to a PBKDF2 PRF name: 2 is
// HMAC-SHA1, 3 is HMAC-SHA256 (the Java only understands those two, see
// 02-handshake-and-crypto.md §6). Anything else falls back to SHA-1.
func PRFForAlgo(algo int) string {
	if algo == 3 {
		return PRFSHA256
	}
	return PRFSHA1
}

func hashFor(prf string) func() hash.Hash {
	if prf == PRFSHA256 {
		return sha256.New
	}
	return sha1.New
}

// DeriveKeyMaterial runs the PBKDF2 that produces the 56 bytes
// (VMConsole.createSecretCertifyCode / AESHandler.getvmmcodekey):
//
//	PBKDF2(password = UTF-8 round-trip of certifyID, salt, iterations, 56)
//
// certifyID is the negotiated 20-byte code key, or the 4-byte big-endian
// mmVerifyValue on the legacy path; salt is the 16-byte vmm salt (16 zero bytes
// when the negotiation never happened — VirtualMedia.getVmmSalt). The output is
// NOT 4-byte-reversed: unlike the KVM channel's encodeKey and kvm_key, the VMM
// key material is used as PBKDF2 returns it.
func DeriveKeyMaterial(certifyID, salt []byte, iterations int, prf string) (KeyMaterial, error) {
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	if len(salt) != IVSize {
		return KeyMaterial{}, fmt.Errorf("vmm: salt must be %d bytes, got %d", IVSize, len(salt))
	}
	complete, err := pbkdf2.Key(hashFor(prf), string(javaPasswordBytes(certifyID)), salt, iterations, 56)
	if err != nil {
		return KeyMaterial{}, err
	}
	if len(complete) < 56 {
		return KeyMaterial{}, fmt.Errorf("vmm: PBKDF2 returned %d bytes, want 56", len(complete))
	}
	return KeyMaterial{
		SessionID: append([]byte(nil), complete[0:24]...),
		SecretKey: append([]byte(nil), complete[24:40]...),
		SecretIV:  append([]byte(nil), complete[40:56]...),
	}, nil
}

// VMMCodeKey is DeriveKeyMaterial's raw 56-byte output, for callers that want to
// inspect or pin the derivation.
func VMMCodeKey(certifyID, salt []byte, iterations int, prf string) ([]byte, error) {
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	if len(salt) != IVSize {
		return nil, fmt.Errorf("vmm: salt must be %d bytes, got %d", IVSize, len(salt))
	}
	return pbkdf2.Key(hashFor(prf), string(javaPasswordBytes(certifyID)), salt, iterations, 56)
}

// javaPasswordBytes reproduces the password bytes the Java actually feeds into
// PBKDF2. Two transformations happen there and both are lossy:
//
//	new String(certifyID, "UTF-8")   // bytes -> chars, invalid sequences -> U+FFFD
//	... .toCharArray() -> new PBEKeySpec(chars, ...)
//	// SunJCE's PBKDF2KeyImpl converts the chars back to UTF-8 bytes
//
// For a code key that is valid UTF-8 (the negotiated one is 20 bytes and may be
// arbitrary binary) this is the identity; for arbitrary bytes it is not, and the
// replacement count follows the Unicode "maximal subpart" rule that the JDK's
// UTF-8 decoder implements. Reproducing that here matters: a code key that Java
// mangles must be mangled the same way or CERTIFY_ID will not match.
func javaPasswordBytes(certifyID []byte) []byte {
	if utf8.Valid(certifyID) {
		return certifyID
	}
	runes := make([]rune, 0, len(certifyID))
	for i := 0; i < len(certifyID); {
		c := certifyID[i]
		if c < utf8.RuneSelf {
			runes = append(runes, rune(c))
			i++
			continue
		}
		n, ok := wellFormedSeqLen(certifyID[i:])
		if !ok {
			// One U+FFFD for the maximal subpart, then rescan from the byte
			// that broke the sequence.
			runes = append(runes, utf8.RuneError)
			i += n
			continue
		}
		r, size := utf8.DecodeRune(certifyID[i:])
		if r == utf8.RuneError && size <= 1 {
			runes = append(runes, utf8.RuneError)
			i++
			continue
		}
		runes = append(runes, r)
		i += size
	}
	return []byte(string(runes))
}

// wellFormedSeqLen returns the length of the longest prefix of b that could
// still start a well-formed UTF-8 sequence (the maximal subpart). ok is true
// when the whole sequence at b[0] is well formed, in which case n is its length.
func wellFormedSeqLen(b []byte) (n int, ok bool) {
	c := b[0]
	var need int
	var lo, hi byte = 0x80, 0xBF // allowed range for the second byte
	switch {
	case c >= 0xC2 && c <= 0xDF:
		need = 1
	case c == 0xE0:
		need, lo = 2, 0xA0
	case c >= 0xE1 && c <= 0xEC:
		need = 2
	case c == 0xED:
		need, hi = 2, 0x9F // exclude surrogates
	case c >= 0xEE && c <= 0xEF:
		need = 2
	case c == 0xF0:
		need, lo = 3, 0x90
	case c >= 0xF1 && c <= 0xF3:
		need = 3
	case c == 0xF4:
		need, hi = 3, 0x8F
	default:
		return 1, false // continuation byte, overlong lead, or invalid lead
	}
	if len(b) < need+1 {
		// Truncated: count the bytes that are still valid continuations.
		k := 1
		for k < len(b) && b[k] >= lo && b[k] <= hi {
			k++
			lo, hi = 0x80, 0xBF
		}
		return k, false
	}
	if b[1] < lo || b[1] > hi {
		return 1, false
	}
	for i := 2; i <= need; i++ {
		if b[i] < 0x80 || b[i] > 0xBF {
			return i, false
		}
	}
	return need + 1, true
}

// ---------------------------------------------------------------------------
// Data-plane AES (AESHandler.vmmencry / vmm_decry)
// ---------------------------------------------------------------------------

// EncryptPayload is AESHandler.vmmencry: the plaintext is zero-padded up to the
// next 16-byte boundary and encrypted with AES-128-CBC (NoPadding). The true
// length is not part of the ciphertext — that is what the 4-byte length prefix
// in the payload is for. The key is the 16-byte secretKey, the IV the 16-byte
// secretIv. An empty input returns nil, exactly like the Java's len <= 0 guard.
func EncryptPayload(plain, key, iv []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	if len(key) != SecretKeySize {
		return nil, fmt.Errorf("vmm: AES key must be %d bytes, got %d", SecretKeySize, len(key))
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("vmm: AES IV must be %d bytes, got %d", IVSize, len(iv))
	}
	return kvm.AESEncryptNoPad(kvm.ZeroPad(plain), key, iv)
}

// DecryptPayload is AESHandler.vmm_decry: AES-128-CBC (NoPadding) over the whole
// ciphertext with the key used as-is (no offset, unlike the KVM helpers). The
// result is not unpadded. The Java returns null when the length is not a
// multiple of the block size; here that is an error.
func DecryptPayload(ct, key, iv []byte) ([]byte, error) {
	if len(key) != SecretKeySize {
		return nil, fmt.Errorf("vmm: AES key must be %d bytes, got %d", SecretKeySize, len(key))
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("vmm: AES IV must be %d bytes, got %d", IVSize, len(iv))
	}
	if len(ct) == 0 {
		return nil, nil
	}
	return kvm.AESDecryptNoPad(ct, key, iv)
}

// WrapPayload builds the DATA payload for vmm_compress == 1:
//
//	4-byte big-endian plaintext length || AES-CBC(zero-padded plaintext)
//
// The header length field of the frame carrying this must be len(WrapPayload),
// i.e. ciphertext + 4, while the prefix keeps the real length
// (USBProcessor.getDataEncry reads it back and truncates).
func WrapPayload(plain, key, iv []byte) ([]byte, error) {
	ct, err := EncryptPayload(plain, key, iv)
	if err != nil {
		return nil, err
	}
	if ct == nil {
		return nil, nil
	}
	out := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(plain)))
	copy(out[4:], ct)
	return out, nil
}

// UnwrapPayload reverses WrapPayload. It returns exactly the plaintext length
// recorded in the prefix, or an error when the frame is malformed (a short
// prefix, a ciphertext that is not a block multiple, or a prefix longer than the
// decrypted block).
func UnwrapPayload(wire, key, iv []byte) ([]byte, error) {
	if len(wire) < 4 {
		return nil, fmt.Errorf("vmm: encrypted payload shorter than its 4-byte length prefix (%d)", len(wire))
	}
	realLen := int(binary.BigEndian.Uint32(wire[0:4]))
	if realLen < 0 {
		return nil, fmt.Errorf("vmm: encrypted payload length %d overflows", realLen)
	}
	pt, err := DecryptPayload(wire[4:], key, iv)
	if err != nil {
		return nil, err
	}
	if realLen > len(pt) {
		return nil, fmt.Errorf("vmm: plaintext length %d exceeds decrypted %d", realLen, len(pt))
	}
	return pt[:realLen], nil
}
