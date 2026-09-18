package vmm

// Key-derivation and data-plane framing tests.
//
// The derivation mirrors VMConsole.createSecretCertifyCode +
// AESHandler.getvmmcodekey: PBKDF2 over the UTF-8 round trip of the code key,
// producing 56 bytes that split 24 / 16 / 16. The data plane is
// AES-128-CBC/NoPadding wrapped as `4-byte big-endian length || ciphertext`
// (docs/protocol/05-virtual-media.md §4.3-4.5).

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDeriveKeyMaterialSplit(t *testing.T) {
	codeKey := []byte("0123456789abcdefghij") // 20 bytes, like the negotiation
	salt := []byte("0123456789abcdef")        // 16 bytes
	mat, err := DeriveKeyMaterial(codeKey, salt, 5000, PRFSHA1)
	if err != nil {
		t.Fatalf("DeriveKeyMaterial: %v", err)
	}
	if len(mat.SessionID) != 24 || len(mat.SecretKey) != 16 || len(mat.SecretIV) != 16 {
		t.Fatalf("分段长度不对: %d/%d/%d", len(mat.SessionID), len(mat.SecretKey), len(mat.SecretIV))
	}

	// Independent PBKDF2 over the same inputs: the 56 bytes must be the raw
	// PBKDF2 output (no 4-byte reversal, unlike the KVM channel's keys).
	raw, err := pbkdf2.Key(sha1.New, string(codeKey), salt, 5000, 56)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	if !bytes.Equal(mat.SessionID, raw[0:24]) {
		t.Fatalf("session id 应为 PBKDF2[0:24]\n got %x\nwant %x", mat.SessionID, raw[0:24])
	}
	if !bytes.Equal(mat.SecretKey, raw[24:40]) {
		t.Fatalf("secretKey 应为 PBKDF2[24:40]\n got %x\nwant %x", mat.SecretKey, raw[24:40])
	}
	if !bytes.Equal(mat.SecretIV, raw[40:56]) {
		t.Fatalf("secretIv 应为 PBKDF2[40:56]\n got %x\nwant %x", mat.SecretIV, raw[40:56])
	}

	// Deterministic, and pinned so a PBKDF2-parameter regression is visible.
	again, err := DeriveKeyMaterial(codeKey, salt, 5000, PRFSHA1)
	if err != nil {
		t.Fatalf("DeriveKeyMaterial: %v", err)
	}
	if !bytes.Equal(again.SessionID, mat.SessionID) {
		t.Fatal("两次派生结果不同")
	}
	t.Logf("PBKDF2(HmacSHA1, 5000) session id = %s", hex.EncodeToString(mat.SessionID))

	// The raw helper agrees with the split version.
	full, err := VMMCodeKey(codeKey, salt, 5000, PRFSHA1)
	if err != nil {
		t.Fatalf("VMMCodeKey: %v", err)
	}
	if len(full) != 56 {
		t.Fatalf("PBKDF2 输出应为 56 字节，实际 %d", len(full))
	}
	if !bytes.Equal(full, raw) {
		t.Fatal("VMMCodeKey 与 DeriveKeyMaterial 的 PBKDF2 不一致")
	}

	// SHA-256 is the suite the real BMC selects (algo 3).
	mat256, err := DeriveKeyMaterial(codeKey, salt, 10000, PRFSHA256)
	if err != nil {
		t.Fatalf("DeriveKeyMaterial(sha256): %v", err)
	}
	raw256, _ := pbkdf2.Key(sha256.New, string(codeKey), salt, 10000, 56)
	if !bytes.Equal(mat256.SessionID, raw256[0:24]) {
		t.Fatal("SHA-256 派生不匹配")
	}
	if bytes.Equal(mat256.SessionID, mat.SessionID) {
		t.Fatal("SHA-1 与 SHA-256 的派生结果不应相同")
	}

	// Defaults: 5000 iterations / SHA-1 (ConsoleControllers).
	def, err := DeriveKeyMaterial(codeKey, salt, 0, "")
	if err != nil {
		t.Fatalf("DeriveKeyMaterial(defaults): %v", err)
	}
	if !bytes.Equal(def.SessionID, mat.SessionID) {
		t.Fatal("默认参数应为 5000 次 / SHA-1")
	}
	if _, err := DeriveKeyMaterial(codeKey, salt[:15], 5000, PRFSHA1); err == nil {
		t.Fatal("salt 长度不是 16 应报错")
	}
}

// The Java round-trips the code key through `new String(certifyID, "UTF-8")`
// before PBKDF2 sees it (new String -> toCharArray -> PBEKeySpec, which SunJCE
// re-encodes as UTF-8). For valid UTF-8 that is the identity; for arbitrary
// bytes it replaces each maximal ill-formed subpart with U+FFFD. These vectors
// pin that conversion.
func TestJavaPasswordBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"ascii 原样", []byte("0123456789abcdefghij"), []byte("0123456789abcdefghij")},
		{"合法多字节原样", []byte{0xC3, 0xA9, 0x41}, []byte{0xC3, 0xA9, 0x41}},
		{"坏前缀+ASCII", []byte{0xC3, 0x28}, []byte{0xEF, 0xBF, 0xBD, 0x28}},
		{"三字节截断", []byte{0xE1, 0x80, 0x41}, []byte{0xEF, 0xBF, 0xBD, 0x41}},
		{"代理区非法", []byte{0xED, 0xA0, 0x80}, []byte{0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD}},
		{"孤立续字节", []byte{0x80, 0x41}, []byte{0xEF, 0xBF, 0xBD, 0x41}},
		{"超长编码 C0", []byte{0xC0, 0xAF}, []byte{0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD}},
		{"四字节合法", []byte{0xF0, 0x9F, 0x98, 0x80}, []byte{0xF0, 0x9F, 0x98, 0x80}},
		{"末尾截断", []byte{0x41, 0xE1, 0x80}, []byte{0x41, 0xEF, 0xBF, 0xBD}},
	}
	for _, tc := range cases {
		got := javaPasswordBytes(tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: javaPasswordBytes(% x) = % x，应为 % x", tc.name, tc.in, got, tc.want)
		}
	}
}

// A code key that is not valid UTF-8 must not reach PBKDF2 unchanged (the Java
// would mangle it), and the derived values must change accordingly.
func TestDeriveKeyMaterialNonUTF8CodeKey(t *testing.T) {
	codeKey := []byte{0xC3, 0x28, 0x80, 0xFF, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}
	salt := make([]byte, 16)
	mat, err := DeriveKeyMaterial(codeKey, salt, 5000, PRFSHA1)
	if err != nil {
		t.Fatalf("DeriveKeyMaterial: %v", err)
	}
	replaced := javaPasswordBytes(codeKey)
	if bytes.Equal(replaced, codeKey) {
		t.Fatal("非法 UTF-8 的 code key 应被替换后再做 PBKDF2")
	}
	want, _ := pbkdf2.Key(sha1.New, string(replaced), salt, 5000, 56)
	if !bytes.Equal(mat.SessionID, want[0:24]) {
		t.Fatal("PBKDF2 未使用替换后的口令字节")
	}
}

func TestPRFForAlgo(t *testing.T) {
	if PRFForAlgo(2) != PRFSHA1 || PRFForAlgo(3) != PRFSHA256 {
		t.Fatal("algo 2/3 应映射到 SHA1/SHA256")
	}
	if PRFForAlgo(1) != PRFSHA1 || PRFForAlgo(0) != PRFSHA1 {
		t.Fatal("未知 algo 应回落 SHA-1")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)

	// Not a multiple of 16: vmmencry zero-pads, so the ciphertext grows.
	plain := []byte("1234567890") // 10 bytes
	ct, err := EncryptPayload(plain, key, iv)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if len(ct) != 16 {
		t.Fatalf("10 字节明文应补零到 16 字节密文，实际 %d", len(ct))
	}
	pt, err := DecryptPayload(ct, key, iv)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(pt[:len(plain)], plain) {
		t.Fatalf("解密后前 %d 字节应为原文: % x", len(plain), pt)
	}
	if !bytes.Equal(pt[len(plain):], make([]byte, len(pt)-len(plain))) {
		t.Fatalf("补零字节应为 0: % x", pt[len(plain):])
	}

	// Already aligned: no padding is added (NoPadding).
	aligned := bytes.Repeat([]byte{0xAB}, 32)
	ct2, err := EncryptPayload(aligned, key, iv)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if len(ct2) != 32 {
		t.Fatalf("整块明文不应增长，实际 %d", len(ct2))
	}

	// Empty input returns nil, like the Java's len <= 0 guard.
	if out, err := EncryptPayload(nil, key, iv); err != nil || out != nil {
		t.Fatalf("空明文应返回 nil, nil，实际 %v, %v", out, err)
	}
	if _, err := DecryptPayload(bytes.Repeat([]byte{0}, 17), key, iv); err == nil {
		t.Fatal("非 16 倍数的密文应报错（Java 返回 null）")
	}
	if _, err := EncryptPayload(plain, key[:8], iv); err == nil {
		t.Fatal("密钥长度不是 16 应报错")
	}
}

// The data-plane framing: 4-byte big-endian plaintext length + ciphertext, the
// ciphertext length being the padded one. This is what the frame's length field
// must carry (len(ct)+4) while the prefix keeps the true length.
func TestWrapPayloadFraming(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	iv := bytes.Repeat([]byte{0x44}, 16)
	for _, n := range []int{1, 15, 16, 17, 2048, CDROMPacketSize} {
		plain := bytes.Repeat([]byte{0x5A}, n)
		wire, err := WrapPayload(plain, key, iv)
		if err != nil {
			t.Fatalf("WrapPayload(%d): %v", n, err)
		}
		if got := int(binary.BigEndian.Uint32(wire[0:4])); got != n {
			t.Fatalf("前缀应为真实明文长度 %d，实际 %d", n, got)
		}
		padded := (n + 15) / 16 * 16
		if got := len(wire) - 4; got != padded {
			t.Fatalf("密文长度应为补零后的 %d，实际 %d", padded, got)
		}
		if len(wire)%16 != 4 && padded == n {
			t.Fatalf("对齐时总长应为 4+%d，实际 %d", n, len(wire))
		}
		back, err := UnwrapPayload(wire, key, iv)
		if err != nil {
			t.Fatalf("UnwrapPayload(%d): %v", n, err)
		}
		if len(back) != n || !bytes.Equal(back, plain) {
			t.Fatalf("解出的长度/内容不对: %d != %d", len(back), n)
		}
	}

	if _, err := UnwrapPayload([]byte{0, 0, 1}, key, iv); err == nil {
		t.Fatal("短于 4 字节的负载应报错")
	}
	// A prefix that claims more than the ciphertext holds.
	bad, _ := WrapPayload(bytes.Repeat([]byte{1}, 16), key, iv)
	bad[3] = 200
	if _, err := UnwrapPayload(bad, key, iv); err == nil {
		t.Fatal("前缀大于解密长度应报错")
	}
	if out, err := WrapPayload(nil, key, iv); err != nil || out != nil {
		t.Fatalf("空负载应返回 nil, nil，实际 %v, %v", out, err)
	}
}
