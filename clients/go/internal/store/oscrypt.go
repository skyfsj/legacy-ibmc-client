package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
)

// Chromium / Electron safeStorage-compatible string encryption (macOS).
//
// Layout — verified against real Electron output, not assumed:
//
//	"v10" | AES-128-CBC( PKCS#7-padded plaintext )
//
// There is NO IV in the blob. The IV is 16 spaces (0x20) and the key is derived from
// the keychain entry's password:
//
//	key = PBKDF2-HMAC-SHA1(keychainPassword, "saltysalt", 1003, 16)
//
// The keychain entry is "<app> Safe Storage" with account "<app> Key" — the same one
// Electron's safeStorage creates, which is what lets the Go and Electron builds read
// each other's saved passwords. Longer plaintexts simply produce more blocks:
// 3 chars -> 19 bytes, 16 chars -> 35 bytes.
const (
	oscryptPrefix   = "v10"
	oscryptSalt     = "saltysalt"
	oscryptIters    = 1003
	oscryptKeyLen   = 16
	oscryptKeychain = "huawei-ibmc-kvm-client Safe Storage"
)

// oscryptIV is Chromium's fixed IV on macOS: sixteen spaces.
var oscryptIV = bytes.Repeat([]byte{' '}, aes.BlockSize)

var (
	// ErrNotOSCrypt means the blob is not in the v10 layout.
	ErrNotOSCrypt = errors.New("密文不是 safeStorage(v10) 格式")
)

// OSCryptKey derives the AES-128 key from the keychain password.
func OSCryptKey(keychainPassword string) ([]byte, error) {
	k, err := pbkdf2.Key(sha1.New, keychainPassword, []byte(oscryptSalt), oscryptIters, oscryptKeyLen)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// OSCryptEncrypt produces a blob readable by Electron's safeStorage.decryptString.
func OSCryptEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != oscryptKeyLen {
		return nil, fmt.Errorf("密钥长度应为 %d，实际 %d", oscryptKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, oscryptIV).CryptBlocks(ct, padded)
	return append([]byte(oscryptPrefix), ct...), nil
}

// OSCryptDecrypt reverses OSCryptEncrypt.
func OSCryptDecrypt(key, blob []byte) ([]byte, error) {
	if len(key) != oscryptKeyLen {
		return nil, fmt.Errorf("密钥长度应为 %d，实际 %d", oscryptKeyLen, len(key))
	}
	if len(blob) < len(oscryptPrefix)+aes.BlockSize || !bytes.Equal(blob[:len(oscryptPrefix)], []byte(oscryptPrefix)) {
		return nil, ErrNotOSCrypt
	}
	ct := blob[len(oscryptPrefix):]
	if len(ct)%aes.BlockSize != 0 {
		return nil, ErrNotOSCrypt
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, oscryptIV).CryptBlocks(pt, ct)

	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return nil, errors.New("padding 无效（密钥不匹配或密文损坏）")
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return nil, errors.New("padding 无效（密钥不匹配或密文损坏）")
		}
	}
	return pt[:len(pt)-pad], nil
}

// EncodeOSCryptBlob / DecodeOSCryptBlob convert to and from the base64 form used in
// sessions.json, so callers do not have to remember which layer is base64.
func EncodeOSCryptBlob(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func DecodeOSCryptBlob(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
