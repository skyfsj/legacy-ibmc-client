package kvm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// SendPower is the one path that cannot be checked against the capture (the command
// byte is inside the ciphertext), so pin its layout here: 0x33 | 0x00 | AES(16B, cmd at [15]).
func TestSendPowerFrameLayout(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 48)
	s := &Session{kvmKey: key, codeKey: 1000000001}

	frame := s.powerFrame(0x21) // power on
	if frame == nil {
		t.Fatal("powerFrame 返回 nil")
	}
	if frame[0] != 0xfe || frame[1] != 0xf6 {
		t.Fatalf("魔数不对: %x", frame[:2])
	}
	payload := frame[10:]
	if payload[0] != CmdSecurity || payload[1] != 0x00 {
		t.Fatalf("应为 0x33/0x00，实际 %x", payload[:2])
	}
	enc := payload[2:]
	if len(enc) != 16 {
		t.Fatalf("密文应为 16 字节，实际 %d", len(enc))
	}
	plain, err := AESDecryptNoPad(enc, key[0:16], key[32:48])
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if plain[15] != 0x21 {
		t.Fatalf("命令字节应在偏移 15，实际 %x", plain[15])
	}
	for i := 0; i < 15; i++ {
		if plain[i] != 0 {
			t.Fatalf("前 15 字节应为 0，偏移 %d = %x", i, plain[i])
		}
	}
	t.Logf("电源帧: %s", hex.EncodeToString(frame))
}
