package store

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// Opt-in: reads the REAL "<app> Safe Storage" keychain entry that Electron's
// safeStorage created. That entry is what makes the two builds interoperable, so
// being able to read it is the actual prerequisite for shared passwords.
//
// The first read by a different binary makes macOS show an authorization prompt;
// choosing "Always Allow" makes it permanent. The read has a timeout so a missed
// prompt fails fast instead of hanging the test.
//
//	HUAWEI_IBMC_KVM_TEST_KEYCHAIN=1 go test -run TestSecurityKeyring ./internal/store/ -v
func TestSecurityKeyring(t *testing.T) {
	if os.Getenv("HUAWEI_IBMC_KVM_TEST_KEYCHAIN") == "" {
		t.Skip("设置 HUAWEI_IBMC_KVM_TEST_KEYCHAIN=1 才会读取真实钥匙串")
	}
	if _, err := exec.LookPath("security"); err != nil {
		t.Skipf("security CLI 不可用：%v", err)
	}

	kr := securityKeyring{Service: keyringService, Account: keyringAccount}
	key, err := kr.Get()
	if errors.Is(err, ErrNoKeyringEntry) {
		t.Skipf("钥匙串里没有 %q 条目 —— 先用 Electron 版保存一次密码即可创建", keyringService)
	}
	if err != nil {
		t.Fatalf("读取 %q 失败：%v", keyringService, err)
	}
	// the keychain value is the PBKDF2 *password*, not the AES key
	if len(key) == 0 {
		t.Fatal("读到的钥匙串口令为空")
	}
	derived, err := OSCryptKey(string(key))
	if err != nil || len(derived) != 16 {
		t.Fatalf("派生 AES 密钥失败：%v len=%d", err, len(derived))
	}
	t.Logf("成功读到 safeStorage 口令（%d 字符），派生出 16 字节 AES 密钥 —— 与 Electron 版共用同一条钥匙串项", len(key))

	// We must never rewrite it: that would invalidate everything Electron stored.
	if err := kr.Set(key); err == nil {
		t.Fatal("Set 应当拒绝改写 Electron 的钥匙串条目")
	} else {
		t.Logf("Set 按设计拒绝改写：%v", err)
	}
}

// The real cross-implementation check: decrypt a password the ELECTRON build wrote,
// using the shared keychain key. This is what "统一加密方式" has to mean in practice.
// It only reports the shape of the result, never the password itself.
func TestDecryptsElectronSavedPassword(t *testing.T) {
	if os.Getenv("HUAWEI_IBMC_KVM_TEST_KEYCHAIN") == "" {
		t.Skip("设置 HUAWEI_IBMC_KVM_TEST_KEYCHAIN=1 才会读取真实钥匙串")
	}
	st := New() // the real config dir, shared with the Electron build
	l := st.List()
	var target *Record
	for i := range l.Sessions {
		if l.Sessions[i].HasPassword {
			target = &l.Sessions[i]
			break
		}
	}
	if target == nil {
		t.Skip("共享的 sessions.json 里没有带密码的机器")
	}
	t.Logf("目标机器: %s (%s)", target.Name, target.Host)

	pw, err := st.ResolvePassword(ResolveOptions{ID: target.ID})
	if err != nil {
		t.Fatalf("无法解密 Electron 版保存的密码：%v", err)
	}
	if pw.Source != SourceKeychain {
		t.Fatalf("期望来源 keychain，实际 %s", pw.Source)
	}
	if pw.Password == "" {
		t.Fatal("解出的密码为空")
	}
	printable := true
	for _, c := range pw.Password {
		if c < 32 || c > 126 {
			printable = false
			break
		}
	}
	if !printable {
		t.Fatalf("解出的不是可打印 ASCII（%d 字节）—— 格式或密钥不匹配", len(pw.Password))
	}
	t.Logf("✅ 成功解开 Electron 版保存的密码（%d 字节可打印 ASCII）—— 两版加密已统一", len(pw.Password))
}
