package store

// Verifies session persistence and that a remembered password is really
// encrypted on disk (no plaintext).
//
// Go port of test/store.test.js. Two adaptations:
//   - There is no Electron safeStorage; the data key comes from a Keyring, so the
//     tests inject an in-memory keyring instead of touching the real login
//     keychain (and the "no keychain at all" case can be simulated).
//   - Everything runs in t.TempDir(); the real config directory is never touched.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const secret = "S3cr3t-P@ssw0rd-must-not-leak-9f2a"

// memKeyring is an in-memory Keyring. fail=true simulates a machine without a
// usable keychain.
type memKeyring struct {
	mu   sync.Mutex
	key  []byte
	fail bool
}

func (m *memKeyring) Get() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, fmt.Errorf("%w: 测试模拟", ErrKeyringUnavailable)
	}
	if m.key == nil {
		return nil, ErrNoKeyringEntry
	}
	return append([]byte(nil), m.key...), nil
}

func (m *memKeyring) Set(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return fmt.Errorf("%w: 测试模拟", ErrKeyringUnavailable)
	}
	m.key = append([]byte(nil), key...)
	return nil
}

func newTestStore(t *testing.T) (*Store, *memKeyring) {
	t.Helper()
	// Seed the key: the store no longer generates one, because the key must be the
	// one Electron's safeStorage created in the keychain.
	kr := &memKeyring{key: bytes.Repeat([]byte{0x37}, 16)}
	st := NewAt(t.TempDir())
	st.Keyring = kr
	return st, kr
}

func fileContents(t *testing.T, st *Store) string {
	t.Helper()
	raw, err := os.ReadFile(st.File())
	if err != nil {
		t.Fatalf("读取存储文件失败：%v", err)
	}
	return string(raw)
}

func TestSaveListAndNoPlaintextLeak(t *testing.T) {
	st, _ := newTestStore(t)

	saved, err := st.Save(Record{
		Name: "测试机", Host: "10.0.0.9", HTTPSPort: 443, Username: "root",
		ColorBit: 2, Remember: true, Password: secret,
	})
	if err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	if saved.Name != "测试机" || saved.Host != "10.0.0.9" {
		t.Errorf("保存后的记录 = %+v", saved)
	}
	if !saved.HasPassword {
		t.Error("勾选记住密码后 HasPassword 应为 true")
	}
	if saved.ID == "" || saved.ID != IDFor("10.0.0.9", 443, "root") {
		t.Errorf("id = %q，期望 %q", saved.ID, IDFor("10.0.0.9", 443, "root"))
	}

	// list() 不泄露密码字段
	l := st.List()
	if len(l.Sessions) != 1 {
		t.Fatalf("List 返回 %d 条，期望 1 条", len(l.Sessions))
	}
	rec := l.Sessions[0]
	if rec.Password != "" || rec.HasPassword != true {
		t.Errorf("List 的结果 = %+v，期望不含密码、HasPassword=true", rec)
	}
	if l.LastUsed != saved.ID {
		t.Errorf("LastUsed = %q，期望 %q", l.LastUsed, saved.ID)
	}
	if strings.Contains(fmt.Sprintf("%+v", rec), secret) {
		t.Errorf("公开记录里出现了密码：%+v", rec)
	}

	// 磁盘文件里没有明文密码
	raw := fileContents(t, st)
	if strings.Contains(raw, secret) {
		t.Error("文件里出现了明文密码！")
	}
	if strings.Contains(raw, "S3cr3t") {
		t.Error("文件里出现了密码片段！")
	}
	if !strings.Contains(raw, "passwordEnc") {
		t.Error("应存在加密字段 passwordEnc")
	}

	// 能解回原密码
	got, ok, err := st.Password(saved.ID)
	if err != nil {
		t.Fatalf("Password 报错：%v", err)
	}
	if !ok || got != secret {
		t.Errorf("Password = %q/%v，期望 %q", got, ok, secret)
	}

	// 文件权限必须是 0600
	info, err := os.Stat(st.File())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("文件权限 = %o，期望 600", perm)
	}
}

func TestRememberOffNeverStores(t *testing.T) {
	st, _ := newTestStore(t)
	s2, err := st.Save(Record{
		Host: "10.0.0.10", HTTPSPort: 443, Username: "admin",
		Remember: false, Password: "another-secret",
	})
	if err != nil {
		t.Fatalf("remember=false 时 Save 不该失败：%v", err)
	}
	if s2.HasPassword {
		t.Error("未勾选记住密码却存了密码")
	}
	if _, ok, err := st.Password(s2.ID); ok || err != nil {
		t.Errorf("Password = %v/%v，期望未保存（ok=false, err=nil）", ok, err)
	}
	if raw := fileContents(t, st); strings.Contains(raw, "another-secret") {
		t.Error("文件里不该出现明文")
	}
}

// TestRefusesToStoreWithoutKeychain is the core policy of this port: no
// keychain, no remembered password — never a plaintext fallback.
func TestRefusesToStoreWithoutKeychain(t *testing.T) {
	st, kr := newTestStore(t)
	kr.fail = true

	_, err := st.Save(Record{
		Host: "10.0.0.11", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "must-not-be-written",
	})
	if err == nil {
		t.Fatal("钥匙串不可用时必须拒绝保存密码")
	}
	if !errors.Is(err, ErrEncryptionUnavailable) {
		t.Errorf("错误 = %v，期望 ErrEncryptionUnavailable", err)
	}
	// nothing may be written at all, let alone a plaintext password
	if _, statErr := os.Stat(st.File()); statErr == nil {
		raw := fileContents(t, st)
		if strings.Contains(raw, "must-not-be-written") {
			t.Fatal("钥匙串不可用时把密码明文写进了文件！")
		}
		if strings.Contains(raw, "passwordEnc") {
			t.Error("钥匙串不可用时不应留下 passwordEnc")
		}
	}

	// but not remembering still works (nothing needs encrypting)
	if _, err := st.Save(Record{
		Host: "10.0.0.11", HTTPSPort: 443, Username: "root", Remember: false,
	}); err != nil {
		t.Errorf("remember=false 不该依赖钥匙串：%v", err)
	}
}

func TestRenameKeepsPasswordAndRememberOffDeletes(t *testing.T) {
	st, _ := newTestStore(t)
	saved, err := st.Save(Record{
		Name: "测试机", Host: "10.0.0.9", HTTPSPort: 443, Username: "root",
		ColorBit: 2, Remember: true, Password: secret,
	})
	if err != nil {
		t.Fatal(err)
	}

	s3, err := st.Save(Record{
		ID: saved.ID, Name: "改过名的机器", Host: "10.0.0.9", HTTPSPort: 443,
		Username: "root", Remember: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s3.Name != "改过名的机器" {
		t.Errorf("name = %q", s3.Name)
	}
	if !s3.HasPassword {
		t.Error("改名字不该丢掉密码")
	}
	if pw, _, _ := st.Password(saved.ID); pw != secret {
		t.Errorf("改名字后密码 = %q，期望 %q", pw, secret)
	}

	s4, err := st.Save(Record{
		ID: saved.ID, Name: "改过名的机器", Host: "10.0.0.9", HTTPSPort: 443,
		Username: "root", Remember: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s4.HasPassword {
		t.Error("取消记住密码后应删除已存密码")
	}
	if _, ok, _ := st.Password(saved.ID); ok {
		t.Error("取消记住密码后不该还能取回密码")
	}
}

func TestRemove(t *testing.T) {
	st, _ := newTestStore(t)
	saved, err := st.Save(Record{Host: "10.0.0.9", Username: "root", Remember: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Remove(saved.ID); err != nil {
		t.Fatal(err)
	}
	if _, found := st.Get(saved.ID); found {
		t.Error("Remove 之后仍能取到记录")
	}
	if l := st.List(); len(l.Sessions) != 0 {
		t.Errorf("Remove 之后还剩 %d 条", len(l.Sessions))
	}
	if l := st.List(); l.LastUsed != "" {
		t.Errorf("Remove 之后 LastUsed = %q，期望空", l.LastUsed)
	}
}

// TestResolvePasswordFieldNameContract is the regression the JS store.js
// comments: the renderer sends the key as `id` while main used to read only
// `sessionId`, which silently disabled keychain lookup.
func TestResolvePasswordFieldNameContract(t *testing.T) {
	st, _ := newTestStore(t)
	withPw, err := st.Save(Record{
		Name: "契约测试", Host: "10.0.0.20", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "pw-for-contract-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !withPw.HasPassword {
		t.Fatal("准备失败：没有存下密码")
	}

	r, err := st.ResolvePassword(ResolveOptions{ID: withPw.ID, Password: "typed"})
	if err != nil || r.Password != "typed" || r.Source != SourceProvided {
		t.Errorf("显式密码 = %+v/%v，期望 typed/provided", r, err)
	}

	r, err = st.ResolvePassword(ResolveOptions{ID: withPw.ID})
	if err != nil || r.Password != "pw-for-contract-test" || r.Source != SourceKeychain {
		t.Errorf("用 id 取钥匙串密码 = %+v/%v", r, err)
	}

	r, err = st.ResolvePassword(ResolveOptions{SessionID: withPw.ID})
	if err != nil || r.Password != "pw-for-contract-test" || r.Source != SourceKeychain {
		t.Errorf("用 sessionId 取钥匙串密码 = %+v/%v", r, err)
	}

	r, err = st.ResolvePassword(ResolveOptions{ID: "nope", Host: "10.0.0.20", Username: "root"})
	if err != nil || r.Source != SourceNone || r.Password != "" {
		t.Errorf("未知 id = %+v/%v，期望 none", r, err)
	}

	r, err = st.ResolvePassword(ResolveOptions{})
	if err != nil || r.Source != SourceNone {
		t.Errorf("空请求 = %+v/%v，期望 none", r, err)
	}
}

func TestResolvePasswordDistinctErrorWhenUndecryptable(t *testing.T) {
	st, _ := newTestStore(t)
	withPw, err := st.Save(Record{
		Name: "契约测试", Host: "10.0.0.20", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "pw-for-contract-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// simulate a stale keychain entry by corrupting the ciphertext
	var doc map[string]any
	if err := json.Unmarshal([]byte(fileContents(t, st)), &doc); err != nil {
		t.Fatal(err)
	}
	sessions := doc["sessions"].([]any)
	rec := sessions[0].(map[string]any)
	rec["passwordEnc"] = "bm90LWEtdmFsaWQtY2lwaGVydGV4dA==" // base64("not-a-valid-ciphertext")
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.File(), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = st.ResolvePassword(ResolveOptions{ID: withPw.ID})
	if err == nil {
		t.Fatal("声称有密码但解不开时必须报错，而不是当成「缺少密码」")
	}
	if !errors.Is(err, ErrPasswordNotDecryptable) {
		t.Errorf("错误 = %v，期望 ErrPasswordNotDecryptable", err)
	}
	if !strings.Contains(err.Error(), "无法解密") {
		t.Errorf("错误信息 = %q，应含「无法解密」", err.Error())
	}
	if _, _, perr := st.Password(withPw.ID); !errors.Is(perr, ErrPasswordNotDecryptable) {
		t.Errorf("Password 的错误 = %v，期望 ErrPasswordNotDecryptable", perr)
	}
}

// TestPasswordUnreadableAfterKeychainChange covers the real-world cause of that
// message: the keychain entry (or the machine) changed, so the old ciphertext is
// no longer readable.
func TestPasswordUnreadableAfterKeychainChange(t *testing.T) {
	dir := t.TempDir()
	first := NewAt(dir)
	first.Keyring = &memKeyring{key: bytes.Repeat([]byte{0x11}, 16)}
	saved, err := first.Save(Record{
		Host: "10.0.0.21", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "pw-before-keychain-change",
	})
	if err != nil {
		t.Fatal(err)
	}

	second := NewAt(dir)
	second.Keyring = &memKeyring{key: bytes.Repeat([]byte{0x42}, 16)}
	if _, _, err := second.Password(saved.ID); !errors.Is(err, ErrPasswordNotDecryptable) {
		t.Errorf("钥匙串变化后的错误 = %v，期望 ErrPasswordNotDecryptable", err)
	}
	if err := second.Remove(saved.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOverwriteAndPreservePassword(t *testing.T) {
	st, _ := newTestStore(t)
	ov, err := st.Save(Record{
		Name: "覆盖测试", Host: "10.0.0.30", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "OLD-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pw, _, _ := st.Password(ov.ID); pw != "OLD-password" {
		t.Fatalf("准备失败：密码 = %q", pw)
	}

	// 输入新密码 → 覆盖旧的（且磁盘上仍是密文）
	if _, err := st.Save(Record{
		ID: ov.ID, Host: "10.0.0.30", HTTPSPort: 443, Username: "root",
		Remember: true, Password: "NEW-password",
	}); err != nil {
		t.Fatal(err)
	}
	if pw, _, _ := st.Password(ov.ID); pw != "NEW-password" {
		t.Errorf("覆盖后密码 = %q，期望 NEW-password", pw)
	}
	raw := fileContents(t, st)
	if strings.Contains(raw, "NEW-password") || strings.Contains(raw, "OLD-password") {
		t.Error("文件里出现了明文密码")
	}

	// 不改密码时（password 未提供）保留原密码
	if _, err := st.Save(Record{
		ID: ov.ID, Name: "改个名字", Host: "10.0.0.30", HTTPSPort: 443,
		Username: "root", Remember: true,
	}); err != nil {
		t.Fatal(err)
	}
	if pw, _, _ := st.Password(ov.ID); pw != "NEW-password" {
		t.Errorf("未提供密码时被改动了：%q", pw)
	}

	// 取消「记住密码」→ 删除已存密码
	if _, err := st.Save(Record{
		ID: ov.ID, Host: "10.0.0.30", HTTPSPort: 443, Username: "root", Remember: false,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Password(ov.ID); ok {
		t.Error("取消记住密码后仍能取回密码")
	}
}

func TestStoreUsesTempDirAndNeverTheRealProfile(t *testing.T) {
	dir := t.TempDir()
	st := NewAt(dir)
	if filepath.Dir(st.File()) != dir {
		t.Errorf("File() = %q，期望位于测试临时目录 %q", st.File(), dir)
	}
	if filepath.Base(st.File()) != FileName {
		t.Errorf("File() = %q，文件名应为 %q", st.File(), FileName)
	}
	// New() would point at the real profile, which the tests must never touch.
	if !strings.Contains(New().File(), DirName) {
		t.Errorf("默认存储路径 %q 应位于 %s 目录下", New().File(), DirName)
	}
}

// safeStorage-compatible layout. The blob below was produced OUTSIDE this package
// (PBKDF2-SHA1(password,"saltysalt",1003) + AES-128-CBC/PKCS#7 with Chromium's fixed
// 16-space IV), so it pins the byte layout independently of our own encryptor. If this test ever fails, the
// Go build has stopped being able to read passwords written by the Electron build.
func TestOSCryptInteropVector(t *testing.T) {
	const (
		keyHex = "c0ffe4c25f07f62bfc6ab011d9efa54e"
		blob   = "djEwBBaH4/+V4L5uegch591+9pjC69yhG5mXE5n/KkUvfWc="
		want   = "interop-vector-123"
	)
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OSCryptDecrypt(key, raw)
	if err != nil {
		t.Fatalf("解密参考向量失败: %v", err)
	}
	if string(got) != want {
		t.Fatalf("明文不符: 得到 %q 期望 %q", got, want)
	}

	// and our output must have the same shape + round-trip
	enc, err := OSCryptEncrypt(key, []byte(want))
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:3]) != "v10" {
		t.Fatalf("缺少 v10 前缀: %q", enc[:3])
	}
	back, err := OSCryptDecrypt(key, enc)
	if err != nil || string(back) != want {
		t.Fatalf("往返失败: %q %v", back, err)
	}

	// a wrong key must be rejected, not silently return garbage
	bad := append([]byte(nil), key...)
	bad[0] ^= 0xff
	if _, err := OSCryptDecrypt(bad, raw); err == nil {
		t.Fatal("错误密钥应当解密失败")
	}
}

// A record whose password field cannot be decrypted must raise the distinct
// "无法解密" error rather than silently behaving like "no password saved".
func TestCorruptPasswordIsReported(t *testing.T) {
	st, kr := newTestStore(t)
	_ = kr
	rec, err := st.Save(Record{Host: "10.0.0.40", HTTPSPort: 443, Username: "root", Remember: true, Password: "x"})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	raw := map[string]any{}
	b, _ := os.ReadFile(st.File())
	json.Unmarshal(b, &raw)
	list := raw["sessions"].([]any)
	list[0].(map[string]any)["passwordEnc"] = base64.StdEncoding.EncodeToString([]byte("not-a-v10-blob"))
	out, _ := json.Marshal(raw)
	os.WriteFile(st.File(), out, 0o600)

	if _, _, err := st.Password(rec.ID); !errors.Is(err, ErrPasswordNotDecryptable) {
		t.Fatalf("期望 ErrPasswordNotDecryptable，得到 %v", err)
	}
}
