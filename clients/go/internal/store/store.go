// Package store implements session persistence: saved machines and optional
// remembered passwords (a port of src/main/store.js).
//
// Passwords are encrypted with AES-256-GCM under a random 32-byte data key that
// lives in the OS keychain, and are never written in plaintext. If the OS cannot
// provide a keychain entry we refuse to remember the password rather than
// silently storing it in the clear — the same policy as the JS reference, which
// used Electron's safeStorage for the same reason.
//
// The keychain is reached through the `security` CLI (add-generic-password /
// find-generic-password), which is the only keychain access available to a plain
// Go binary without cgo. Only macOS is wired up; elsewhere the store still works
// but refuses to remember passwords.
package store

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// appName is used for the config directory AND for the keychain entry names, so it
	// must match the Electron build's app.setName().
	appName = "huawei-ibmc-kvm-client"

	// DirName is the directory under the user config dir that holds the store.
	DirName = "huawei-ibmc-kvm-client"
	// FileName is the store file name.
	FileName = "sessions.json"

	// keyringService / keyringAccount identify the keychain entry holding the
	// 32-byte data key used to encrypt remembered passwords.
	// Deliberately the SAME entry Electron's safeStorage creates, so a password saved
	// by either build is readable by the other. macOS shows a one-time "wants to use
	// this key" prompt the first time a different binary reads it; choosing
	// "Always Allow" makes it permanent.
	// keychainTimeout guards against the authorization dialog blocking us.
	keychainTimeout = 10 * time.Second

	keyringService = appName + " Safe Storage"
	// keyringAccount is "<app> Key" — NOT "<service> Key". Chromium stores the
	// safeStorage secret under service "<app> Safe Storage" / account "<app> Key";
	// guessing the account from the service name silently yields "no key yet".
	keyringAccount = appName + " Key"
)

// Errors returned by the store. Callers are expected to distinguish
// ErrPasswordNotDecryptable ("a password is stored but unreadable") from "no
// password stored at all" — the JS reference had exactly this distinction after
// a mismatched field name silently disabled keychain lookup.
var (
	// ErrNoKeyringEntry means the keychain works but holds no entry yet; the
	// store creates one on first use.
	ErrNoKeyringEntry = errors.New("钥匙串中没有条目")
	// ErrKeyringUnavailable means there is no usable keychain at all.
	ErrKeyringUnavailable = errors.New("系统钥匙串不可用")
	// ErrEncryptionUnavailable is what Save returns when the password was asked
	// to be remembered but cannot be encrypted.
	ErrEncryptionUnavailable = errors.New("系统未提供加密存储（系统钥匙串不可用），无法安全地记住密码")
	// ErrPasswordNotDecryptable means the record claims a password that cannot be
	// decrypted (stale keychain entry, corrupted ciphertext, other machine).
	ErrPasswordNotDecryptable = errors.New("已保存的密码无法解密（系统钥匙串条目可能已失效）。请重新输入密码，或取消「记住密码」后再连。")
)

// Password sources reported by ResolvePassword.
const (
	SourceProvided = "provided"
	SourceKeychain = "keychain"
	SourceNone     = "none"
)

// Keyring stores the 32-byte data key that protects remembered passwords.
type Keyring interface {
	// Get returns the data key, ErrNoKeyringEntry when the keychain works but has
	// no entry yet, or ErrKeyringUnavailable when there is no usable keychain.
	Get() ([]byte, error)
	// Set stores (or replaces) the data key.
	Set(key []byte) error
}

// Store is the on-disk session store.
type Store struct {
	// Dir is the directory holding sessions.json. Empty means the default
	// (<userConfigDir>/huawei-ibmc-kvm-client).
	Dir string
	// Keyring provides the password data key. Nil means the platform default
	// (`security` CLI on macOS).
	Keyring Keyring
}

// Record is the public view of a saved machine. It never carries password
// material: HasPassword only says whether a password is stored.
//
// Password is input-only (it is ignored when reading) and is never persisted in
// cleartext.
type Record struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Host        string `json:"host"`
	HTTPSPort   int    `json:"httpsPort"`
	Username    string `json:"username"`
	ColorBit    int    `json:"colorBit"`
	DQT         int    `json:"dqt,omitempty"`
	Remember    bool   `json:"remember"`
	HasPassword bool   `json:"hasPassword"`
	CreatedAt   int64  `json:"createdAt,omitempty"`
	UpdatedAt   int64  `json:"updatedAt,omitempty"`

	// Password is input-only for Save. An empty string means "not provided",
	// which preserves whatever is already stored.
	Password string `json:"-"`
}

// ListResult is what List returns: the public records plus the last used id.
type ListResult struct {
	Sessions []Record `json:"sessions"`
	LastUsed string   `json:"lastUsed,omitempty"`
}

// ResolveOptions selects the password to use for a connect request. It accepts
// both `SessionID` and `ID`: the renderer's form record calls it `id`, and a
// mismatch here silently disabled keychain lookup once already (JS store.js).
type ResolveOptions struct {
	// Password, when non-empty, wins outright (source = provided).
	Password string
	// SessionID / ID are the saved record's id, in either spelling.
	SessionID string
	ID        string
	Host      string
	Username  string
}

// ResolveResult is the outcome of ResolvePassword.
type ResolveResult struct {
	Password string
	Source   string // provided | keychain | none
}

// ---------------------------------------------------------------------------
// Construction / file layout
// ---------------------------------------------------------------------------

// New returns a store at the default location with the platform keyring.
func New() *Store { return &Store{Dir: DefaultDir()} }

// NewAt returns a store rooted at dir (used by tests; never the real profile).
func NewAt(dir string) *Store { return &Store{Dir: dir} }

// DefaultDir is <userConfigDir>/huawei-ibmc-kvm-client.
func DefaultDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	return filepath.Join(base, DirName)
}

// File is the path of the JSON file.
func (s *Store) File() string { return filepath.Join(s.dir(), FileName) }

func (s *Store) dir() string {
	if s.Dir == "" {
		return DefaultDir()
	}
	return s.Dir
}

// storedRecord is the on-disk shape; PasswordEnc is the only secret in it.
type storedRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Host        string `json:"host"`
	HTTPSPort   int    `json:"httpsPort"`
	Username    string `json:"username"`
	ColorBit    int    `json:"colorBit"`
	DQT         int    `json:"dqt,omitempty"`
	Remember    bool   `json:"remember"`
	CreatedAt   int64  `json:"createdAt,omitempty"`
	UpdatedAt   int64  `json:"updatedAt,omitempty"`
	PasswordEnc string `json:"passwordEnc,omitempty"`
	// EncScheme records which implementation wrote PasswordEnc. The Electron build
	// shares this same config file but uses safeStorage, so a record can carry a
	// ciphertext we cannot read; tagging it lets us say so precisely instead of
	// reporting a vague "wrong password".
	EncScheme string `json:"encScheme,omitempty"`
}

// Scheme values for storedRecord.EncScheme.
const (
	SchemeGCM      = "aes-256-gcm+keychain" // this build
	SchemeElectron = "electron-safeStorage" // the Electron build, unreadable here
)

type fileData struct {
	Version  int            `json:"version"`
	Sessions []storedRecord `json:"sessions"`
	LastUsed string         `json:"lastUsed,omitempty"`
}

// read never fails: a missing, unreadable or corrupt file starts empty, exactly
// like the JS reference.
func (s *Store) read() fileData {
	raw, err := os.ReadFile(s.File())
	if err != nil {
		return fileData{Version: 1}
	}
	var d fileData
	if err := json.Unmarshal(raw, &d); err != nil || d.Sessions == nil {
		return fileData{Version: 1}
	}
	if d.Version == 0 {
		d.Version = 1
	}
	return d
}

func (s *Store) write(d fileData) error {
	if d.Version == 0 {
		d.Version = 1
	}
	if err := os.MkdirAll(s.dir(), 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	file := s.File()
	// write-then-rename so a crash cannot leave a truncated file
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// publicView strips the secret before anything leaves the store.
func publicView(rec storedRecord) Record {
	return Record{
		ID:          rec.ID,
		Name:        rec.Name,
		Host:        rec.Host,
		HTTPSPort:   rec.HTTPSPort,
		Username:    rec.Username,
		ColorBit:    rec.ColorBit,
		DQT:         rec.DQT,
		Remember:    rec.Remember,
		HasPassword: rec.PasswordEnc != "",
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}
}

// IDFor derives the stable record id: sha1("user@host:port")[:12].
func IDFor(host string, httpsPort int, username string) string {
	if httpsPort == 0 {
		httpsPort = 443
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%s@%s:%d", username, host, httpsPort)))
	return hex.EncodeToString(sum[:])[:12]
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// List returns every saved record (without password material) and the last used id.
func (s *Store) List() ListResult {
	d := s.read()
	out := ListResult{Sessions: make([]Record, 0, len(d.Sessions)), LastUsed: d.LastUsed}
	for _, rec := range d.Sessions {
		out.Sessions = append(out.Sessions, publicView(rec))
	}
	return out
}

// Get returns one record by id.
func (s *Store) Get(id string) (Record, bool) {
	for _, rec := range s.read().Sessions {
		if rec.ID == id {
			return publicView(rec), true
		}
	}
	return Record{}, false
}

// Save creates or updates a session.
//
// Only touches the stored password when rec.Password is provided: a new password
// overwrites, remember=false deletes, and leaving it empty preserves what is
// there. Returns ErrEncryptionUnavailable (and writes nothing) when a password
// was asked to be remembered but cannot be encrypted.
func (s *Store) Save(rec Record) (Record, error) {
	d := s.read()
	id := rec.ID
	if id == "" {
		id = IDFor(rec.Host, rec.HTTPSPort, rec.Username)
	}
	idx := -1
	for i := range d.Sessions {
		if d.Sessions[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		d.Sessions = append(d.Sessions, storedRecord{ID: id, CreatedAt: time.Now().UnixMilli()})
		idx = len(d.Sessions) - 1
	}
	entry := &d.Sessions[idx]

	if rec.Name != "" {
		entry.Name = rec.Name
	} else if entry.Name == "" {
		entry.Name = rec.Host
	}
	entry.Host = rec.Host
	if rec.HTTPSPort != 0 {
		entry.HTTPSPort = rec.HTTPSPort
	} else if entry.HTTPSPort == 0 {
		entry.HTTPSPort = 443
	}
	entry.Username = rec.Username
	if rec.ColorBit != 0 {
		entry.ColorBit = rec.ColorBit
	} else if entry.ColorBit == 0 {
		entry.ColorBit = 2
	}
	if rec.DQT != 0 {
		entry.DQT = rec.DQT
	}
	entry.Remember = rec.Remember
	entry.UpdatedAt = time.Now().UnixMilli()

	if rec.Password != "" {
		if entry.Remember {
			enc, err := s.encryptPassword(rec.Password)
			if err != nil {
				return Record{}, err
			}
			entry.PasswordEnc = enc
			entry.EncScheme = SchemeElectron
		} else {
			entry.PasswordEnc = "" // user turned remembering off
		}
	} else if !entry.Remember {
		entry.PasswordEnc = ""
	}

	d.LastUsed = id
	if err := s.write(d); err != nil {
		return Record{}, err
	}
	return publicView(*entry), nil
}

// Remove deletes a session.
func (s *Store) Remove(id string) error {
	d := s.read()
	kept := d.Sessions[:0]
	for _, rec := range d.Sessions {
		if rec.ID != id {
			kept = append(kept, rec)
		}
	}
	d.Sessions = kept
	if d.LastUsed == id {
		d.LastUsed = ""
	}
	return s.write(d)
}

// MarkUsed records which session was used last.
func (s *Store) MarkUsed(id string) error {
	d := s.read()
	for _, rec := range d.Sessions {
		if rec.ID == id {
			d.LastUsed = id
			return s.write(d)
		}
	}
	return nil
}

// Password returns the decrypted password for a saved session.
//
// ok is false when nothing is stored. err is ErrPasswordNotDecryptable when the
// record claims a stored password that cannot be read back — deliberately
// distinct from "no password", so callers can say so instead of "缺少密码".
func (s *Store) Password(id string) (pw string, ok bool, err error) {
	rec, found := s.stored(id)
	if !found || rec.PasswordEnc == "" {
		return "", false, nil
	}
	plain, derr := s.decryptPasswordScheme(rec.PasswordEnc, rec.EncScheme)
	if derr != nil {
		if errors.Is(derr, ErrForeignPassword) {
			return "", false, ErrForeignPassword
		}
		return "", false, ErrPasswordNotDecryptable
	}
	return plain, true, nil
}

// ResolvePassword works out which password to use for a connect request.
//
// Accepts both `SessionID` and `ID`; a field-name mismatch here silently
// disabled keychain lookup once already, so both spellings are honoured.
func (s *Store) ResolvePassword(opts ResolveOptions) (ResolveResult, error) {
	if opts.Password != "" {
		return ResolveResult{Password: opts.Password, Source: SourceProvided}, nil
	}
	id := opts.SessionID
	if id == "" {
		id = opts.ID
	}
	if id != "" {
		pw, ok, err := s.Password(id)
		if err != nil {
			return ResolveResult{}, err
		}
		if ok && pw != "" {
			return ResolveResult{Password: pw, Source: SourceKeychain}, nil
		}
	}
	return ResolveResult{Password: "", Source: SourceNone}, nil
}

func (s *Store) stored(id string) (storedRecord, bool) {
	for _, rec := range s.read().Sessions {
		if rec.ID == id {
			return rec, true
		}
	}
	return storedRecord{}, false
}

// ---------------------------------------------------------------------------
// Password encryption
// ---------------------------------------------------------------------------

// KeyringAvailable reports whether remembered passwords can be protected on this
// machine. When false, Save refuses to store a password rather than falling back
// to plaintext.
func (s *Store) KeyringAvailable() bool {
	_, err := s.keyring().Get()
	return err != ErrKeyringUnavailable
}

func (s *Store) keyring() Keyring {
	if s.Keyring != nil {
		return s.Keyring
	}
	return defaultKeyring()
}

// dataKey returns the 32-byte data key, generating and storing it on first use.
func (s *Store) dataKey() ([]byte, error) {
	kr := s.keyring()
	raw, err := kr.Get()
	if err == nil {
		return OSCryptKey(string(raw))
	}
	if !errors.Is(err, ErrNoKeyringEntry) {
		return nil, err
	}
	// No entry yet. We cannot create one ourselves: this key belongs to Electron's
	// safeStorage, and writing our own would make existing safeStorage ciphertexts
	// unreadable. Report it so the UI can tell the user to save a password once with
	// the version that owns the keychain entry.
	return nil, errors.New("钥匙串里还没有 Safe Storage 密钥；请先用 Electron 版保存一次密码以创建它")
}

func (s *Store) encryptPassword(password string) (string, error) {
	key, err := s.dataKey()
	if err != nil {
		return "", fmt.Errorf("%w（%v）", ErrEncryptionUnavailable, err)
	}
	blob, err := OSCryptEncrypt(key, []byte(password))
	if err != nil {
		return "", fmt.Errorf("%w（%v）", ErrEncryptionUnavailable, err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

func (s *Store) decryptPassword(encoded string) (string, error) {
	return s.decryptPasswordScheme(encoded, "")
}

// ErrForeignPassword means the ciphertext was written by a different build.
var ErrForeignPassword = errors.New("该密码由 Electron 版保存，加密格式不同，本版无法解密")

func (s *Store) decryptPasswordScheme(encoded, scheme string) (string, error) {
	// Both builds now use the safeStorage v10 layout, so there is nothing to gate on:
	// just try to decrypt. (scheme is kept for diagnostics only.)
	return s.decryptPasswordSchemeInner(encoded)
}

func (s *Store) decryptPasswordSchemeInner(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrPasswordNotDecryptable
	}
	key, err := s.dataKey() // derives the AES key from the keychain password
	if err != nil {
		return "", ErrPasswordNotDecryptable
	}
	plain, err := OSCryptDecrypt(key, raw)
	if err != nil {
		return "", ErrPasswordNotDecryptable
	}
	return string(plain), nil
}

// ---------------------------------------------------------------------------
// Keyring implementations
// ---------------------------------------------------------------------------

func defaultKeyring() Keyring {
	if runtime.GOOS == "darwin" {
		return securityKeyring{Service: keyringService, Account: keyringAccount}
	}
	return unavailableKeyring{}
}

// securityKeyring keeps the data key in the login keychain through the
// `security` CLI.
type securityKeyring struct {
	Service string
	Account string
}

func (k securityKeyring) Get() ([]byte, error) {
	args := []string{"find-generic-password", "-s", k.Service, "-w"}
	if k.Account != "" {
		args = append(args, "-a", k.Account)
	}
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", args...).Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("%w: 读取钥匙串超时（可能弹出了授权对话框，选择「始终允许」后重试）", ErrKeyringUnavailable)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			// errSecItemNotFound: no entry yet, which is not an error.
			return nil, ErrNoKeyringEntry
		}
		return nil, fmt.Errorf("%w: security find-generic-password: %v", ErrKeyringUnavailable, err)
	}
	// The keychain value is a password, not the AES key: the key is derived from it
	// (see OSCryptKey). Return it verbatim.
	return []byte(strings.TrimSpace(string(out))), nil
}

// Set is deliberately unsupported: this entry belongs to Electron's safeStorage, and
// rewriting it would make every password it has already stored undecryptable.
func (k securityKeyring) Set(key []byte) error {
	return fmt.Errorf("%w: 该条目由 Electron safeStorage 管理，本程序不会改写它", ErrKeyringUnavailable)
}

// unavailableKeyring is the non-macOS default: the store still works, but
// remembering a password is refused instead of falling back to plaintext.
type unavailableKeyring struct{}

func (unavailableKeyring) Get() ([]byte, error) {
	return nil, fmt.Errorf("%w: 该平台尚未接入钥匙串（仅实现 macOS 的 security CLI）", ErrKeyringUnavailable)
}

func (unavailableKeyring) Set([]byte) error {
	return fmt.Errorf("%w: 该平台尚未接入钥匙串（仅实现 macOS 的 security CLI）", ErrKeyringUnavailable)
}

// ---------------------------------------------------------------------------
// Package-level convenience API (mirrors the JS module's exported functions)
// ---------------------------------------------------------------------------

// Default is the store used by the package-level helpers.
var Default = New()

// List mirrors the JS store.list().
func List() ListResult { return Default.List() }

// Get mirrors the JS store.get(id).
func Get(id string) (Record, bool) { return Default.Get(id) }

// Save mirrors the JS store.save(rec).
func Save(rec Record) (Record, error) { return Default.Save(rec) }

// Remove mirrors the JS store.remove(id).
func Remove(id string) error { return Default.Remove(id) }

// Password mirrors the JS store.password(id).
func Password(id string) (string, bool, error) { return Default.Password(id) }

// MarkUsed mirrors the JS store.markUsed(id).
func MarkUsed(id string) error { return Default.MarkUsed(id) }

// ResolvePassword mirrors the JS store.resolvePassword(opts).
func ResolvePassword(opts ResolveOptions) (ResolveResult, error) {
	return Default.ResolvePassword(opts)
}

// File returns the default store's file path.
func File() string { return Default.File() }
