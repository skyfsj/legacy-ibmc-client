package vmm

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/kvm"
)

// ---------------------------------------------------------------------------
// KVM-channel bootstrap
//
// The VMM port and the code key are handed out over the KVM channel:
//
//	TX REQ_VMM_CODEKEY(0x31) payload {31, blade}
//	RX VMM_CODEKEY_REPORT(0x32) -> 20-byte code key + 16-byte vmm salt
//	TX REQ_VMM_PORT(0x35)    payload {35, blade}
//	RX VMM_PORT_REPORT(0x36)   -> 2-byte port, little-endian
//
// Both reports are AES-encrypted with kvm_key when the KVM channel's `compress`
// parameter is 1 (BladeThread.distributeNegotiVMMCodeKey / distributeVMMPort use
// AESHandler.decry: key = kvm_key[0:16], IV = kvm_key[32:48]).
//
// The Java polls each reply for 50 * 60ms = 3s (VirtualMedia's two request
// methods) and gives up when the blade is not the primary one (NOT_PRI 0x51).
// ---------------------------------------------------------------------------

// Bootstrap is the VMM material learned from the KVM channel.
type Bootstrap struct {
	// CodeKey is the 20-byte PBKDF2 password material.
	CodeKey []byte
	// Salt is the 16-byte vmm salt.
	Salt []byte
	// Port is the VMM TCP port, decoded little-endian from the report.
	Port int
	// Compress is the KVM channel's `compress` setting, echoed here for the
	// caller's convenience; it selects how the reports were decrypted.
	Compress bool
}

// BootstrapPollInterval and BootstrapPollCount are the Java's
// `Thread.sleep(60)` / `for (i = 0; i < 50; ++i)` loop bounds.
const (
	BootstrapPollInterval = 60 * time.Millisecond
	BootstrapPollCount    = 50
)

// Negotiate asks the KVM channel for the VMM code key and port. kvmKey is
// kvm.Session.KvmKey() (48 bytes) and compress is the JNLP `compress` parameter
// (Base.getCompress); both reports are AES-decrypted with kvmKey when compress
// is true.
//
// A zero timeout means 3s. The returned error is nil only when both reports
// arrived; Port is 0 when the port report did not (the caller may then fall back
// to DefaultPort, as VirtualMedia does with its hardcoded 8208).
func Negotiate(s *kvm.Session, kvmKey []byte, compress bool, timeout time.Duration) (*Bootstrap, error) {
	if timeout <= 0 {
		timeout = BootstrapPollInterval * BootstrapPollCount
	}
	codeKey, salt, err := RequestCodeKey(s, kvmKey, compress, timeout)
	if err != nil {
		return nil, err
	}
	b := &Bootstrap{CodeKey: codeKey, Salt: salt, Compress: compress}
	port, err := RequestPort(s, kvmKey, compress, timeout)
	if err != nil {
		return b, err
	}
	b.Port = port
	return b, nil
}

// RequestCodeKey is VirtualMedia.requestVMCodeKey + BladeThread's
// distributeNegotiVMMCodeKey.
func RequestCodeKey(s *kvm.Session, kvmKey []byte, compress bool, timeout time.Duration) (codeKey, salt []byte, err error) {
	body, err := requestReport(s, kvm.CmdReqVmmCodeKey, kvm.RspVmmCodeKey, "REQ_VMM_CODEKEY", timeout)
	if err != nil {
		return nil, nil, err
	}
	if compress {
		if len(kvmKey) < 48 {
			return nil, nil, fmt.Errorf("vmm: kvm_key must be 48 bytes to decrypt the code key report, got %d", len(kvmKey))
		}
		body, err = decryptKvmReport(body, kvmKey)
		if err != nil {
			return nil, nil, err
		}
	}
	// BladeThread requires at least code key + salt after decryption.
	if len(body) < 20+16 {
		return nil, nil, fmt.Errorf("vmm: code key report too short: %d bytes", len(body))
	}
	codeKey = append([]byte(nil), body[0:20]...)
	salt = append([]byte(nil), body[20:36]...)
	return codeKey, salt, nil
}

// RequestPort is VirtualMedia.requestVMPort + BladeThread.distributeVMMPort.
// The port is little-endian on the wire, unlike everything else in this
// protocol (VirtualMedia does `(strPort[1] << 8) | strPort[0]`).
func RequestPort(s *kvm.Session, kvmKey []byte, compress bool, timeout time.Duration) (int, error) {
	body, err := requestReport(s, kvm.CmdReqVmmPort, kvm.RspVmmPort, "REQ_VMM_PORT", timeout)
	if err != nil {
		return 0, err
	}
	if compress {
		if len(kvmKey) < 48 {
			return 0, fmt.Errorf("vmm: kvm_key must be 48 bytes to decrypt the port report, got %d", len(kvmKey))
		}
		body, err = decryptKvmReport(body, kvmKey)
		if err != nil {
			return 0, err
		}
	}
	if len(body) < 2 {
		return 0, fmt.Errorf("vmm: port report too short: %d bytes", len(body))
	}
	return int(body[1])<<8 | int(body[0]), nil
}

// requestReport sends one KVM request and waits for the matching report.
//
// The report payload layout is the same as every other KVM reply:
// `00 00 | cmd | blade | body...`, so the body starts at payload[4] (the Java's
// UnPackData strips `{cmd, blade}`, i.e. sourceData[2:] = UnPackData[2:]).
func requestReport(s *kvm.Session, cmd, want byte, label string, timeout time.Duration) ([]byte, error) {
	if s == nil {
		return nil, errors.New("vmm: nil KVM session")
	}
	reports := make(chan []byte, 4)
	notPri := make(chan struct{}, 1)

	prev := s.SetCommandHook(func(payload []byte) {
		if len(payload) < 5 {
			return
		}
		switch payload[2] {
		case want:
			body := append([]byte(nil), payload[4:]...)
			select {
			case reports <- body:
			default:
			}
		case kvm.RspNotPri:
			// distributeNoVMMPri: state 2 or 3 means another user holds the
			// blade, and the Java stops waiting for the recall.
			if payload[4] == 2 || payload[4] == 3 {
				select {
				case notPri <- struct{}{}:
				default:
				}
			}
		}
	})
	defer s.SetCommandHook(prev)

	s.Send(kvm.BuildFrame(s.CodeKey(), []byte{cmd, kvm.Blade}), label)

	// The Java polls every 60ms for at most 50 rounds.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case body := <-reports:
			return body, nil
		case <-notPri:
			return nil, errors.New("vmm: 虚拟介质已被其他用户占用")
		case <-time.After(BootstrapPollInterval):
		}
	}
	return nil, fmt.Errorf("vmm: %s 超时（%s）", label, timeout)
}

// decryptKvmReport is AESHandler.decry: AES-128-CBC with key kvm_key[0:16] and
// IV kvm_key[32:48], NoPadding (the caller knows the plaintext length).
func decryptKvmReport(body, kvmKey []byte) ([]byte, error) {
	if len(body) == 0 || len(body)%IVSize != 0 {
		return nil, fmt.Errorf("vmm: encrypted report length %d is not a multiple of 16", len(body))
	}
	return kvm.AESDecryptNoPad(body, kvmKey[0:16], kvmKey[32:48])
}

// ---------------------------------------------------------------------------
// Turning the bootstrap into session options
// ---------------------------------------------------------------------------

// Options builds Session options for a negotiated code key. host is the BMC
// address; st is the KVM session's Status, whose Algo/Iterations carry the
// PBKDF2 suite the VMM console must use (VirtualMedia calls
// setPbkdf2Params(kvmInterface.getHmac(), kvmInterface.getIterations())).
func (b *Bootstrap) Options(host string, st kvm.Status, noCompress bool) Options {
	return Options{
		Host:       host,
		Port:       b.Port,
		CodeKey:    b.CodeKey,
		Salt:       b.Salt,
		Iterations: st.Iterations,
		PRF:        PRFForAlgo(st.Algo),
		NoCompress: noCompress,
	}
}

// JNLPOptions builds Session options for the legacy path, where the KVM channel
// never negotiated a code key: the PBKDF2 password is the mmVerifyValue (a
// decimal string) truncated to 32 bits and written big-endian, the salt is 16
// zero bytes, and the PBKDF2 parameters are ConsoleControllers' defaults.
//
//	vmm_compress=1 (the default when the parameter is absent) means encrypted
//	data payloads, so NoCompress is set when the parameter is explicitly 0.
func JNLPOptions(host string, params map[string]string) (Options, error) {
	raw := params["mmVerifyValue"]
	if raw == "" {
		return Options{}, errors.New("vmm: JNLP 缺少 mmVerifyValue")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return Options{}, fmt.Errorf("vmm: mmVerifyValue %q 不是整数: %w", raw, err)
	}
	codeKey := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	return Options{
		Host:       host,
		Port:       DefaultPort,
		CodeKey:    codeKey,
		Salt:       make([]byte, IVSize),
		Iterations: DefaultIterations,
		PRF:        DefaultPRF,
		NoCompress: params["vmm_compress"] == "0",
	}, nil
}
