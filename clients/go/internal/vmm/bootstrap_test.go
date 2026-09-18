package vmm

// KVM-channel bootstrap tests: a fake KVM peer answers REQ_VMM_CODEKEY(0x31)
// and REQ_VMM_PORT(0x35) the way BladeThread distributes the two reports.
//
// Client -> BMC frames are `FE F6 | len u16be | codeKey i32be | crc16 | payload`
// and BMC -> client frames are `FE F6 00 | dlen u8 | payload` (see
// docs/protocol/01-transport-and-frames.md).

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/kvm"
)

// fakeKVM is a minimal KVM-channel peer that answers the two VMM requests.
type fakeKVM struct {
	t        *testing.T
	ln       net.Listener
	kvmKey   []byte
	codeKey  []byte
	salt     []byte
	port     []byte // wire order (little-endian)
	notPri   bool
	silent   bool
	requests chan byte
}

func newFakeKVM(t *testing.T, codeKey, salt, port []byte) *fakeKVM {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	k := &fakeKVM{
		t: t, ln: ln,
		kvmKey:  bytes.Repeat([]byte{0x5A}, 48),
		codeKey: codeKey, salt: salt, port: port,
		requests: make(chan byte, 8),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go k.serve()
	return k
}

func (k *fakeKVM) hostPort() (string, int) {
	host, portStr, _ := net.SplitHostPort(k.ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return host, p
}

// writeBMC sends one BMC frame.
func (k *fakeKVM) writeBMC(conn net.Conn, payload []byte) {
	k.t.Helper()
	frame := append([]byte{0xfe, 0xf6, 0x00, byte(len(payload))}, payload...)
	if _, err := conn.Write(frame); err != nil {
		k.t.Errorf("写 KVM 帧失败: %v", err)
	}
}

// readClient parses one client frame and returns its payload. Read failures
// (including the deadline when the test has already finished) return nil without
// failing the test: the fake peer only observes, the assertions live in the test
// body.
func (k *fakeKVM) readClient(conn net.Conn) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil
	}
	if hdr[0] != 0xfe || hdr[1] != 0xf6 {
		k.t.Errorf("魔数不对: % x", hdr[:2])
		return nil
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4])) - 2
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil
	}
	return payload
}

func (k *fakeKVM) serve() {
	conn, err := k.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 0; i < 2; i++ {
		payload := k.readClient(conn)
		if payload == nil {
			return
		}
		if len(payload) < 2 {
			return
		}
		k.requests <- payload[0]
		if k.silent {
			continue
		}
		switch payload[0] {
		case kvm.CmdReqVmmCodeKey:
			if k.notPri {
				k.writeBMC(conn, []byte{0x00, 0x00, kvm.RspNotPri, 0x00, 2})
				continue
			}
			plain := append(append([]byte(nil), k.codeKey...), k.salt...)
			k.writeBMC(conn, k.report(kvm.RspVmmCodeKey, plain))
		case kvm.CmdReqVmmPort:
			k.writeBMC(conn, k.report(kvm.RspVmmPort, k.port))
		}
	}
	_, _ = io.Copy(io.Discard, conn)
}

// report builds [00 00 cmd blade] + body, AES-encrypting (zero-padded) with
// kvm_key the way BladeThread's two report handlers decrypt it.
func (k *fakeKVM) report(cmd byte, body []byte) []byte {
	enc, err := kvm.AESEncryptNoPad(kvm.ZeroPad(body), k.kvmKey[0:16], k.kvmKey[32:48])
	if err != nil {
		k.t.Fatalf("加密上报失败: %v", err)
	}
	out := []byte{0x00, 0x00, cmd, 0x00}
	return append(out, enc...)
}

func dialKVM(t *testing.T, host string, port int) *kvm.Session {
	t.Helper()
	s := kvm.New(kvm.Options{Host: host, Port: port, Quiet: true})
	if err := s.Connect(); err != nil {
		t.Fatalf("KVM Connect: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestBootstrapNegotiateEncrypted(t *testing.T) {
	codeKey := []byte("0123456789abcdefghij")
	salt := bytes.Repeat([]byte{0x77}, 16)
	// 8208 = 0x2010, little-endian on the wire.
	k := newFakeKVM(t, codeKey, salt, []byte{0x10, 0x20})
	host, port := k.hostPort()

	ks := dialKVM(t, host, port)
	b, err := Negotiate(ks, k.kvmKey, true, 2*time.Second)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	assertBytes(t, "code key", b.CodeKey, codeKey)
	assertBytes(t, "vmm salt", b.Salt, salt)
	if b.Port != 8208 {
		t.Fatalf("端口应为 8208（小端解码），实际 %d", b.Port)
	}
	if !b.Compress {
		t.Fatal("Compress 应被记录")
	}
	if first := <-k.requests; first != kvm.CmdReqVmmCodeKey {
		t.Fatalf("第一个请求应为 0x31，实际 %#x", first)
	}
	if second := <-k.requests; second != kvm.CmdReqVmmPort {
		t.Fatalf("第二个请求应为 0x35，实际 %#x", second)
	}
}

func TestBootstrapNegotiatePlaintext(t *testing.T) {
	codeKey := bytes.Repeat([]byte{0xAB}, 20)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// compress == 0: the reports are not encrypted. A dedicated server writes
	// the raw bodies.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 2; i++ {
			hdr := make([]byte, 10)
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[2:4])) - 2
			payload := make([]byte, n)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			var body []byte
			var cmd byte
			switch payload[0] {
			case kvm.CmdReqVmmCodeKey:
				cmd = kvm.RspVmmCodeKey
				body = append(append([]byte(nil), codeKey...), salt...)
			case kvm.CmdReqVmmPort:
				cmd = kvm.RspVmmPort
				body = []byte{0x34, 0x12} // 0x1234 little-endian
			}
			out := append([]byte{0xfe, 0xf6, 0x00}, 0)
			report := append([]byte{0x00, 0x00, cmd, 0x00}, body...)
			out[3] = byte(len(report))
			out = append(out, report...)
			if _, err := conn.Write(out); err != nil {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ks := dialKVM(t, host, port)
	b, err := Negotiate(ks, nil, false, 2*time.Second)
	if err != nil {
		t.Fatalf("Negotiate(明文): %v", err)
	}
	assertBytes(t, "明文 code key", b.CodeKey, codeKey)
	assertBytes(t, "明文 salt", b.Salt, salt)
	if b.Port != 0x1234 {
		t.Fatalf("端口应为 0x1234，实际 %#x", b.Port)
	}
}

// NOT_PRI(0x51) with state 2 means another user holds the blade: the Java stops
// waiting (bVmmPri = false), so the request fails instead of timing out.
func TestBootstrapNotPrimary(t *testing.T) {
	k := newFakeKVM(t, bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 16), []byte{0x10, 0x20})
	k.notPri = true
	host, port := k.hostPort()

	ks := dialKVM(t, host, port)
	start := time.Now()
	_, _, err := RequestCodeKey(ks, k.kvmKey, true, 2*time.Second)
	if err == nil {
		t.Fatal("NOT_PRI 应导致失败")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("NOT_PRI 应立即返回，实际耗时 %s", elapsed)
	}
}

func TestBootstrapTimeout(t *testing.T) {
	k := newFakeKVM(t, bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 16), []byte{0x10, 0x20})
	k.silent = true
	host, port := k.hostPort()

	ks := dialKVM(t, host, port)
	if _, _, err := RequestCodeKey(ks, k.kvmKey, true, 150*time.Millisecond); err == nil {
		t.Fatal("无应答应超时")
	}
}

// The report body must decrypt to at least 36 bytes; a short one is an error
// rather than a panic (the Java's arraycopy would throw).
func TestBootstrapShortReport(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	kvmKey := bytes.Repeat([]byte{0x5A}, 48)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 10)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4])) - 2
		if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
			return
		}
		enc, _ := kvm.AESEncryptNoPad(kvm.ZeroPad([]byte{1, 2, 3, 4}), kvmKey[0:16], kvmKey[32:48])
		report := append([]byte{0x00, 0x00, kvm.RspVmmCodeKey, 0x00}, enc...)
		frame := append([]byte{0xfe, 0xf6, 0x00, byte(len(report))}, report...)
		_, _ = conn.Write(frame)
		time.Sleep(200 * time.Millisecond)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ks := dialKVM(t, host, port)
	if _, _, err := RequestCodeKey(ks, kvmKey, true, 300*time.Millisecond); err == nil {
		t.Fatal("过短的上报应报错")
	}
}

func TestBootstrapOptionsFromSuite(t *testing.T) {
	b := &Bootstrap{CodeKey: []byte("k"), Salt: []byte("s"), Port: 8208, Compress: true}
	opts := b.Options("1.2.3.4", kvm.Status{Algo: 3, Iterations: 10000}, true)
	if opts.Host != "1.2.3.4" || opts.Port != 8208 {
		t.Fatalf("Options 的主机/端口不对: %+v", opts)
	}
	if opts.PRF != PRFSHA256 || opts.Iterations != 10000 {
		t.Fatalf("套件参数应为 SHA256/10000，实际 %s/%d", opts.PRF, opts.Iterations)
	}
	if !opts.NoCompress {
		t.Fatal("NoCompress 应透传")
	}
	opts2 := b.Options("1.2.3.4", kvm.Status{Algo: 2, Iterations: 5000}, false)
	if opts2.PRF != PRFSHA1 || opts2.Iterations != 5000 || opts2.NoCompress {
		t.Fatalf("algo 2 应为 SHA1/5000 且加密: %+v", opts2)
	}
}

// The legacy path: no negotiation, so the code key is the 4-byte big-endian
// mmVerifyValue and the salt is all zeros.
func TestJNLPOptions(t *testing.T) {
	opts, err := JNLPOptions("10.0.0.1", map[string]string{
		"mmVerifyValue": "1000000001",
		"vmm_compress":  "0",
	})
	if err != nil {
		t.Fatalf("JNLPOptions: %v", err)
	}
	if opts.Port != DefaultPort {
		t.Fatalf("默认端口应为 %d，实际 %d", DefaultPort, opts.Port)
	}
	// 1000000001 = 0x3B9ACA01.
	if got := binary.BigEndian.Uint32(opts.CodeKey); got != 1000000001 {
		t.Fatalf("code key 应为 1000000001 的大端 4 字节，实际 %d", got)
	}
	if !opts.NoCompress {
		t.Fatal("vmm_compress=0 应关闭加密")
	}
	if opts.Iterations != DefaultIterations || opts.PRF != DefaultPRF {
		t.Fatalf("默认应为 5000/SHA1，实际 %d/%s", opts.Iterations, opts.PRF)
	}
	if !bytes.Equal(opts.Salt, make([]byte, IVSize)) {
		t.Fatal("未协商时 salt 应为 16 个 0")
	}

	// vmm_compress absent means 1 (encrypted), the vendor default.
	opts2, err := JNLPOptions("10.0.0.1", map[string]string{"mmVerifyValue": "1"})
	if err != nil {
		t.Fatalf("JNLPOptions: %v", err)
	}
	if opts2.NoCompress {
		t.Fatal("缺少 vmm_compress 时应默认加密")
	}
	if _, err := JNLPOptions("10.0.0.1", map[string]string{}); err == nil {
		t.Fatal("缺少 mmVerifyValue 应报错")
	}
}
