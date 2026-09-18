package vmm

// End-to-end session tests against a scripted TCP peer. No device is involved:
// the "BMC" is a goroutine that speaks the 12-byte frame protocol, checks the
// CERTIFY_ID layout and drives the SCSI exchange.

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fake peer
// ---------------------------------------------------------------------------

type vmmServer struct {
	t    *testing.T
	ln   net.Listener
	conn net.Conn
	mu   sync.Mutex
	seen [][]byte
}

func newVMMServer(t *testing.T) *vmmServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &vmmServer{t: t, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *vmmServer) hostPort() (string, int) {
	host, portStr, _ := net.SplitHostPort(s.ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return host, p
}

func (s *vmmServer) accept() net.Conn {
	s.t.Helper()
	conn, err := s.ln.Accept()
	if err != nil {
		s.t.Errorf("accept: %v", err)
		return nil
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	return conn
}

func (s *vmmServer) closeConn() {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// readFrame reads one whole client frame, skipping heartbeats (recording them).
func (s *vmmServer) readFrame(conn io.Reader) []byte {
	s.t.Helper()
	for {
		if c, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		hdr := make([]byte, HeaderSize)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			s.t.Errorf("读帧头失败: %v", err)
			return nil
		}
		h, _ := DecodeHeader(hdr)
		payload := make([]byte, h.Length)
		if h.Length > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				s.t.Errorf("读 payload 失败: %v", err)
				return nil
			}
		}
		frame := append(hdr, payload...)
		s.mu.Lock()
		s.seen = append(s.seen, frame)
		s.mu.Unlock()
		if h.Op == OpHeartbeat {
			continue
		}
		return frame
	}
}

func (s *vmmServer) writeFrame(conn io.Writer, frame []byte) {
	s.t.Helper()
	if _, err := conn.Write(frame); err != nil {
		s.t.Errorf("写帧失败: %v", err)
	}
}

func (s *vmmServer) assert(cond bool, format string, args ...any) {
	s.t.Helper()
	if !cond {
		s.t.Errorf(format, args...)
	}
}

func ackFrame(code int) []byte {
	f := make([]byte, HeaderSize)
	f[2] = byte(code)
	return f
}

// cdbFrame wraps a 12-byte CDB in an OpUFIData/OpSFFData frame (low nibble 0).
func cdbFrame(op byte, state byte, id byte, cdb []byte) []byte {
	f := make([]byte, HeaderSize+len(cdb))
	f[0] = op
	f[1] = state<<4 | SubCommand
	f[3] = id
	binary.BigEndian.PutUint32(f[4:8], uint32(len(cdb)))
	copy(f[HeaderSize:], cdb)
	return f
}

func requestFrames(frames [][]byte, op byte) [][]byte {
	var out [][]byte
	for _, f := range frames {
		if f[0] == op {
			out = append(out, f)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %s 超时", what)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// The full happy path: CERTIFY_ID (41 bytes, session id from the key material),
// ACK(0), DEVICE_TYPE(2), ACK(16), then an INQUIRY answered with the fixed
// 36-byte payload and a success completion.
func TestSessionHandshakeAndInquiry(t *testing.T) {
	codeKey := []byte("0123456789abcdefghij")
	salt := []byte("0123456789abcdef")
	mat, err := DeriveKeyMaterial(codeKey, salt, 5000, PRFSHA1)
	if err != nil {
		t.Fatalf("DeriveKeyMaterial: %v", err)
	}
	iso := writePatternImage(t, "session.iso", 8, blockLength)

	srv := newVMMServer(t)
	host, port := srv.hostPort()
	done := make(chan struct{})
	inquiryDone := make(chan struct{})
	go func() {
		defer close(done)
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()

		certify := srv.readFrame(conn)
		if certify == nil {
			return
		}
		srv.assert(len(certify) == 41, "CERTIFY_ID 应为 41 字节，实际 %d", len(certify))
		srv.assert(certify[0] == OpCertifyID, "CERTIFY_ID op 应为 1，实际 %d", certify[0])
		srv.assert(binary.BigEndian.Uint32(certify[4:8]) == 29, "长度字段应为 29")
		srv.assert(bytes.Equal(certify[8:12], []byte{3, 1, 1, 1}), "版本应为 03 01 01 01，实际 % x", certify[8:12])
		srv.assert(bytes.Equal(certify[12:36], mat.SessionID), "payload 前 24 字节应为派生 session id")
		srv.assert(certify[36] == 0, "IPv4 类型字节应为 0")
		srv.assert(bytes.Equal(certify[37:41], []byte{127, 0, 0, 1}), "IP 应为 127.0.0.1，实际 % x", certify[37:41])

		srv.writeFrame(conn, ackFrame(AckCertifyPass))

		dev := srv.readFrame(conn)
		if dev == nil {
			return
		}
		srv.assert(dev[0] == OpDeviceType && dev[1] == DeviceCDROM, "DEVICE_TYPE 应为光驱，实际 % x", dev[:2])
		srv.writeFrame(conn, ackFrame(AckDeviceCreat))

		srv.writeFrame(conn, cdbFrame(OpSFFData, SubEnd, 0x42, cdbInquiry()))
		// Collect until the SFF completion, then wait for the client's CLOSE_VM.
		sawCompletion := false
		for {
			f := srv.readFrame(conn)
			if f == nil {
				return
			}
			if f[0] == OpSFFComplete && !sawCompletion {
				sawCompletion = true
				srv.assert(f[1] == CmdOK, "INQUIRY 完成帧应成功，实际 %d", f[1])
				srv.assert(f[3] == 0x42, "完成帧的 ID 应为 0x42，实际 %#x", f[3])
				close(inquiryDone)
				continue
			}
			if f[0] == OpCloseVM {
				// The client-side builder writes the device type in the low bits.
				srv.assert(f[1] == CloseTypeLink, "关闭全部时低 2 位应为 0，实际 %#x", f[1])
				return
			}
		}
	}()

	s := New(Options{
		Host: host, Port: port,
		CodeKey: codeKey, Salt: salt,
		Iterations: 5000, PRF: PRFSHA1,
		Quiet:        true,
		TickInterval: 200 * time.Millisecond, // 40 ticks = 8s: no watchdog in the way
	})
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	waitFor(t, "ACTIVE", func() bool { return s.State() == StateActive })

	select {
	case <-inquiryDone:
	case <-time.After(3 * time.Second):
		t.Fatal("INQUIRY 交换超时")
	}

	// The client's own frames: the INQUIRY answer is 12 + 36 bytes.
	srv.mu.Lock()
	seen := append([][]byte(nil), srv.seen...)
	srv.mu.Unlock()
	data := requestFrames(seen, OpSFFData)
	if len(data) != 1 {
		t.Fatalf("应有 1 个数据帧，实际 %d", len(data))
	}
	// vmm_compress defaults to 1: the payload is `4-byte plaintext length ||
	// AES-CBC(zero-padded)`, so the frame is 12 + 4 + 48 bytes.
	if len(data[0]) != HeaderSize+4+48 {
		t.Fatalf("加密数据帧应为 64 字节，实际 %d", len(data[0]))
	}
	if data[0][1] != 0x31 {
		t.Fatalf("数据帧应为 state=END/data=1，实际 %#x", data[0][1])
	}
	if got := binary.BigEndian.Uint32(data[0][4:8]); got != 4+48 {
		t.Fatalf("头部长度字段应为 52（密文+4），实际 %d", got)
	}
	if got := binary.BigEndian.Uint32(data[0][12:16]); got != 36 {
		t.Fatalf("明文长度前缀应为 36，实际 %d", got)
	}
	plain, err := UnwrapPayload(data[0][HeaderSize:], mat.SecretKey, mat.SecretIV)
	if err != nil {
		t.Fatalf("解密数据帧: %v", err)
	}
	if !bytes.Equal(plain, hexDecodeString(cdromInquiryHex)) {
		t.Fatalf("解密后的 INQUIRY 不对: % x", plain)
	}
	if !bytes.Contains(seen[0], []byte{OpCertifyID}) {
		t.Fatal("第一帧应为 CERTIFY_ID")
	}

	// Closing the session sends CLOSE_VM and tears the link down.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitFor(t, "IDLE", func() bool { return s.State() == StateIdle })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("假 BMC 脚本超时（未收到 CLOSE_VM）")
	}
	srv.mu.Lock()
	seen = append([][]byte(nil), srv.seen...)
	srv.mu.Unlock()
	closeFrames := requestFrames(seen, OpCloseVM)
	if len(closeFrames) != 1 {
		t.Fatalf("ACTIVE 且无错误时应发送 1 个 CLOSE_VM，实际 %d", len(closeFrames))
	}
	if closeFrames[0][1] != CloseTypeLink {
		t.Fatalf("CLOSE_VM 的设备类型应写在低 2 位（0 = 全部），实际 %#x", closeFrames[0][1])
	}
}

// CN_EXIST(49) to CERTIFY_ID means another user holds the media: error 401 and a
// full teardown.
func TestSessionDeviceInUse(t *testing.T) {
	iso := writePatternImage(t, "busy.iso", 8, blockLength)
	srv := newVMMServer(t)
	host, port := srv.hostPort()

	gotErr := make(chan error, 4)
	closed := make(chan struct{})
	go func() {
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(CnExist))
		// The client tears the link down and closes the socket.
		_, _ = io.Copy(io.Discard, conn)
	}()

	s := New(Options{
		Host: host, Port: port,
		CodeKey: []byte("0123456789abcdefghij"),
		Salt:    make([]byte, IVSize),
		Quiet:   true,
		OnError: func(err error) {
			select {
			case gotErr <- err:
			default:
			}
		},
		OnClosed: func() { close(closed) },
	})
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}

	select {
	case err := <-gotErr:
		if errCodeOf(err) != ErrDeviceInUse {
			t.Fatalf("错误码应为 401，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("没有收到 401 错误")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("未关闭连接")
	}
	waitFor(t, "IDLE", func() bool { return s.State() == StateIdle })
	if got := s.Status().CDROMErr; got != ErrDeviceInUse {
		t.Fatalf("光驱错误码应记录为 401，实际 %d", got)
	}
}

// The 40s "no traffic either direction" rule, with the tick shortened: the
// client's own heartbeats must not stop the counter.
func TestSessionNoTrafficDrop(t *testing.T) {
	iso := writePatternImage(t, "quiet.iso", 8, blockLength)
	srv := newVMMServer(t)
	host, port := srv.hostPort()
	heartbeats := make(chan byte, 1)
	go func() {
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckCertifyPass))
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckDeviceCreat))
		// Then stay silent and watch the client's heartbeat arrive.
		hdr := make([]byte, HeaderSize)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, hdr); err == nil && hdr[0] == OpHeartbeat {
			select {
			case heartbeats <- hdr[0]:
			default:
			}
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	gotErr := make(chan error, 4)
	s := New(Options{
		Host: host, Port: port,
		CodeKey:      []byte("0123456789abcdefghij"),
		Quiet:        true,
		TickInterval: 10 * time.Millisecond, // 40 ticks = 400ms
		OnError: func(err error) {
			select {
			case gotErr <- err:
			default:
			}
		},
	})
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	waitFor(t, "ACTIVE", func() bool { return s.State() == StateActive })

	select {
	case hb := <-heartbeats:
		if hb != OpHeartbeat {
			t.Fatalf("客户端应发送心跳帧，实际 %#x", hb)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("没有收到客户端心跳")
	}

	select {
	case err := <-gotErr:
		if errCodeOf(err) != ErrNoTraffic {
			t.Fatalf("错误码应为 123，实际 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("40 个 tick 后仍未断开")
	}
	waitFor(t, "IDLE", func() bool { return s.State() == StateIdle })
}

// No ACK(0) within the certify watchdog -> error 121 and teardown.
func TestSessionCertifyTimeout(t *testing.T) {
	iso := writePatternImage(t, "slow.iso", 8, blockLength)
	srv := newVMMServer(t)
	host, port := srv.hostPort()
	go func() {
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		if srv.readFrame(conn) == nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn) // never answer
	}()

	gotErr := make(chan error, 4)
	s := New(Options{
		Host: host, Port: port,
		CodeKey: []byte("0123456789abcdefghij"),
		Quiet:   true,
		OnError: func(err error) {
			select {
			case gotErr <- err:
			default:
			}
		},
	})
	s.certifyTimeout = 50 * time.Millisecond
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	select {
	case err := <-gotErr:
		if errCodeOf(err) != ErrCertifyTime {
			t.Fatalf("错误码应为 121，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("认证看门狗未触发")
	}
	waitFor(t, "IDLE", func() bool { return s.State() == StateIdle })
}

// A second device mounted while the link is ACTIVE is registered with its own
// DEVICE_TYPE on the same socket, and UFI traffic then flows.
func TestSessionSecondDeviceOnSameSocket(t *testing.T) {
	iso := writePatternImage(t, "both.iso", 8, blockLength)
	img := writePatternImage(t, "both.img", floppyTotalBlocks, floppyBlockLength)
	srv := newVMMServer(t)
	host, port := srv.hostPort()
	floppyInquirySeen := make(chan []byte, 1)
	detachedSeen := make(chan byte, 1)

	go func() {
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckCertifyPass))
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckDeviceCreat))

		// Second device: the floppy announces itself on the live socket.
		dev := srv.readFrame(conn)
		if dev == nil {
			return
		}
		srv.assert(dev[0] == OpDeviceType && dev[1] == DeviceFloppy, "第二个 DEVICE_TYPE 应为软驱，实际 % x", dev[:2])
		srv.writeFrame(conn, ackFrame(AckDeviceCreat))

		srv.writeFrame(conn, cdbFrame(OpUFIData, SubEnd, 0x0C, cdbInquiry()))
		detached := detachedSeen
		for {
			f := srv.readFrame(conn)
			if f == nil {
				return
			}
			if f[0] == OpUFIComplete {
				srv.assert(f[1] == CmdOK, "软驱 INQUIRY 应成功，实际 %d", f[1])
				continue
			}
			if f[0] == OpUFIData {
				select {
				case floppyInquirySeen <- append([]byte(nil), f[HeaderSize:]...):
				default:
				}
				continue
			}
			if f[0] == OpCloseVM {
				select {
				case detached <- f[1]:
				default:
				}
				return
			}
		}
	}()

	s := New(Options{
		Host: host, Port: port,
		CodeKey:      []byte("0123456789abcdefghij"),
		Quiet:        true,
		NoCompress:   true, // the frames are compared in the clear here
		TickInterval: 50 * time.Millisecond,
	})
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	waitFor(t, "ACTIVE", func() bool { return s.State() == StateActive })

	if err := s.MountFloppy(img, true); err != nil {
		t.Fatalf("MountFloppy: %v", err)
	}
	waitFor(t, "软驱 ACTIVE", func() bool { return s.Status().FloppyState == StateActive })

	select {
	case body := <-floppyInquirySeen:
		want := hexDecodeString(floppyInquiryHex)
		if !bytes.Equal(body, want) {
			t.Fatalf("软驱 INQUIRY 应为固定 36 字节\n got % x\nwant % x", body, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("没有收到软驱 INQUIRY 应答")
	}

	// Detaching the floppy keeps the socket and sends CLOSE_VM(1) in the low
	// bits (the client-side encoding).
	if err := s.Detach(DeviceFloppy); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	select {
	case b := <-detachedSeen:
		if b != CloseTypeFloppy {
			t.Fatalf("卸载软驱应发送 CLOSE_VM(低 2 位 = 1)，实际 %#x", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没有收到卸载软驱的 CLOSE_VM")
	}
	if s.State() != StateActive {
		t.Fatalf("卸载单个设备后应保持 ACTIVE，实际 %s", s.State())
	}
	if s.Status().FloppyState != StateIdle {
		t.Fatalf("软驱链路状态应为 idle，实际 %s", s.Status().FloppyState)
	}
}

// An inbound CLOSE_VM carries its reason in byte 2 and the device type in the
// high nibble; errorProcess routes that reason. A reason of 0 matches no case
// and is silently ignored (the Java behaves the same), so the test uses 101.
func TestSessionInboundCloseVM(t *testing.T) {
	iso := writePatternImage(t, "close.iso", 8, blockLength)
	srv := newVMMServer(t)
	host, port := srv.hostPort()
	go func() {
		conn := srv.accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckCertifyPass))
		if srv.readFrame(conn) == nil {
			return
		}
		srv.writeFrame(conn, ackFrame(AckDeviceCreat))
		// CLOSE_VM with the device type in the HIGH nibble, reason 101.
		shutdown := make([]byte, HeaderSize)
		shutdown[0] = OpCloseVM
		shutdown[1] = byte(CloseTypeLink) << 4
		shutdown[2] = 101
		srv.writeFrame(conn, shutdown)
		_, _ = io.Copy(io.Discard, conn)
	}()

	// A slow tick so the 40-tick no-traffic rule cannot be what closes the link.
	s := New(Options{
		Host: host, Port: port,
		CodeKey:      []byte("0123456789abcdefghij"),
		Quiet:        true,
		TickInterval: 200 * time.Millisecond,
	})
	if err := s.MountISO(iso); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	waitFor(t, "IDLE", func() bool { return s.State() == StateIdle })
	if s.Status().CDROMState != StateIdle {
		t.Fatalf("设备链路状态应回到 idle，实际 %s", s.Status().CDROMState)
	}
	if got := s.ErrCode(0); got != 101 {
		t.Fatalf("应记录原因 101，实际 %d", got)
	}
}

// Without a code key the session refuses to do anything.
func TestSessionRequiresCodeKey(t *testing.T) {
	s := New(Options{Host: "127.0.0.1", Port: 1})
	if err := s.MountISO("/tmp/nope.iso"); err == nil {
		t.Fatal("缺少 CodeKey 应报错")
	}
}
