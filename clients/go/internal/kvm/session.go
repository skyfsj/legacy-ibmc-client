// KVM session: raw TCP to the BMC's console port, handshake, frame
// reassembly, and input injection. Mirrors the vendor client's
// BladeThread / DrawThread logic (src/main/session.js).
//
// Validated against a real iBMC (see huawei-ibmc-kvm-protocol/07-live-verification.md).
package kvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Blade is the blade number used for single-blade machines (JS `BLADE`).
	Blade = 0
	// SubpacketChunk is the vendor client's hardcoded 220-byte sub-packet cap;
	// it is used when sizing the reassembly buffer.
	SubpacketChunk = 220
	// DefaultPort is the KVM console TCP port when the JNLP does not carry one.
	DefaultPort = 2198
	// DefaultColorBit is the 8-bit colour mode the vendor client sends.
	DefaultColorBit = 2

	heartbeatInterval = 5 * time.Second
	dialTimeout       = 20 * time.Second
)

// Frame is one reassembled IMAGE_DATA frame, delivered through Session.OnFrame.
//
// For a "no change" marker (the BMC sends header-only sub-packets with
// packLenght == 0) NoChange is true and Stream is nil; the other fields still
// carry what the header said.
type Frame struct {
	NoChange bool
	FrameNo  int
	Width    int
	Height   int
	BlockX   int // ceil(width/64)  — 64x64 block grid
	BlockY   int // ceil(height/64)
	Diff     int // 1 = differential frame (XOR against the previous frame)
	DQT      int // quantization table index from the frame header
	IFrame   int // 1 = the header's I-frame flag is set
	Stream   []byte
}

// Status is a snapshot of the session's protocol state. It is safe to read
// from any goroutine (unlike the raw fields, which the read loop mutates).
type Status struct {
	Connected      bool
	Authenticated  bool
	Width          int
	Height         int
	BlockX         int
	BlockY         int
	Dqt            int
	DqtSeen        bool
	MouseMode      int
	MouseModeSeen  bool
	FrameNo        int
	FramesReceived int
	Algo           int
	Iterations     int
	HasKvmKey      bool
	HasReconnKey   bool
	HdrDqt         int
	HdrDqtSeen     bool
}

// Options configures a Session.
type Options struct {
	Host string
	Port int
	// Params are the JNLP parameters (see ibmc.ParseJnlpParams); the session
	// reads verifyValue, verifyValueExt and decrykey.
	Params map[string]string
	// ColorBit defaults to 2 (8 bit) when zero.
	ColorBit int
	// Quiet suppresses the Log hook (the JS default is verbose).
	Quiet bool
	// Log receives human-readable progress messages (may be nil). It is copied
	// into Session.Log, so setting it here is equivalent.
	Log func(string)
}

// Session is one KVM connection to the BMC.
//
// Every hook below is optional and is called from the session's read goroutine
// (or from a timer goroutine); set them before Connect and do not mutate them
// afterwards. Hooks must not block for long: they run on the read path.
type Session struct {
	Host     string
	Port     int
	ColorBit int
	Quiet    bool

	// Log receives human-readable progress messages (the UI log pane).
	Log func(string)
	// OnError receives socket errors. It is not called for an orderly Close.
	OnError func(error)
	// OnConnected fires once the TCP connection is up.
	OnConnected func()
	// OnClosed fires when the connection is gone (remote close, error or Close).
	OnClosed func()
	// OnAuthenticated fires when the 48-byte kvm_key has been derived.
	OnAuthenticated func()
	// OnConnectState carries the CONNECT_STATE(0x08) value (0 = success).
	OnConnectState func(state int)
	// OnMouseMode carries the MOUSE_MODE(0x25) value (1 = absolute/synchronised).
	OnMouseMode func(mode int)
	// OnDqt carries the DQT_MODE(0x28) quality value the BMC reports (e.g. 70).
	OnDqt func(quality int)
	// OnHdrDqt carries the quantization table index (0..9) from a frame header
	// whenever it changes — the frame header is authoritative for decoding.
	OnHdrDqt func(index int)
	// OnKeyState carries the KEY_STATE(0x04) lock-light bitmap.
	OnKeyState func(state int)
	// OnNotPri carries the NOT_PRI(0x51) value.
	OnNotPri func(value int)
	// OnFrame delivers a reassembled video frame.
	OnFrame func(f Frame)
	// OnSent observes every frame the session emits toward the BMC (label is
	// empty when the JS reference sends without one). It is called even when no
	// socket is connected; used by tests and by a future traffic tracer.
	OnSent func(frame []byte, label string)

	hookMu      sync.Mutex
	commandHook func([]byte)

	params map[string]string
	defry  []byte // decrykey as bytes: [0:16] user_key, [16:32] user_iv

	mu             sync.Mutex
	conn           net.Conn
	closedCh       chan struct{}
	closeOnce      sync.Once
	parser         *ServerFrameParser
	codeKey        int32
	encodeKey      []byte
	kvmKey         []byte
	reconnKey      []byte
	algo           int
	iterations     int
	connected      bool
	authenticated  bool
	width          int
	height         int
	blockX         int
	blockY         int
	dqt            int
	dqtSeen        bool
	hdrDqt         int
	hdrDqtSeen     bool
	mouseMode      int
	mouseModeSeen  bool
	mouseModeForce bool
	frameNo        int
	framesReceived int
	pending        *pendingFrame
	heartbeat      *time.Ticker
	timers         []*time.Timer
	lastMouse      [2]int
	lastButtons    int
	haveLastMouse  bool
}

// pendingFrame is the frame currently being reassembled.
type pendingFrame struct {
	frameNo int
	total   int
	diff    int
	dqt     int
	iframe  int
	slots   [][]byte
	sum     int
	got     int
}

// New creates a session from the given options. It does not touch the network.
func New(opts Options) *Session {
	colorBit := opts.ColorBit
	if colorBit == 0 {
		colorBit = DefaultColorBit
	}
	port := opts.Port
	if port == 0 {
		port = DefaultPort
	}
	params := opts.Params
	if params == nil {
		params = map[string]string{}
	}
	return &Session{
		Host:       opts.Host,
		Port:       port,
		ColorBit:   colorBit,
		Quiet:      opts.Quiet,
		Log:        opts.Log,
		params:     params,
		defry:      hexDecode(params["decrykey"]),
		parser:     NewServerFrameParser(),
		closedCh:   make(chan struct{}),
		codeKey:    jsParseInt32(params["verifyValue"]),
		algo:       3,
		iterations: 10000,
		dqt:        6, // table index; firmware default is 70 (= index 6)
	}
}

// Closed reports whether the session has been torn down (Close was called or the
// connection ended).
func (s *Session) Closed() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

// markClosed is idempotent; it releases every timer waiter.
func (s *Session) markClosed() {
	s.closeOnce.Do(func() { close(s.closedCh) })
}

// JnlpParams returns the JNLP parameters the session was built with.
func (s *Session) JnlpParams() map[string]string {
	out := make(map[string]string, len(s.params))
	for k, v := range s.params {
		out[k] = v
	}
	return out
}

// param returns one JNLP parameter.
func (s *Session) param(name string) string { return s.params[name] }

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Connect dials the BMC and starts the reader. StartHandshake must be called
// afterwards (the JS client does the same).
func (s *Session) Connect() error {
	s.mu.Lock()
	if s.conn != nil {
		s.mu.Unlock()
		return errors.New("kvm: session is already connected")
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	s.mu.Lock()
	s.conn = conn
	s.connected = true
	s.mu.Unlock()

	if s.OnConnected != nil {
		s.OnConnected()
	}
	go s.readLoop(conn)
	return nil
}

// Send writes one frame. It reports whether the frame actually went out; OnSent
// is called either way.
func (s *Session) Send(frame []byte, label string) bool { return s.send(frame, label) }

func (s *Session) send(frame []byte, label string) bool {
	if s.OnSent != nil {
		s.OnSent(frame, label)
	}
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return false
	}
	// One write per frame: the BMC does not reassemble frames split across reads.
	if _, err := conn.Write(frame); err != nil {
		s.reportErr(err)
		return false
	}
	if label != "" {
		s.logf("tx %s (%dB)", label, len(frame))
	}
	return true
}

// StartHandshake sends HEART_BEAT and GET_SUITE and starts the 5s heartbeat.
func (s *Session) StartHandshake() {
	s.send(BuildFrame(s.codeKey, []byte{CmdHeartBeat, 0x00}), "HEARTBEAT")
	s.send(BuildFrame(s.codeKey, []byte{CmdGetSuite, Blade}), "GET_SUITE")

	s.mu.Lock()
	if s.heartbeat == nil {
		t := time.NewTicker(heartbeatInterval)
		s.heartbeat = t
		s.mu.Unlock()
		go func() {
			for {
				select {
				case <-s.closedCh:
					return
				case <-t.C:
					s.send(BuildFrame(s.codeKey, []byte{CmdHeartBeat, 0x00}), "")
				}
			}
		}()
		return
	}
	s.mu.Unlock()
}

// FinishHandshake sends the CONNECT_BLADE proof and the follow-up commands.
func (s *Session) FinishHandshake() {
	// connectBlade with the 0x8000 "encrypted frame" variant carrying the 24-byte key proof
	s.mu.Lock()
	encodeKey := s.encodeKey
	s.mu.Unlock()

	payload := ConnectBladePayload(Blade, s.ColorBit)
	s.send(BuildEncryptedFrame(encodeKey, payload, 0x8000|len(payload)), "CONNECT_BLADE")

	// Ask the BMC to pick the mouse mode (the vendor client sends mode 2 here, then
	// reads the effective mode back from the 0x25 reply).
	s.after(200*time.Millisecond, func() {
		s.send(BuildFrame(s.codeKey, []byte{CmdMouseModeSet, 0x00, 0x02, 0x00, 0x00}), "MOUSE_MODE_SET(2)")
	})
	s.after(400*time.Millisecond, func() {
		s.send(BuildFrame(s.codeKey, []byte{CmdFrameComm, 35}), "FRAME_COMM(35)")
	})
	// NOTE: deliberately NOT pushing a quality value on connect. The mapping from the
	// 0x27 quality number to the quantization table is only verified for the
	// firmware's own default (70 -> table index 6). Forcing any other value risked
	// decoding with a table finer than the encoder's, which dims the image.
}

// Close tears the connection down and stops every timer.
func (s *Session) Close() {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.connected = false
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	timers := s.timers
	s.timers = nil
	s.mu.Unlock()

	s.markClosed()
	for _, t := range timers {
		t.Stop()
	}
	if conn != nil {
		_ = conn.Close() // the read loop reports OnClosed
	}
}

func (s *Session) readLoop(conn net.Conn) {
	buf := make([]byte, 4096) // the vendor client reads at most 4096 bytes per read
	var readErr error
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			for _, payload := range s.parser.Push(buf[:n]) {
				s.dispatch(payload)
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}

	s.mu.Lock()
	wasConnected := s.connected
	s.connected = false
	s.conn = nil
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	timers := s.timers
	s.timers = nil
	s.mu.Unlock()

	s.markClosed()
	for _, t := range timers {
		t.Stop()
	}
	// A remote FIN (EOF) or our own Close is not an error worth reporting; the JS
	// socket only emitted 'error' for real failures.
	if readErr != nil && wasConnected && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
		s.reportErr(readErr)
	}
	if s.OnClosed != nil {
		s.OnClosed()
	}
}

// dispatch runs one frame through the state machine, containing panics the same
// way the JS reference's try/catch around onFrame did.
func (s *Session) dispatch(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			s.reportErr(fmt.Errorf("kvm: frame handler panic: %v", r))
		}
	}()
	if h := s.getCommandHook(); h != nil {
		// A copy: the caller must not be able to corrupt the parser's buffer.
		h(bytes.Clone(payload))
	}
	s.onFrame(payload)
}

// SetCommandHook installs (or replaces) a hook that receives a copy of every
// inbound frame payload — the bytes after the KVM frame header, so payload[2] is
// the command byte. It returns the previous hook, which callers may chain. The
// hook runs on the read goroutine and must not block.
//
// Unlike the other callbacks this one may be installed while the session is
// running; that is what the VMM bootstrap needs, since it asks on an already
// connected KVM channel and waits for the reply (see internal/vmm/bootstrap.go).
func (s *Session) SetCommandHook(fn func([]byte)) func([]byte) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	prev := s.commandHook
	s.commandHook = fn
	return prev
}

func (s *Session) getCommandHook() func([]byte) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	return s.commandHook
}

// after runs fn later unless the session has been torn down first. Note that it
// still runs when no socket is connected (the JS setTimeout behaves the same
// way); the send inside simply reports a frame that cannot be written.
func (s *Session) after(d time.Duration, fn func()) {
	t := time.AfterFunc(d, func() {
		select {
		case <-s.closedCh:
			return
		default:
		}
		fn()
	})
	s.mu.Lock()
	s.timers = append(s.timers, t)
	s.mu.Unlock()
}

func (s *Session) logf(format string, args ...any) {
	if s.Quiet || s.Log == nil {
		return
	}
	s.Log(fmt.Sprintf(format, args...))
}

func (s *Session) reportErr(err error) {
	if err == nil || s.OnError == nil {
		return
	}
	s.OnError(err)
}

// Status returns a consistent snapshot of the session state.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		Connected:      s.connected,
		Authenticated:  s.authenticated,
		Width:          s.width,
		Height:         s.height,
		BlockX:         s.blockX,
		BlockY:         s.blockY,
		Dqt:            s.dqt,
		DqtSeen:        s.dqtSeen,
		MouseMode:      s.mouseMode,
		MouseModeSeen:  s.mouseModeSeen,
		FrameNo:        s.frameNo,
		FramesReceived: s.framesReceived,
		Algo:           s.algo,
		Iterations:     s.iterations,
		HasKvmKey:      s.kvmKey != nil,
		HasReconnKey:   s.reconnKey != nil,
		HdrDqt:         s.hdrDqt,
		HdrDqtSeen:     s.hdrDqtSeen,
	}
}

// KvmKey returns a copy of the 48-byte session key, or nil before it arrives.
func (s *Session) KvmKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.kvmKey)
}

// EncodeKey returns a copy of the 24-byte CONNECT_BLADE proof, or nil.
func (s *Session) EncodeKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.encodeKey)
}

// CodeKey returns the codeKey taken from the JNLP verifyValue.
func (s *Session) CodeKey() int32 { return s.codeKey }

// ---------------------------------------------------------------------------
// Frame dispatch
// ---------------------------------------------------------------------------

func (s *Session) onFrame(p []byte) {
	if len(p) < 3 {
		return
	}
	switch p[2] {
	case RspKvmSuiteList:
		s.onSuiteList(p)
	case RspKvmKeySet:
		s.onKeySet(p)
	case RspConnectState:
		if len(p) < 5 {
			return
		}
		state := int(p[4])
		s.logf("rx 连接状态 = %d", state)
		if s.OnConnectState != nil {
			s.OnConnectState(state)
		}
	case RspMouseMode:
		s.onMouseMode(p)
	case RspDqtMode:
		if len(p) < 5 {
			return
		}
		v := int(p[4])
		// JS: Math.max(0, Math.min(9, v / 10 - 1)). Real values are multiples of
		// ten, so the index is an exact integer in practice.
		idx := int(math.Max(0, math.Min(9, float64(v)/10-1)))
		s.mu.Lock()
		s.dqt = idx
		s.dqtSeen = true
		s.mu.Unlock()
		s.logf("rx DQT 档 = %d（索引 %d）", v, idx)
		if s.OnDqt != nil {
			s.OnDqt(v)
		}
	case RspImageData:
		s.onImage(p)
	case RspKeyState:
		if len(p) < 5 {
			return
		}
		if s.OnKeyState != nil {
			s.OnKeyState(int(p[4]))
		}
	case RspNotPri:
		if len(p) < 5 {
			return
		}
		if s.OnNotPri != nil {
			s.OnNotPri(int(p[4]))
		}
	default:
		s.logf("rx cmd=0x%x dlen=%d", p[2], len(p))
	}
}

func (s *Session) onSuiteList(p []byte) {
	sl := ParseSuiteList(p)
	okText := "失败"
	if sl.LengthOK {
		okText = "OK"
	}
	s.logf("rx 套件表 count=%d 长度自校验=%s", sl.Count, okText)
	for _, su := range sl.Suites {
		s.logf("   algo=%d iterations=%d", su.Algo, su.Iterations)
	}

	// Prefer SHA-256 (algo 3), else SHA-1 (algo 2); fall back to 5000/SHA-1.
	chosen := Suite{Algo: 1, Iterations: 5000}
	if su, found := sl.Find(3); found {
		chosen = su
	} else if su, found := sl.Find(2); found {
		chosen = su
	}

	s.mu.Lock()
	s.algo = chosen.Algo
	s.iterations = int(chosen.Iterations)
	encodeKey, err := DeriveEncodeKey(s.param("verifyValueExt"), sub(s.defry, 16, 32), s.iterations, s.algo)
	if err == nil {
		s.encodeKey = encodeKey
	}
	s.mu.Unlock()
	if err != nil {
		s.logf("encodeKey 派生失败: %v", err)
		return
	}
	s.logf("选中 algo=%d iterations=%d", chosen.Algo, chosen.Iterations)

	it := uint32(chosen.Iterations)
	s.send(BuildFrame(s.codeKey, []byte{
		CmdSetSuite, Blade, byte(chosen.Algo),
		byte(it >> 24), byte(it >> 16), byte(it >> 8), byte(it),
	}), "SET_SUITE")
	s.FinishHandshake()
}

func (s *Session) onKeySet(p []byte) {
	if len(p) < 4 {
		return
	}
	dataLen := len(p) - 4 // payload after [00 00 40 blade]
	s.mu.Lock()
	userKey := sub(s.defry, 0, 16)
	userIV := sub(s.defry, 16, 32)
	iterations, algo := s.iterations, s.algo
	s.mu.Unlock()

	pt, err := AESDecryptNoPad(sub(p, 4, len(p)), userKey, userIV)
	if err != nil {
		s.logf("KVM_KEY_SET 解密失败: %v", err)
		return
	}
	switch dataLen {
	case 48:
		key, err := DeriveKvmKey(pt, iterations, algo)
		if err != nil {
			s.logf("kvm_key 派生失败: %v", err)
			return
		}
		s.mu.Lock()
		s.kvmKey = key
		s.authenticated = true
		s.mu.Unlock()
		s.logf("拿到 kvm_key (48B)，数据密钥 %x…", key[0:8])
		if s.OnAuthenticated != nil {
			s.OnAuthenticated()
		}
	case 128:
		s.mu.Lock()
		s.reconnKey = pt
		s.mu.Unlock()
		s.logf("拿到 128B 重连密钥")
	}
}

func (s *Session) onMouseMode(p []byte) {
	if len(p) < 5 {
		return
	}
	mode := int(p[4])
	s.mu.Lock()
	s.mouseMode = mode
	s.mouseModeSeen = true
	force := mode != 1 && !s.mouseModeForce
	if force {
		s.mouseModeForce = true
	}
	s.mu.Unlock()

	label := "相对"
	if mode == 1 {
		label = "绝对/同步"
	}
	// 1 = absolute/synchronised, 0 = relative. Absolute is what the GUI drives.
	s.logf("rx 鼠标模式 = %d（%s）", mode, label)
	if force {
		s.logf("请求切换到绝对/同步模式（1）…")
		s.after(150*time.Millisecond, func() {
			s.send(BuildFrame(s.codeKey, []byte{CmdMouseModeSet, 0x00, 0x01, 0x00, 0x00}), "MOUSE_MODE_SET(1)")
		})
	}
	if s.OnMouseMode != nil {
		s.OnMouseMode(mode)
	}
}

// onImage handles IMAGE_DATA(0x02). Payload layout (validated):
//
//	[0..1] 00 00 | [2] 0x02 | [3] pad
//	[4..5] sub-packet sequence (u16be), 0 = frame header sub-packet
//	[6]    frame number
//	[7..]  sub-packet body; for seq 0 this is PLAINTEXT, for seq != 0 it is
//	       [7]=plaintext length followed by AES-CBC ciphertext
//
// The session's own `imageData` view starts at payload[4], so buf[k] == payload[k+4]
// exactly as in the protocol notes.
func (s *Session) onImage(p []byte) {
	s.mu.Lock()
	kvmKey := s.kvmKey
	s.mu.Unlock()
	if kvmKey == nil {
		return
	}
	if len(p) < 7 {
		return
	}
	seq := int(binary.BigEndian.Uint16(p[4:6]))
	frameNo := int(p[6])

	var imageData []byte
	if seq == 0 {
		imageData = sub(p, 4, len(p))
	} else {
		if len(p) < 8 {
			return
		}
		plainLen := int(p[7])
		ct := sub(p, 8, len(p))
		if len(ct) == 0 || len(ct)%16 != 0 {
			return
		}
		pt, err := AESDecryptNoPad(ct, sub(kvmKey, 0, 16), sub(kvmKey, 32, 48))
		if err != nil {
			return
		}
		imageData = make([]byte, 0, 3+plainLen)
		imageData = append(imageData, sub(p, 4, 7)...)
		imageData = append(imageData, sub(pt, 0, plainLen)...)
	}

	if seq == 0 {
		if len(imageData) < 17 {
			return
		}
		total := int(binary.BigEndian.Uint32(sub(imageData, 3, 7)))
		flags := imageData[7]
		width := (int(flags&0x7f) << 8) | int(imageData[8])
		height := int(binary.BigEndian.Uint16(sub(imageData, 9, 11)))
		blockX := (width + 63) / 64
		blockY := (height + 63) / 64

		// The frame header is authoritative for which quantization table to decode
		// with. Log it whenever it changes so a mismatch with the 0x27 setting (which
		// would show up as a dim or washed-out picture) is visible rather than guessed.
		hdrDqt := int(imageData[16] & 0x0f)
		s.mu.Lock()
		s.width, s.height = width, height
		s.blockX, s.blockY = blockX, blockY
		changed := !s.hdrDqtSeen || s.hdrDqt != hdrDqt
		s.hdrDqt = hdrDqt
		s.hdrDqtSeen = true
		s.mu.Unlock()
		if changed {
			s.logf("帧头 DQT 索引 = %d（量化表 _%d）", hdrDqt, hdrDqt*10+10)
			if s.OnHdrDqt != nil {
				s.OnHdrDqt(hdrDqt)
			}
		}

		n := total/SubpacketChunk + 1
		if total%SubpacketChunk != 0 {
			n++
		}
		cur := &pendingFrame{
			frameNo: frameNo,
			total:   total,
			diff:    int((flags >> 7) & 1),
			dqt:     int(imageData[16] & 0x0f),
			iframe:  int((imageData[16] >> 7) & 1),
			slots:   make([][]byte, n),
			got:     1,
		}
		cur.slots[0] = imageData
		s.mu.Lock()
		s.pending = cur
		if total == 0 {
			s.framesReceived++
			s.pending = nil
		}
		s.mu.Unlock()

		if total == 0 {
			if s.OnFrame != nil {
				s.OnFrame(Frame{
					NoChange: true,
					FrameNo:  frameNo,
					Width:    width, Height: height,
					BlockX: blockX, BlockY: blockY,
					Diff: cur.diff, DQT: cur.dqt, IFrame: cur.iframe,
				})
			}
		}
		return
	}

	s.mu.Lock()
	cur := s.pending
	if cur == nil || cur.frameNo != frameNo {
		// stale sub-packet from an aborted frame
		s.mu.Unlock()
		return
	}
	if seq >= len(cur.slots) {
		s.pending = nil
		s.mu.Unlock()
		return
	}
	if cur.slots[seq] == nil {
		cur.slots[seq] = imageData
		cur.sum += len(imageData) - 3
		cur.got++
	}
	done := cur.sum == cur.total
	s.mu.Unlock()
	if done {
		s.completeFrame()
	}
}

func (s *Session) completeFrame() {
	s.mu.Lock()
	cur := s.pending
	s.pending = nil
	s.mu.Unlock()
	if cur == nil {
		return
	}

	// combine(): data[0] = diff flag, then concatenate buf[3..] of every seq>=1
	// sub-packet. packLenght counts only seq>=1 sub-packets, so this yields
	// exactly total+1 bytes.
	parts := [][]byte{{byte(cur.diff)}}
	total := 1
	for i := 1; i < len(cur.slots); i++ {
		sl := cur.slots[i]
		if sl == nil {
			s.logf("帧 %d 序号 %d 缺失，丢弃", cur.frameNo, i)
			s.RequestIFrame()
			return
		}
		chunk := sub(sl, 3, len(sl))
		parts = append(parts, chunk)
		total += len(chunk)
	}
	stream := bytes.Join(parts, nil)

	s.mu.Lock()
	s.framesReceived++
	s.frameNo = cur.frameNo
	width, height := s.width, s.height
	blockX, blockY := s.blockX, s.blockY
	s.mu.Unlock()

	if total != cur.total+1 {
		// The vendor's accounting says the combined buffer must be exactly
		// packLenght+1 bytes; anything else means the stream and our bookkeeping
		// disagree, which is worth surfacing rather than rendering.
		s.logf("帧 %d 重组长度 %d != packLenght+1 (%d)", cur.frameNo, total, cur.total+1)
	}

	if s.OnFrame != nil {
		s.OnFrame(Frame{
			FrameNo: cur.frameNo,
			Width:   width, Height: height,
			BlockX: blockX, BlockY: blockY,
			Diff: cur.diff, DQT: cur.dqt, IFrame: cur.iframe,
			Stream: stream,
		})
	}
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// SendKeyboard sends an 8-byte USB HID boot-keyboard report
// ([modifier, 0, k0..k5]); the payload is AES-encrypted once the kvm_key exists.
func (s *Session) SendKeyboard(report [8]byte) {
	s.mu.Lock()
	kvmKey := s.kvmKey
	authenticated := s.authenticated
	s.mu.Unlock()
	if !authenticated && kvmKey == nil {
		return
	}
	var payload []byte
	if kvmKey != nil {
		enc, err := AESEncryptNoPad(ZeroPad(report[:]), sub(kvmKey, 16, 32), sub(kvmKey, 32, 48))
		if err != nil {
			s.reportErr(err)
			return
		}
		payload = append([]byte{CmdKeyPack, Blade}, enc...)
	} else {
		payload = append([]byte{CmdKeyPack, Blade}, report[:]...)
	}
	s.send(BuildFrame(s.codeKey, payload), "")
}

// SendMouseAbs sends the absolute mouse position in the BMC's normalised
// 0..3000 space (mode 1 / synchronised).
func (s *Session) SendMouseAbs(x, y, buttons, wheel int) {
	s.mu.Lock()
	kvmKey := s.kvmKey
	width, height := s.width, s.height
	if kvmKey == nil || width == 0 || height == 0 {
		s.mu.Unlock()
		return
	}
	nx := int(math.Round(float64(x) * 3000 / float64(width)))
	ny := int(math.Round(float64(y) * 3000 / float64(height)))
	// dedup on the normalised values (raw pixel coords jitter, normalised ones don't)
	if s.haveLastMouse && nx == s.lastMouse[0] && ny == s.lastMouse[1] && wheel == 0 &&
		buttons == s.lastButtons {
		s.mu.Unlock()
		return
	}
	s.lastMouse = [2]int{nx, ny}
	s.lastButtons = buttons
	s.haveLastMouse = true
	s.mu.Unlock()

	body := make([]byte, 6)
	body[0] = byte(buttons)
	binary.BigEndian.PutUint16(body[1:], uint16(nx))
	binary.BigEndian.PutUint16(body[3:], uint16(ny))
	body[5] = byte(wheel)

	enc, err := AESEncryptNoPad(ZeroPad(body), sub(kvmKey, 16, 32), sub(kvmKey, 32, 48))
	if err != nil {
		s.reportErr(err)
		return
	}
	s.send(BuildFrame(s.codeKey, append([]byte{CmdMousePack, Blade}, enc...)), "")
}

// SendMouseRel sends relative mouse movement (mode 0), clamped to +/-120 per
// packet and split into as many packets as needed (at most 16).
func (s *Session) SendMouseRel(dx, dy, buttons int) {
	s.mu.Lock()
	kvmKey := s.kvmKey
	s.mu.Unlock()
	if kvmKey == nil {
		return
	}
	leftX := clampInt(dx, -120, 120)
	leftY := clampInt(dy, -120, 120)
	for i := 0; i < 16 && (leftX != 0 || leftY != 0); i++ {
		sx := clampInt(leftX, -120, 120)
		sy := clampInt(leftY, -120, 120)
		body := []byte{byte(buttons), byte(sx), byte(sy), 0x00}
		enc, err := AESEncryptNoPad(ZeroPad(body), sub(kvmKey, 16, 32), sub(kvmKey, 32, 48))
		if err != nil {
			s.reportErr(err)
			return
		}
		s.send(BuildFrame(s.codeKey, append([]byte{CmdMousePack, Blade}, enc...)), "")
		leftX -= sx
		leftY -= sy
	}
}

// RequestIFrame asks the BMC for a fresh I frame (needed when a differential
// frame arrives without a reference frame).
// Power control (power on/off, restart) and USB reset.
//
// With compress=1 — this firmware — the command is NOT sent directly. The BMC expects
// the 0x33 (SECURITY) command carrying a 16-byte AES-CBC block whose LAST byte is the
// real command; the key is kvmKey[0:16] and the IV kvmKey[32:48]. That is also why a
// power command cannot be verified from the wire alone: the command byte is encrypted.
func (s *Session) SendPower(cmd byte) error {
	frame := s.powerFrame(cmd)
	if frame == nil {
		return errors.New("尚未完成密钥协商，无法发送电源命令")
	}
	s.Send(frame, fmt.Sprintf("POWER(0x%02x)", cmd))
	return nil
}

// powerFrame builds the 0x33-wrapped power frame, or nil before key negotiation.
func (s *Session) powerFrame(cmd byte) []byte {
	key := s.KvmKey()
	if len(key) != 48 {
		return nil
	}
	body := make([]byte, 16)
	body[15] = cmd
	enc, err := AESEncryptNoPad(body, key[0:16], key[32:48])
	if err != nil {
		return nil
	}
	payload := make([]byte, 0, 18)
	payload = append(payload, CmdSecurity, 0x00)
	payload = append(payload, enc...)
	return BuildFrame(s.CodeKey(), payload)
}

func (s *Session) RequestIFrame() {
	s.send(BuildFrame(s.codeKey, []byte{CmdIReq, Blade}), "I_REQ")
}

// SetDqt sets the DQT quality. `dqtType` mirrors the vendor client: 2 while the
// slider is being dragged (continuous), 1 on release (commit); zero means 1.
func (s *Session) SetDqt(quality, dqtType int) {
	if dqtType == 0 {
		dqtType = 1
	}
	s.send(BuildFrame(s.codeKey, []byte{CmdDqtModeSet, 0x00, byte(quality), byte(dqtType), 0x00}),
		fmt.Sprintf("DQT(%d, type=%d)", quality, dqtType))
}

// CtrlAltDel sends Ctrl+Alt+Del as a HID report with modifier bits 0x01|0x04
// and keycode 0x4C, released 90ms later.
func (s *Session) CtrlAltDel() {
	s.SendKeyboard([8]byte{0x05, 0x00, 0x4c, 0, 0, 0, 0, 0})
	s.after(90*time.Millisecond, func() {
		s.SendKeyboard([8]byte{})
	})
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// jsParseInt32 mimics JavaScript's parseInt(s, 10) | 0: it reads the leading
// (optionally signed) decimal digits and truncates to 32 bits. The JNLP
// verifyValue is used exactly this way as the frame codeKey.
func jsParseInt32(s string) int32 {
	t := strings.TrimSpace(s)
	i := 0
	neg := false
	if i < len(t) && (t[i] == '+' || t[i] == '-') {
		neg = t[i] == '-'
		i++
	}
	var v uint64
	digits := 0
	for ; i < len(t) && t[i] >= '0' && t[i] <= '9'; i++ {
		v = v*10 + uint64(t[i]-'0')
		digits++
	}
	if digits == 0 {
		return 0
	}
	if neg {
		return int32(uint32(-v))
	}
	return int32(uint32(v))
}

// hexDecode decodes a hex string, tolerating odd input by stopping at the first
// invalid pair (the JS Buffer.from(hex) behaves the same way).
func hexDecode(s string) []byte {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			break
		}
		out = append(out, hi<<4|lo)
	}
	return out
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
