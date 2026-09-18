package vmm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// State is VMConsole's console state machine. The per-device link states
// (cdromState / floppyState) use the same five values in the Java, so this type
// is used for both.
type State int

const (
	StateIdle    State = 0 // CONSOLE_IDLE
	StateInit    State = 1 // CONSOLE_INIT    (socket connected, nothing sent yet)
	StateCertify State = 2 // CONSOLE_CERTIFY (CERTIFY_ID sent, awaiting ACK 0)
	StateDevice  State = 3 // CONSOLE_DEVICE  (DEVICE_TYPE sent, awaiting ACK 16)
	StateActive  State = 4 // CONSOLE_ACTIVE  (SCSI traffic + heartbeats)
)

// String renders the state for logs.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateInit:
		return "init"
	case StateCertify:
		return "certify"
	case StateDevice:
		return "device"
	case StateActive:
		return "active"
	}
	return fmt.Sprintf("state%d", int(s))
}

// DefaultPort is the VMM channel's TCP port (VirtualMedia's hardcoded 8208).
const DefaultPort = 8208

// DefaultVersion is the client version reported in CERTIFY_ID
// (vmconfigResource.properties: com.huawei.vm.console.config.version).
const DefaultVersion = "3.01.01.01"

// Options configures a Session.
type Options struct {
	Host string
	// Port defaults to 8208 when zero.
	Port int
	// CodeKey is the PBKDF2 password material: the 20-byte negotiated code key,
	// or the 4-byte big-endian mmVerifyValue on the legacy path. Required.
	CodeKey []byte
	// Salt is the 16-byte vmm salt from the KVM channel; nil means 16 zero
	// bytes, which is what VirtualMedia.getVmmSalt returns when the code key was
	// never negotiated.
	Salt []byte
	// Iterations and PRF come from the KVM suite negotiation; they default to
	// ConsoleControllers' values (5000 / PBKDF2WithHmacSHA1).
	Iterations int
	PRF        string
	// Version is the CERTIFY_ID version string; empty means DefaultVersion.
	Version string
	// NoCompress mirrors vmm_compress == 0: when true, SCSI data payloads are
	// sent and expected in the clear. The vendor default is vmm_compress = 1
	// (encrypted), so the zero value of this field means "encrypt".
	NoCompress bool
	// Quiet suppresses the Log hook.
	Quiet bool
	// Log receives human-readable progress messages (may be nil).
	Log func(string)
	// OnState fires whenever the console state changes.
	OnState func(State)
	// OnError fires for protocol/device errors, including the fatal ones that
	// tear the link down. The value is an *Error.
	OnError func(error)
	// OnClosed fires when the connection is gone (remote close, error or Close).
	OnClosed func()
	// DialTimeout overrides the 20s connect timeout.
	DialTimeout time.Duration
	// LocalIP overrides the address sent in CERTIFY_ID (testing hook); nil uses
	// the socket's own local address (Socket.getLocalAddress).
	LocalIP net.IP
	// TickInterval overrides the 1s heartbeat timer granularity (testing hook).
	TickInterval time.Duration
}

// Status is a consistent snapshot of the session.
type Status struct {
	State       State
	Connected   bool
	Certified   bool
	Active      bool
	CDROMState  State
	FloppyState State
	ErrCode     int
	CDROMErr    int
	FloppyErr   int
	HasKey      bool
}

// deviceHandler is what the reader needs to feed a mounted device.
type deviceHandler interface {
	enqueueCommand(id byte, cdb []byte)
	enqueueData(b []byte)
}

// Session is one VMM connection. Like VMConsole it holds a single socket that
// can carry a CD-ROM and a floppy at the same time; each Mount registers one
// device type.
//
// A Session performs network I/O in background goroutines and is safe for
// concurrent use. The zero value is not usable: call New.
type Session struct {
	opts Options

	mu            sync.Mutex
	conn          net.Conn
	state         State
	key           KeyMaterial
	hasKey        bool
	errCode       int // VMConsole.errCode (console level)
	cdromState    State
	floppyState   State
	cdromErr      int
	floppyErr     int
	cdromReconn   bool
	floppyReconn  bool
	cdromDev      *CDROM
	floppyDev     *Floppy
	cdromH        *sffHandler
	floppyH       *ufiHandler
	cdromStarted  bool
	floppyStarted bool
	localIP       net.IP

	hbCount  int
	hbSteps  int
	tickerOn bool

	// Watchdog durations; the Java hardcodes 10s for both. Kept as fields so
	// tests can shrink them.
	certifyTimeout time.Duration
	deviceTimeout  time.Duration

	done      chan struct{}
	stopped   bool
	watchers  []*time.Timer
	readerWG  sync.WaitGroup
	handlerWG sync.WaitGroup
	writeMu   sync.Mutex
}

// New creates a session. It does not touch the network: the connection is made
// by the first Mount.
func New(opts Options) *Session {
	if opts.Port == 0 {
		opts.Port = DefaultPort
	}
	if opts.Version == "" {
		opts.Version = DefaultVersion
	}
	if opts.Iterations == 0 {
		opts.Iterations = DefaultIterations
	}
	if opts.PRF == "" {
		opts.PRF = DefaultPRF
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = ConnectTimeoutMs * time.Millisecond
	}
	if opts.TickInterval == 0 {
		opts.TickInterval = HeartbeatTickMs * time.Millisecond
	}
	if opts.Salt == nil {
		opts.Salt = make([]byte, IVSize) // VirtualMedia.getVmmSalt fallback
	}
	return &Session{
		opts:           opts,
		done:           make(chan struct{}),
		certifyTimeout: CertifyTimeoutMs * time.Millisecond,
		deviceTimeout:  DeviceTimeoutMs * time.Millisecond,
	}
}

// ---------------------------------------------------------------------------
// Public lifecycle API
// ---------------------------------------------------------------------------

// MountISO attaches an ISO file as the virtual CD-ROM. The first call dials the
// VMM port and runs CERTIFY_ID + DEVICE_TYPE; a call made while the session is
// already ACTIVE (for example with a floppy attached) reuses the same socket and
// only registers the CD-ROM (VMConsole.sentVirtualCommand).
//
// Mount the CD-ROM first when both devices are wanted: the ACK(0) handler
// registers a CD-ROM whenever one exists, so a floppy mounted before the first
// ACK is acknowledged would never be registered (the Java has the same hole).
func (s *Session) MountISO(path string) error { return s.mount(DeviceCDROM, path, false) }

// MountFloppy attaches an .img file (exactly 2880 * 512 bytes) as the virtual
// floppy. writeProtect mirrors the vendor UI's checkbox; the Java default is
// protected (MassStorageDevice.isWP = true).
func (s *Session) MountFloppy(path string, writeProtect bool) error {
	return s.mount(DeviceFloppy, path, writeProtect)
}

// Detach removes one device (CloseTypeFloppy or CloseTypeCDROM) or everything
// (CloseTypeLink, which is what Close does). Detaching one device while the
// other is active keeps the socket, exactly like VMConsole.destoryVMLink; the
// detached image is closed.
func (s *Session) Detach(deviceType int) error {
	s.destroyLink(deviceType)
	return nil
}

// Close tears the session down, sending CLOSE_VM(0) when the link is ACTIVE and
// healthy (VMConsole.destoryVMLink(0)).
func (s *Session) Close() error {
	s.destroyLink(0)
	return nil
}

// State returns the console state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Status returns a snapshot.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		State:       s.state,
		Connected:   s.conn != nil,
		Certified:   s.state >= StateDevice,
		Active:      s.state == StateActive,
		CDROMState:  s.cdromState,
		FloppyState: s.floppyState,
		ErrCode:     s.errCode,
		CDROMErr:    s.cdromErr,
		FloppyErr:   s.floppyErr,
		HasKey:      s.hasKey,
	}
}

// ErrCode returns the recorded error code for a device type (0 = console,
// 1 = floppy, 2 = CD-ROM), mirroring VMConsole.getState.
func (s *Session) ErrCode(deviceType int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch deviceType {
	case DeviceFloppy:
		return s.floppyErr
	case DeviceCDROM:
		return s.cdromErr
	}
	return s.errCode
}

// ---------------------------------------------------------------------------
// Mount (VMConsole.creatVMLink + createCommon)
// ---------------------------------------------------------------------------

func (s *Session) mount(deviceType int, path string, writeProtect bool) error {
	if deviceType != DeviceCDROM && deviceType != DeviceFloppy {
		return fmt.Errorf("vmm: unknown device type %d", deviceType)
	}
	if len(s.opts.CodeKey) == 0 {
		return errors.New("vmm: Options.CodeKey is required")
	}

	s.mu.Lock()
	if s.cdromDev != nil && deviceType == DeviceCDROM {
		s.mu.Unlock()
		return errors.New("vmm: CD-ROM 已挂载")
	}
	if s.floppyDev != nil && deviceType == DeviceFloppy {
		s.mu.Unlock()
		return errors.New("vmm: 软驱已挂载")
	}
	firstMount := s.state == StateIdle
	if firstMount {
		// createCommon: clear the error codes, enter INIT and dial.
		s.errCode, s.cdromErr, s.floppyErr = 0, 0, 0
		s.state = StateInit
		if deviceType == DeviceCDROM {
			s.cdromState = StateInit
		} else {
			s.floppyState = StateInit
		}
	}
	s.mu.Unlock()

	if firstMount {
		if err := s.connect(); err != nil {
			s.errorProcess(0, errCodeOf(err))
			return err
		}
		s.notifyState()
	}

	// The device object is created after the socket, the way creatVMLink opens
	// CDROMImage / FloppyImage right after createCommon.
	var dev scsiDevice
	var err error
	switch deviceType {
	case DeviceCDROM:
		var c *CDROM
		c, err = OpenISO(path)
		if err == nil {
			dev = c
		}
	case DeviceFloppy:
		var f *Floppy
		f, err = OpenFloppy(path, writeProtect)
		if err == nil {
			dev = f
		}
	}
	if err != nil {
		s.errorProcess(deviceType, errCodeOf(err))
		return err
	}

	s.mu.Lock()
	switch deviceType {
	case DeviceCDROM:
		s.cdromDev = dev.(*CDROM)
		s.cdromH = newSFFHandler(s, dev.(*CDROM))
		s.cdromStarted = false
		s.cdromState = StateInit
	case DeviceFloppy:
		s.floppyDev = dev.(*Floppy)
		s.floppyH = newUFIHandler(s, dev.(*Floppy))
		s.floppyStarted = false
		s.floppyState = StateInit
	}
	if s.cdromDev == nil && s.floppyDev == nil {
		// creatVMLink raises VMException(301) when neither device exists.
		s.mu.Unlock()
		_ = dev.close()
		s.errorProcess(deviceType, ErrCreateDevice)
		return &Error{Code: ErrCreateDevice, DeviceType: deviceType, Op: "mount"}
	}
	// createSecretCertifyCode runs on every mount in the Java, recomputing the
	// same key material from the same inputs.
	mat, err := DeriveKeyMaterial(s.opts.CodeKey, s.opts.Salt, s.opts.Iterations, s.opts.PRF)
	if err != nil {
		s.mu.Unlock()
		s.errorProcess(deviceType, ErrCreateDevice)
		return err
	}
	s.key, s.hasKey = mat, true
	s.mu.Unlock()

	s.sendCertifyCode(deviceType)
	s.sendVirtualCommand(deviceType)
	return nil
}

// connect dials the VMM port and starts the reader (VMConsole.connect plus the
// receiver/sender thread startup in createCommon).
func (s *Session) connect() error {
	if s.opts.Host == "" || s.opts.Port < 0 {
		return &Error{Code: ErrIP, DeviceType: 0, Op: "connect"}
	}
	addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
	conn, err := net.DialTimeout("tcp", addr, s.opts.DialTimeout)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return &Error{Code: ErrConnectTime, DeviceType: 0, Op: "connect", Err: err}
		}
		return &Error{Code: ErrConnect, DeviceType: 0, Op: "connect", Err: err}
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	ip := s.opts.LocalIP
	if ip == nil {
		if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			ip = ta.IP
		}
	}
	var ipBytes []byte
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ipBytes = v4
		} else {
			ipBytes = ip.To16()
		}
	}
	if ipBytes == nil {
		_ = conn.Close()
		return &Error{Code: ErrConnect, DeviceType: 0, Op: "connect", Err: errors.New("no local IP")}
	}

	s.mu.Lock()
	s.conn = conn
	s.localIP = ipBytes
	s.hbCount = heartbeatOvertime
	s.hbSteps = 0
	s.stopped = false
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()

	s.readerWG.Add(1)
	go s.readLoop(conn, done)
	return nil
}

// sendCertifyCode is VMConsole.sentCertifyCode.
func (s *Session) sendCertifyCode(deviceType int) {
	s.mu.Lock()
	if s.state != StateInit {
		s.mu.Unlock()
		return
	}
	sessionID := append([]byte(nil), s.key.SessionID...)
	ip := append([]byte(nil), s.localIP...)
	pack, err := ConnectPak(sessionID, ip, s.opts.Version)
	if err != nil {
		s.mu.Unlock()
		s.errorProcess(deviceType, ErrConnect)
		return
	}
	s.state = StateCertify
	if deviceType == DeviceCDROM {
		s.cdromState = StateCertify
	} else {
		s.floppyState = StateCertify
	}
	s.mu.Unlock()
	s.notifyState()
	// 10s watchdog: no ACK(0) by then is error 121 (ConsoleCertifyTimerTask).
	s.armWatchdog(StateCertify, deviceType, ErrCertifyTime, s.certifyTimeout)
	s.write(pack)
}

// sendVirtualCommand is VMConsole.sentVirtualCommand: when the console is
// already ACTIVE this registers the second device on the existing socket.
func (s *Session) sendVirtualCommand(deviceType int) {
	s.mu.Lock()
	switch {
	case deviceType == DeviceCDROM && s.state == StateActive &&
		s.cdromState == StateInit && s.cdromDev != nil:
		s.startSFFLocked()
		s.cdromState = StateDevice
	case deviceType == DeviceFloppy && s.state == StateActive &&
		s.floppyState == StateInit && s.floppyDev != nil:
		s.startUFILocked()
		s.floppyState = StateDevice
	default:
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	// CdromStateTimerTask / FloppyStateTimerTask: 10s to get ACK(16).
	s.armWatchdog(StateDevice, deviceType, ErrDeviceTime, s.deviceTimeout)
	s.write(DevicesPak(deviceType))
}

// ---------------------------------------------------------------------------
// ACK handling (VMConsole.processAck)
// ---------------------------------------------------------------------------

func (s *Session) processAck(code int) {
	s.mu.Lock()
	state := s.state
	switch {
	case state == StateCertify && code == AckCertifyPass:
		s.cancelWatchdogsLocked()
		// The Java picks the CD-ROM whenever one is configured, regardless of
		// which device this mount was for; the floppy path is the else.
		var pack []byte
		if s.cdromDev != nil {
			s.startSFFLocked()
			pack = DevicesPak(DeviceCDROM)
			s.cdromState = StateDevice
		} else {
			s.startUFILocked()
			pack = DevicesPak(DeviceFloppy)
			s.floppyState = StateDevice
		}
		s.state = StateDevice
		s.mu.Unlock()
		s.notifyState()
		s.logf("rx ACK(0) 认证通过，发送 DEVICE_TYPE")
		s.armWatchdog(StateDevice, 0, ErrDeviceTime, s.deviceTimeout)
		s.write(pack)
		return
	case (state == StateDevice || state == StateActive) && code == AckDeviceCreat:
		s.cancelWatchdogsLocked()
		if state == StateDevice {
			s.startTickerLocked()
			s.hbCount = heartbeatOvertime
			s.hbSteps = 0
		}
		s.state = StateActive
		if s.cdromState == StateDevice {
			s.cdromState = StateActive
			s.cdromReconn = true
		}
		if s.floppyState == StateDevice {
			s.floppyState = StateActive
			s.floppyReconn = true
		}
		s.mu.Unlock()
		s.notifyState()
		s.logf("rx ACK(16) 设备创建成功，进入 ACTIVE")
		return
	case (s.cdromState == StateCertify || s.floppyState == StateCertify) && code == CnExist:
		deviceType := 0
		if s.cdromState == StateCertify {
			deviceType = DeviceCDROM
		} else if s.floppyState == StateCertify {
			deviceType = DeviceFloppy
		}
		s.mu.Unlock()
		s.errorProcess(deviceType, ErrDeviceInUse)
		return
	case s.cdromState == StateCertify:
		s.mu.Unlock()
		s.errorProcess(DeviceCDROM, code)
		return
	case s.floppyState == StateCertify:
		s.mu.Unlock()
		s.errorProcess(DeviceFloppy, code)
		return
	default:
		errCode := s.errCode
		s.mu.Unlock()
		s.errorProcess(0, errCode)
	}
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

func (s *Session) readLoop(conn net.Conn, done chan struct{}) {
	defer s.readerWG.Done()
	var readErr error
	for {
		select {
		case <-done:
			s.closeReader(conn, nil)
			return
		default:
		}
		hdr := make([]byte, HeaderSize)
		if err := readFullDeadline(conn, hdr, HeartbeatEveryMs, done); err != nil {
			if errors.Is(err, errReadTimeout) {
				continue // the Java's soTimeout with nothing read: poll again
			}
			readErr = err
			break
		}
		h, _ := DecodeHeader(hdr)
		var payload []byte
		if h.Length > 0 {
			payload = make([]byte, h.Length)
			for {
				err := readFullDeadline(conn, payload, BusinessOvertimeMs, done)
				if errors.Is(err, errReadTimeout) {
					continue // the Java keeps retrying the payload read
				}
				if err != nil {
					readErr = err
				}
				break
			}
			if readErr != nil {
				break
			}
		}
		// ProtocolProcessor.resetHeartbit: any complete inbound frame counts as
		// traffic.
		s.resetHeartbeat()
		s.dispatch(h, payload)
	}
	s.closeReader(conn, readErr)
}

// closeReader unwinds the reader: a socket error or EOF tears the link down
// (the Java's ProtocolProcessor turns them into errorProcess(0, 101) for EOF and
// 102 for an IOException), unless the session was stopped deliberately. OnClosed
// fires once per connection.
func (s *Session) closeReader(conn net.Conn, err error) {
	s.mu.Lock()
	intentional := s.stopped || s.conn != conn
	if s.conn == conn {
		s.conn = nil
	}
	s.mu.Unlock()

	if err != nil && !intentional && !errors.Is(err, net.ErrClosed) {
		code := 102 // VMException(102): IOException while receiving
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			code = 101 // VMException(101): the peer closed the socket
		}
		s.errorProcess(0, code)
	}
	if s.opts.OnClosed != nil {
		s.opts.OnClosed()
	}
}

// dispatch runs one frame (ProtocolProcessor.parsePak).
func (s *Session) dispatch(h Header, payload []byte) {
	switch h.Op {
	case OpACK:
		s.processAck(int(h.Code))
	case OpCloseVM:
		s.closeVM(CloseVMTypeIn(h.Sub), int(h.Code))
	case OpShutdown:
		s.closeVM(0, int(h.Code))
	case OpUFIData, OpSFFData:
		s.dispatchUSB(h, payload)
	case OpConsolePrint:
		s.logf("rx 打印级别 = %d", h.Code)
	default:
		s.logf("rx 未知帧 op=0x%02x len=%d", h.Op, h.Length)
	}
}

// dispatchUSB mirrors ProtocolProcessor's UFI/SFF branches: a zero-length frame
// queues nothing, a low nibble of 0 is a 12-byte CDB (anything else is dropped,
// because DataElement.getUSBRequestInstance insists on exactly 12 bytes) and
// anything else is data.
func (s *Session) dispatchUSB(h Header, payload []byte) {
	if h.Length == 0 {
		return // parsePak: `if (0 == nextDataSize) { resetRcvVar(); break; }`
	}
	s.mu.Lock()
	var handler deviceHandler
	if h.Op == OpUFIData {
		if s.floppyH != nil {
			handler = s.floppyH
		}
	} else if s.cdromH != nil {
		handler = s.cdromH
	}
	s.mu.Unlock()

	if handler == nil {
		kind := DeviceFloppy
		if h.Op == OpSFFData {
			kind = DeviceCDROM
		}
		s.logf("rx %s 数据但设备未挂载，丢弃", DeviceTypeName(kind))
		return
	}
	if h.DataKind() == SubCommand {
		handler.enqueueCommand(h.ID, payload)
		return
	}
	handler.enqueueData(payload)
}

// closeVM is VMConsole.closeVM (CLOSE_VM and SHUTDOWN).
func (s *Session) closeVM(vmType, reason int) {
	s.logf("rx CLOSE_VM %s reason=%d", DeviceTypeName(vmType), reason)
	switch vmType {
	case CloseTypeLink:
		s.errorProcess(0, reason)
	case CloseTypeCDROM:
		s.errorProcess(DeviceCDROM, reason)
	case CloseTypeFloppy:
		s.errorProcess(DeviceFloppy, reason)
	}
}

// ---------------------------------------------------------------------------
// errorProcess / destoryVMLink
// ---------------------------------------------------------------------------

// stateForLocked is the switcher of VMConsole.errorProcess: the console state
// for type 0, the device's own link state otherwise.
func (s *Session) stateForLocked(deviceType int) State {
	switch deviceType {
	case DeviceCDROM:
		return s.cdromState
	case DeviceFloppy:
		return s.floppyState
	}
	return s.state
}

func (s *Session) setErrCodeLocked(deviceType, code int) {
	switch deviceType {
	case DeviceCDROM:
		s.cdromErr = code
	case DeviceFloppy:
		s.floppyErr = code
	default:
		s.errCode = code
	}
}

// errorProcess is VMConsole.errorProcess: the routing table decides between
// tearing down one device's link and tearing down the whole console. (The Java
// also marks the console flag "destory" here, which only drives its UI.)
func (s *Session) errorProcess(deviceType, code int) {
	if code != 0 {
		s.reportErr(&Error{Code: code, DeviceType: deviceType})
	}

	s.mu.Lock()
	full := false
	partial := false
	switch s.stateForLocked(deviceType) {
	case StateInit:
		switch code {
		case 110, 220, 223, 253, 301, 320, 321, 326, 327, 335:
			s.setErrCodeLocked(deviceType, code)
			full = true
		case 102, 103, 104, 105, 210:
			s.setErrCodeLocked(deviceType, code)
			s.setErrCodeLocked(0, code)
			full = true
		}
	case StateCertify:
		switch code {
		case 335:
			s.setErrCodeLocked(deviceType, code)
			partial = true
		case 1, 2, 34, 35, 101, 102, 121:
			s.setErrCodeLocked(deviceType, code)
			s.setErrCodeLocked(0, code)
			full = true
		case 401:
			if deviceType == DeviceCDROM || deviceType == DeviceFloppy {
				s.setErrCodeLocked(0, code)
				s.setErrCodeLocked(deviceType, code)
				partial = true
			}
		}
	case StateDevice:
		switch code {
		case 122, 335:
			s.setErrCodeLocked(deviceType, code)
			partial = true
		case 17, 34, 35, 101, 102:
			s.setErrCodeLocked(deviceType, code)
			s.setErrCodeLocked(0, code)
			full = true
		}
	case StateActive:
		switch code {
		case 34, 35, 101, 102, 123:
			s.setErrCodeLocked(deviceType, code)
			s.setErrCodeLocked(0, code)
			full = true
		case 335:
			s.setErrCodeLocked(deviceType, code)
			partial = true
		}
	}
	s.mu.Unlock()

	switch {
	case full:
		s.destroyLink(0)
	case partial:
		s.destroyLink(deviceType)
	}
}

// destroyLink is VMConsole.destoryVMLink.
func (s *Session) destroyLink(deviceType int) {
	s.mu.Lock()
	if s.state == StateIdle {
		s.mu.Unlock()
		return
	}
	cdromActive := s.cdromState == StateActive
	floppyActive := s.floppyState == StateActive
	full := deviceType == 0 ||
		(deviceType == DeviceFloppy && !cdromActive) ||
		(deviceType == DeviceCDROM && !floppyActive)

	if full {
		// The client says goodbye only on a healthy ACTIVE link.
		sendClose := s.state == StateActive && s.errCode == 0
		s.mu.Unlock()
		if sendClose {
			s.write(VMLinkClosePak(CloseTypeLink, 0))
			// destoryVMLink waits 2ms for the frame to leave before closing.
			time.Sleep(2 * time.Millisecond)
		}
		s.stopEverything()
		return
	}

	if deviceType == DeviceFloppy && cdromActive {
		// Detach the floppy, keep the socket (VMConsole's
		// `1 == type && 4 == cdromState` branch).
		sendClose := floppyActive && s.errCode == 0
		h := s.floppyH
		dev := s.floppyDev
		s.floppyState = StateIdle
		s.floppyReconn = false
		s.floppyDev, s.floppyH, s.floppyStarted = nil, nil, false
		s.mu.Unlock()
		if sendClose {
			s.write(VMLinkClosePak(CloseTypeFloppy, 0))
		}
		if h != nil {
			h.stop()
		}
		if dev != nil {
			_ = dev.close()
		}
		return
	}
	if deviceType == DeviceCDROM && floppyActive {
		sendClose := cdromActive && s.errCode == 0
		h := s.cdromH
		dev := s.cdromDev
		s.cdromState = StateIdle
		s.cdromReconn = false
		s.cdromDev, s.cdromH, s.cdromStarted = nil, nil, false
		s.mu.Unlock()
		if sendClose {
			s.write(VMLinkClosePak(CloseTypeCDROM, 0))
		}
		if h != nil {
			h.stop()
		}
		if dev != nil {
			_ = dev.close()
		}
		return
	}
	s.mu.Unlock()
}

// stopEverything is destroyCommonConn + initAll: stop the reader and the device
// handlers, close the socket and every image, and drop back to IDLE.
func (s *Session) stopEverything() {
	s.mu.Lock()
	if s.stopped && s.conn == nil && s.state == StateIdle {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	conn := s.conn
	s.conn = nil
	done := s.done
	s.cancelWatchdogsLocked()
	cdH, flH := s.cdromH, s.floppyH
	cdDev, flDev := s.cdromDev, s.floppyDev
	s.cdromH, s.floppyH = nil, nil
	s.cdromDev, s.floppyDev = nil, nil
	s.cdromStarted, s.floppyStarted = false, false
	// commonInit(): console and both device states back to 0.
	s.state = StateIdle
	s.cdromState = StateIdle
	s.floppyState = StateIdle
	s.cdromReconn, s.floppyReconn = false, false
	s.tickerOn = false
	select {
	case <-done:
	default:
		close(done)
	}
	s.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if cdH != nil {
		cdH.stop()
	}
	if flH != nil {
		flH.stop()
	}
	if cdDev != nil {
		_ = cdDev.close()
	}
	if flDev != nil {
		_ = flDev.close()
	}
	s.notifyState()
	s.logf("VMM 链路已断开")
}

// startSFFLocked / startUFILocked are createSFFProcessor / createUFIProcessor.
// The Java would start a second consumer thread if called twice (both would
// drain the same queue); the Go port keeps exactly one consumer per device.
func (s *Session) startSFFLocked() {
	if s.cdromH == nil || s.cdromStarted {
		return
	}
	s.cdromStarted = true
	h := s.cdromH
	s.handlerWG.Add(1)
	go func() {
		defer s.handlerWG.Done()
		h.run()
	}()
}

func (s *Session) startUFILocked() {
	if s.floppyH == nil || s.floppyStarted {
		return
	}
	s.floppyStarted = true
	h := s.floppyH
	s.handlerWG.Add(1)
	go func() {
		defer s.handlerWG.Done()
		h.run()
	}()
}

// ---------------------------------------------------------------------------
// Watchdogs and the heartbeat ticker
// ---------------------------------------------------------------------------

// armWatchdog schedules the Java's tempTask. ConsoleCertifyTimerTask and
// ConsoleStateTimerTask check the console state; the two device tasks check the
// device's own link state. Either way the timer is a no-op if the state has
// already moved on.
func (s *Session) armWatchdog(expected State, deviceType, code int, d time.Duration) {
	t := time.AfterFunc(d, func() {
		s.mu.Lock()
		var current State
		if deviceType != 0 {
			current = s.stateForLocked(deviceType)
		} else {
			current = s.state
		}
		s.mu.Unlock()
		if current != expected {
			return
		}
		s.errorProcess(deviceType, code)
	})
	s.mu.Lock()
	s.watchers = append(s.watchers, t)
	s.mu.Unlock()
}

func (s *Session) cancelWatchdogsLocked() {
	for _, t := range s.watchers {
		t.Stop()
	}
	s.watchers = nil
}

// startTickerLocked starts the 1s VMTimerTask loop (once per ACTIVE link).
func (s *Session) startTickerLocked() {
	if s.tickerOn {
		return
	}
	s.tickerOn = true
	done := s.done
	interval := s.opts.TickInterval
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.tick()
			}
		}
	}()
}

// tick is VMTimerTask.run: decrement the 40-tick "no traffic" counter and send
// a heartbeat every 10th tick. The client's own heartbeat never resets the
// counter (CommunicationSender.resetHeartbit skips frames whose first byte is
// the heartbeat opcode), so the BMC must send something within 40s.
func (s *Session) tick() {
	s.mu.Lock()
	s.hbSteps = (s.hbSteps + 1) % (HeartbeatEveryMs / HeartbeatTickMs)
	s.hbCount--
	expired := s.hbCount == 0
	sendHB := s.hbSteps == 0
	s.mu.Unlock()
	if expired {
		s.logf("40s 无流量，断开链路")
		s.errorProcess(0, ErrNoTraffic)
		return
	}
	if sendHB {
		_ = s.write(HeartbeatFrame())
	}
}

// resetHeartbeat is VMTimerTask.heartBitInit.
func (s *Session) resetHeartbeat() {
	s.mu.Lock()
	s.hbCount = heartbeatOvertime
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Transport (wire implementation)
// ---------------------------------------------------------------------------

// heartbeatOvertime is 4 * (HEARTBIT_INTERVAL / 1000) ticks = 40 seconds.
const heartbeatOvertime = 4 * (HeartbeatEveryMs / HeartbeatTickMs)

var errNoConn = errors.New("vmm: not connected")

// write is CommunicationSender.send plus the sender thread's write/flush.
func (s *Session) write(frame []byte) error {
	if len(frame) > 0 {
		s.logf("tx op=0x%02x len=%d", frame[0], len(frame))
	}
	s.writeMu.Lock()
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		s.writeMu.Unlock()
		return errNoConn
	}
	_, err := conn.Write(frame)
	s.writeMu.Unlock()
	if err != nil {
		return err
	}
	// CommunicationSender.resetHeartbit: a 12-byte frame that is not a
	// heartbeat counts as outbound traffic.
	if len(frame) == HeaderSize && frame[0] != OpHeartbeat {
		s.resetHeartbeat()
	}
	return nil
}

func (s *Session) send(frame []byte) error { return s.write(frame) }

func (s *Session) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func (s *Session) encryptPayloads() bool { return !s.opts.NoCompress }

func (s *Session) secret() (key, iv []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key.SecretKey, s.key.SecretIV
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var errReadTimeout = errors.New("vmm: read timeout")

// readFullDeadline reads len(buf) bytes, applying the Java's soTimeout to each
// read attempt. A timeout with nothing read returns errReadTimeout (the caller
// polls again, like receiveByLimit returning false); a timeout after a partial
// read keeps waiting, mirroring the Java's "reset soTimeout to 0 and continue".
func readFullDeadline(conn net.Conn, buf []byte, timeoutMs int, done chan struct{}) error {
	off := 0
	for off < len(buf) {
		select {
		case <-done:
			return net.ErrClosed
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
		n, err := conn.Read(buf[off:])
		off += n
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if off == 0 {
					return errReadTimeout
				}
				continue
			}
			return err
		}
	}
	return nil
}

func (s *Session) notifyState() {
	if s.opts.OnState == nil {
		return
	}
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	s.opts.OnState(st)
}

func (s *Session) logf(format string, args ...any) {
	if s.opts.Quiet || s.opts.Log == nil {
		return
	}
	s.opts.Log(fmt.Sprintf(format, args...))
}

func (s *Session) reportErr(err error) {
	if err == nil || s.opts.OnError == nil {
		return
	}
	s.opts.OnError(err)
}

// errCodeOf extracts the numeric code from an *Error (0 when there is none).
func errCodeOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}
