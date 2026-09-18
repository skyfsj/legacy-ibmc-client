package vmm

import (
	"errors"
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------
// Error codes (VMException keys / errorProcess codes in the Java)
// ---------------------------------------------------------------------------

// Numeric codes carried by *Error. They are the Java client's own keys, so the
// UI can map them to the vendor's message resources.
const (
	ErrIP           = 110 // no server address / bad port
	ErrConnect      = 103 // socket connect failed
	ErrConnectTime  = 105 // SocketTimeoutException while connecting
	ErrCertifyTime  = 121 // no answer to CERTIFY_ID within 10s
	ErrDeviceTime   = 122 // no answer to DEVICE_TYPE within 10s
	ErrNoTraffic    = 123 // 40s with no traffic in either direction
	ErrCreateDevice = 301 // neither device could be created
	ErrImageMissing = 320 // image file does not exist
	ErrImageIsDir   = 321 // path is a directory
	ErrImageOpen    = 326 // image file cannot be opened
	ErrBadPath      = 333 // empty device path
	ErrCapacity     = 335 // floppy image is not exactly 2880 * 512 bytes
	ErrDeviceInUse  = 401 // the virtual media is held by another user
	// Codes raised inside the storage layer (VMException keys in the Java).
	ErrRead         = 250 // IOException during a read
	ErrBadAddress   = 251 // address outside the medium
	ErrBadUnit      = 252 // the command is not supported by this unit
	ErrNoMedium     = 253 // no medium / image not open
	ErrWriteProtect = 254 // write attempted on a protected medium
)

// Error is a VMM protocol or device error carrying the Java client's numeric
// code. DeviceType is 0 for the console/link, 1 for the floppy, 2 for the
// CD-ROM, matching errorProcess' first argument.
type Error struct {
	Code       int
	DeviceType int
	Op         string
	Err        error
}

func (e *Error) Error() string {
	msg := e.Message()
	if e.Op != "" {
		return fmt.Sprintf("vmm: %s (%d, %s)", msg, e.Code, e.Op)
	}
	return fmt.Sprintf("vmm: %s (%d)", msg, e.Code)
}

func (e *Error) Unwrap() error { return e.Err }

// Message renders the user-facing text. The four strings below are the vendor's
// own resource strings for the codes the VMM console raises most often
// (com.huawei.vm.console.error.<code>); the rest are descriptive fallbacks.
func (e *Error) Message() string {
	switch e.Code {
	case ErrCertifyTime:
		return "服务器无响应，连接未建立"
	case ErrDeviceTime:
		return "虚拟介质设备创建失败，服务器无响应"
	case ErrNoTraffic:
		return "服务器无响应，连接已中断"
	case ErrDeviceInUse:
		return "虚拟介质已被其他用户使用"
	case ErrCapacity:
		return "软驱镜像必须恰好为 2880 × 512 字节"
	case ErrImageMissing:
		return "镜像文件不存在"
	case ErrImageIsDir:
		return "路径是目录"
	case ErrWriteProtect:
		return "介质写保护"
	case ErrNoMedium:
		return "介质不存在"
	}
	return fmt.Sprintf("虚拟介质错误 %d", e.Code)
}

// ---------------------------------------------------------------------------
// Device-level errors (VMException keys inside the storage classes)
// ---------------------------------------------------------------------------

// deviceError is the Go counterpart of the Java's VMException inside the storage
// layer; the SCSI handlers switch on its code.
type deviceError struct {
	code int
}

func (e *deviceError) Error() string { return fmt.Sprintf("vmm: device error %d", e.code) }

func derr(code int) error { return &deviceError{code: code} }

// isDeviceCode reports whether err carries the given device code.
func isDeviceCode(err error, code int) bool {
	var de *deviceError
	if errors.As(err, &de) {
		return de.code == code
	}
	return false
}

// ---------------------------------------------------------------------------
// DataArray: the blocking element queue between the reader and a SCSI handler
// ---------------------------------------------------------------------------

// dataItem is one element of the Java's DataArray: either a 12-byte SCSI
// command (carrying the transaction id) or a data block.
type dataItem struct {
	isCommand bool
	id        byte
	data      []byte
}

// dataQueue mirrors DataArray as USBProcessor uses it: a blocking list that the
// protocol reader appends to and the device handler drains.
type dataQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []dataItem
	closed bool
}

func newDataQueue() *dataQueue {
	q := &dataQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// addMore is DataArray.addMore (non-blocking, unbounded).
func (q *dataQueue) addMore(it dataItem) {
	q.mu.Lock()
	if !q.closed {
		q.items = append(q.items, it)
		q.cond.Broadcast()
	}
	q.mu.Unlock()
}

// addCommand queues a CDB. The Java's DataElement.getUSBRequestInstance only
// builds an element when the request is exactly 12 bytes, so anything else is
// dropped here as well.
func (q *dataQueue) addCommand(id byte, cdb []byte) {
	if len(cdb) != HeaderSize {
		return
	}
	q.addMore(dataItem{isCommand: true, id: id, data: append([]byte(nil), cdb...)})
}

// addData queues a data block (DataElement.getDataInstance, which requires a
// non-empty buffer).
func (q *dataQueue) addData(b []byte) {
	if len(b) == 0 {
		return
	}
	q.addMore(dataItem{isCommand: false, data: append([]byte(nil), b...)})
}

// close releases every waiter; later adds are ignored.
func (q *dataQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// nextCommand blocks until a command element is available (USBProcessor
// getCommand with DataArray.getAndRemoveFirstByBlock). Data elements are left in
// place for getData. ok is false once the queue is closed.
//
// Note: the Java's getCommand removes the *head* element and silently drops every
// data element it finds before a command, so an out-of-order data frame is lost
// and the write that was waiting for it blocks. Here the first command is taken
// and the data elements stay queued. The ordering a real BMC produces (command
// first, then data) is unaffected; only that pathological order differs.
func (q *dataQueue) nextCommand() ([]byte, byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		for i, it := range q.items {
			if it.isCommand {
				q.items = append(q.items[:i], q.items[i+1:]...)
				return it.data, it.id, true
			}
		}
		if q.closed {
			return nil, 0, false
		}
		q.cond.Wait()
	}
}

// getData mirrors USBProcessor.getData: copy whole data elements into dst until
// length bytes have been collected. It returns the number of bytes written, or 0
// when the first element is a command, when the next data block is larger than
// the remaining space (the element is left in the queue), or when the queue is
// closed.
func (q *dataQueue) getData(dst []byte, length int) int {
	if length <= 0 {
		return 0
	}
	off := 0
	q.mu.Lock()
	defer q.mu.Unlock()
	for length > 0 {
		for len(q.items) == 0 {
			if q.closed {
				return 0
			}
			q.cond.Wait()
		}
		it := q.items[0]
		if !it.isCommand {
			n := len(it.data)
			if n > length {
				return 0 // the Java breaks out with off = 0, keeping the element
			}
			q.items = q.items[1:]
			copy(dst[off:], it.data)
			off += n
			length -= n
			continue
		}
		// A command at the head: stop (the Java breaks with off = 0).
		return 0
	}
	return off
}

// getDataEncry mirrors USBProcessor.getDataEncry: the first four bytes of the
// element are the plaintext length, the rest is AES-CBC ciphertext. The
// decrypted block is truncated to the recorded length.
func (q *dataQueue) getDataEncry(dst []byte, length int, key, iv []byte) (int, error) {
	if length <= 0 {
		return 0, nil
	}
	off := 0
	q.mu.Lock()
	defer q.mu.Unlock()
	for length > 0 {
		for len(q.items) == 0 {
			if q.closed {
				return 0, nil
			}
			q.cond.Wait()
		}
		it := q.items[0]
		if it.isCommand {
			return 0, nil
		}
		if len(it.data) < 4 {
			return 0, fmt.Errorf("vmm: encrypted data element too short (%d)", len(it.data))
		}
		realLen := int(uint32(it.data[0])<<24 | uint32(it.data[1])<<16 | uint32(it.data[2])<<8 | uint32(it.data[3]))
		if realLen > length {
			return 0, nil // the Java breaks out with off = 0
		}
		q.items = q.items[1:]
		pt, err := DecryptPayload(it.data[4:], key, iv)
		if err != nil {
			return 0, err
		}
		if realLen > len(pt) {
			return 0, fmt.Errorf("vmm: plaintext length %d exceeds decrypted %d", realLen, len(pt))
		}
		copy(dst[off:], pt[:realLen])
		off += realLen
		length -= realLen
	}
	return off, nil
}

// ---------------------------------------------------------------------------
// USBProcessor: shared SCSI plumbing
// ---------------------------------------------------------------------------

// senseLength is the REQUEST SENSE payload the Java always returns (18 bytes).
const senseLength = 18

// usbProcessor mirrors USBProcessor.java: the sense template, the data buffers
// and the element queue shared by both device handlers.
type usbProcessor struct {
	wire  wire
	queue *dataQueue

	command   [HeaderSize]byte
	commandID byte

	// dataBuffer is 32768 bytes and dataBuffer2 131072 bytes in the Java
	// (USBProcessor's constructor); the CD-ROM read path uses dataBuffer2, the
	// floppy and every control command use dataBuffer.
	dataBuffer  []byte
	dataBuffer2 []byte

	// senseData is the REQUEST SENSE template:
	// 70 00 00 06 00 00 00 0A 00 00 00 00 29 00 00 00 00 00
	// setSenseKeys overwrites [0], [2], [3..6], [12] and [13].
	//
	// Note the initial byte 3 = 0x06 and ASC = 0x29 (power-on/reset), which the
	// Java only clears once the first command sets sense keys.
	senseData [senseLength]byte

	mu     sync.Mutex
	closed bool

	// exitFlag mirrors USBProcessor.exitFlag: set by setExit, checked by the
	// data-assembly loops.
	exitFlag bool

	// onCommand is the per-command hook used by the pre-send commands
	// (c.getChangeDisk in the Java); installed by the concrete handlers.
	onCommand func()
}

func newUSBProcessor(w wire) *usbProcessor {
	p := &usbProcessor{
		wire:        w,
		queue:       newDataQueue(),
		dataBuffer:  make([]byte, 32768),
		dataBuffer2: make([]byte, 131072),
	}
	p.senseData = [senseLength]byte{0x70, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00}
	return p
}

// setSenseKeys is USBProcessor.setSenseKeys. information != 0 flips byte 0 to
// 0xF0 and stores the value in bytes 3..6.
func (p *usbProcessor) setSenseKeys(senseKey, asc, ascq, information int) {
	if information == 0 {
		p.senseData[0] = 0x70
		p.senseData[3] = 0
		p.senseData[4] = 0
		p.senseData[5] = 0
		p.senseData[6] = 0
	} else {
		p.senseData[0] = 0xF0
		p.senseData[3] = byte(information >> 24)
		p.senseData[4] = byte(information >> 16)
		p.senseData[5] = byte(information >> 8)
		p.senseData[6] = byte(information)
	}
	p.senseData[2] = byte(senseKey)
	p.senseData[12] = byte(asc)
	p.senseData[13] = byte(ascq)
}

// getSenseKey is USBProcessor.getSenseKey.
func (p *usbProcessor) getSenseKey() byte { return p.senseData[2] }

// stop ends the handler loop (USBProcessor.setExit).
func (p *usbProcessor) stop() {
	p.mu.Lock()
	p.exitFlag = true
	p.mu.Unlock()
	p.queue.close()
}

// isStopped reports whether stop was called (thread-safe view of exitFlag).
func (p *usbProcessor) isStopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitFlag
}

// enqueueCommand feeds a CDB from the reader.
func (p *usbProcessor) enqueueCommand(id byte, cdb []byte) { p.queue.addCommand(id, cdb) }

// enqueueData feeds a data block from the reader.
func (p *usbProcessor) enqueueData(b []byte) { p.queue.addData(b) }

// getData is USBProcessor.getData: collect whole data elements into dst.
func (p *usbProcessor) getData(dst []byte, length int) int { return p.queue.getData(dst, length) }

// getDataEncry is USBProcessor.getDataEncry: same, with the encrypted element
// framing (4-byte plaintext length + ciphertext).
func (p *usbProcessor) getDataEncry(dst []byte, length int, key, iv []byte) (int, error) {
	return p.queue.getDataEncry(dst, length, key, iv)
}

// run is USBProcessor's run loop: take the next command and process it.
func (p *usbProcessor) run(process func()) {
	for {
		cdb, id, ok := p.queue.nextCommand()
		if !ok {
			return
		}
		p.mu.Lock()
		stopped := p.exitFlag
		if !stopped {
			copy(p.command[:], cdb)
			p.commandID = id
		}
		p.mu.Unlock()
		if stopped {
			return
		}
		process()
	}
}

// ---------------------------------------------------------------------------
// Storage devices
// ---------------------------------------------------------------------------

// scsiDevice is the storage surface the SCSI handlers need: the union of
// MassStorageDevice's abstract methods plus CDROMDriver/FloppyDriver specifics.
// It is unexported on purpose — the public API exposes *CDROM and *Floppy.
type scsiDevice interface {
	// mediumSize is getMediumSize; a closed/missing medium returns an error
	// carrying errNoMedium, like the Java's VMException(253).
	mediumSize() (int64, error)
	read(buf []byte, off int64, n int) (int, error)
	// testUnitReady mirrors MassStorageDevice.testUnitReady, including its
	// side effect of writing the media state back.
	testUnitReady() int
	setMediaState(state int)
	mediaState() int
	modeSense(buf []byte, pc, pageCode int) int
	refreshState()
	isInited() bool
	isWriteProtect() bool
	close() error
	blockLength() int
	totalBlocks() int
}

// baseDevice mirrors MassStorageDevice: the device name, the write-protect
// flag, the media state and the disk-change protocol.
type baseDevice struct {
	name        string
	wp          bool
	media       int // deviceState, default 3 = STATE_MEDIUM_READY
	diskChanged bool
	newDiskName string
	needInit    bool
}

const (
	stateMediumNotPresent = 0
	stateMediumChange     = 2
	stateMediumReady      = 3
	stateNotReady         = 4
	stateBadMedia         = 5
)

func (d *baseDevice) mediaState() int      { return d.media }
func (d *baseDevice) setMediaState(s int)  { d.media = s }
func (d *baseDevice) isWriteProtect() bool { return d.wp }

// testUnitReady is MassStorageDevice.testUnitReady, verbatim:
//
//	size < 0 && media == 3          -> 2 (medium change)
//	size < 0 && (media == 2|0)      -> 0 (not present)
//	size < 0 && media == 4|5        -> 3 (!) the Java leaves curState at 3
//	size >= 0 && media == 0         -> 2
//	size >= 0 otherwise             -> 3
//
// and the result is stored back into the media state.
func (d *baseDevice) testUnitReady(size int64, err error) int {
	cur := stateMediumReady
	if err != nil || size < 0 {
		switch d.media {
		case stateMediumReady:
			cur = stateMediumChange
		case stateMediumChange, stateMediumNotPresent:
			cur = stateMediumNotPresent
		}
	} else if d.media == stateMediumNotPresent {
		cur = stateMediumChange
	}
	d.setMediaState(cur)
	return cur
}

// isChangeDisk consumes the pending disk-change flag (MassStorageDevice),
// including the Java's finally-block reset.
func (d *baseDevice) isChangeDisk() bool {
	changed := d.diskChanged
	d.diskChanged = false
	return changed
}

func (d *baseDevice) isEject() bool { return d.newDiskName == "" }

// ---------------------------------------------------------------------------
// wire: what the SCSI layer needs from the session
// ---------------------------------------------------------------------------

// wire mirrors CommunicationSender + the VMConsole getters the processors use.
type wire interface {
	// send is CommunicationSender.send: hand one complete frame to the socket.
	send(frame []byte) error
	// isStopped is CommunicationSender.getExit.
	isStopped() bool
	// encryptPayloads is VMConsole.getVmm_compress_state.
	encryptPayloads() bool
	// secret is VMConsole.getSecretKey / getSecretIvBMC.
	secret() (key, iv []byte)
}

// ---------------------------------------------------------------------------
// Small helpers shared by the handlers
// ---------------------------------------------------------------------------

// logf reports a line through the session's logger when the wire behind it
// offers one (the test wire does not).
func logf(w wire, format string, args ...any) {
	if l, ok := w.(interface{ logf(string, ...any) }); ok {
		l.logf(format, args...)
	}
}
