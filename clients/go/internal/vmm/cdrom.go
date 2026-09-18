package vmm

import (
	"errors"
	"io"
	"os"
	"sync"
)

// ---------------------------------------------------------------------------
// ISO-backed CD-ROM (CDROMImage + CDROMDriver + ImageIO)
// ---------------------------------------------------------------------------

// blockLength is CDROMDriver.BLOCK_LENGTH: a CD-ROM sector is 2048 bytes and
// the SCSI layer assumes that everywhere.
const blockLength = 2048

// CDROM is the ISO-file-backed CD-ROM device (the Java's CDROMImage, srcType 1).
//
// The image is opened read-only, exactly like ImageIO.open(path, mustExist)
// does; CDROMDriver.setWriteProtect forces write protection on regardless.
type CDROM struct {
	baseDevice

	mu         sync.Mutex
	file       *os.File
	size       int64 // -1 once closed
	zeroOffset int   // CPQRFBLO header offset (see openFile)
}

// OpenISO opens an ISO image as a virtual CD-ROM. The error carries the Java
// client's code (320 missing, 321 directory, 326 open failure).
func OpenISO(path string) (*CDROM, error) {
	c := &CDROM{}
	c.wp = true // CDROMDriver.setWriteProtect always forces this true
	c.media = stateMediumReady
	c.name = path
	if err := c.open(path); err != nil {
		return nil, err
	}
	return c, nil
}

// Path returns the image path.
func (c *CDROM) Path() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.name
}

// open mirrors ImageIO.open(path, mustExist) without the create-if-missing path
// (the vendor only creates images for a local directory, which is JNI/UDF code
// that is out of scope here).
func (c *CDROM) open(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		_ = c.file.Close()
		c.file = nil
		c.size = -1
	}
	if path == "" {
		return &Error{Code: ErrBadPath, DeviceType: DeviceCDROM, Op: "open"}
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Error{Code: ErrImageMissing, DeviceType: DeviceCDROM, Op: "open", Err: err}
		}
		return &Error{Code: ErrImageOpen, DeviceType: DeviceCDROM, Op: "open", Err: err}
	}
	if st.IsDir() {
		return &Error{Code: ErrImageIsDir, DeviceType: DeviceCDROM, Op: "open"}
	}
	f, err := os.Open(path) // ImageIO's "r" mode
	if err != nil {
		return &Error{Code: ErrImageOpen, DeviceType: DeviceCDROM, Op: "open", Err: err}
	}
	c.file = f
	c.name = path
	c.zeroOffset = 0
	// ImageIO probes the first 512 bytes for a "CPQRFBLO" (Compaq SoftPaq)
	// header and skips the little-endian offset stored at bytes 14..15.
	var head [512]byte
	n, _ := f.ReadAt(head[:], 0)
	if n >= 512 && string(head[0:8]) == "CPQRFBLO" {
		// The Java is `head[14] & 0xFF | head[15] << 8`, where head[15] is a
		// signed byte; a high bit therefore produces a negative shift. Ported
		// as-is.
		c.zeroOffset = int(head[14])&0xFF | int(int8(head[15]))<<8
	}
	if fi, err := f.Stat(); err == nil {
		c.size = fi.Size() - int64(c.zeroOffset)
	} else {
		c.size = -1
	}
	return nil
}

// openFn is the MassStorageDevice.open hook used by refreshState.
func (c *CDROM) openFn(path string) error { return c.open(path) }

// Close releases the image.
func (c *CDROM) Close() error { return c.close() }

func (c *CDROM) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		err := c.file.Close()
		c.file = nil
		c.size = -1
		return err
	}
	return nil
}

// mediumSize is ImageIO.getMediumSize: -1 (here: ErrNoMedium) when closed.
func (c *CDROM) mediumSize() (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return -1, derr(ErrNoMedium)
	}
	if c.size < 0 {
		if fi, err := c.file.Stat(); err == nil {
			c.size = fi.Size() - int64(c.zeroOffset)
		}
	}
	if c.size < 0 {
		return -1, derr(ErrNoMedium)
	}
	return c.size, nil
}

// read is ImageIO.read: seek to startPosition + zeroOffset and fill buf[0:n].
// EOF yields 0 rather than an error (RandomAccessFile.read returns -1, which the
// Java turns into 0).
func (c *CDROM) read(buf []byte, off int64, n int) (int, error) {
	c.mu.Lock()
	f := c.file
	z := int64(c.zeroOffset)
	c.mu.Unlock()
	if f == nil {
		return 0, derr(ErrNoMedium)
	}
	if n <= 0 {
		return 0, nil
	}
	if n > len(buf) {
		n = len(buf)
	}
	got, err := f.ReadAt(buf[:n], off+z)
	if err != nil && !errors.Is(err, io.EOF) {
		return got, derr(ErrRead)
	}
	return got, nil
}

// isInited is CDROMImage.isInited: `!needInit || image.isActive()`. Note this is
// the opposite shape of the floppy's version.
func (c *CDROM) isInited() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.needInit || c.file != nil
}

func (c *CDROM) blockLength() int { return blockLength }
func (c *CDROM) totalBlocks() int {
	if size, err := c.mediumSize(); err == nil {
		return int(size / blockLength)
	}
	return 0
}

func (c *CDROM) testUnitReady() int {
	size, err := c.mediumSize()
	return c.baseDevice.testUnitReady(size, err)
}

// refreshState is MassStorageDevice.refreshState: reopen the image if it is not
// active, and drop to "not present" on any failure.
func (c *CDROM) refreshState() {
	if c.isInited() {
		return
	}
	if err := c.open(c.Path()); err != nil {
		c.setMediaState(stateMediumNotPresent)
		return
	}
	c.setMediaState(stateMediumNotPresent)
}

// modeSense is CDROMImage.modeSense: always the same 8 bytes, with byte 2 set
// to 1 when the unit reports ready and 0x70 (112) otherwise. Note that the Java
// calls testUnitReady() here, which has the side effect of rewriting the media
// state.
func (c *CDROM) modeSense(buf []byte, pc, pageCode int) int {
	if len(buf) < 8 {
		return 0
	}
	buf[0] = 0
	buf[1] = 6
	if c.testUnitReady() != 0 {
		buf[2] = 1
	} else {
		buf[2] = 112
	}
	buf[3], buf[4], buf[5], buf[6], buf[7] = 0, 0, 0, 0, 0
	return 8
}

// startStopUnit is CDROMImage.startStopUnit: (eject && !start) unloads the disk,
// (eject && start) re-inserts it, everything else raises VMException(252).
func (c *CDROM) startStopUnit(isEject, isStart bool) error {
	switch {
	case isEject && !isStart:
		c.setMediaState(stateMediumNotPresent)
		c.needInit = false
	case isEject && isStart:
		c.setMediaState(stateMediumReady)
		c.needInit = true
	default:
		return derr(ErrBadUnit)
	}
	return nil
}

// preventAllowMediumRemoval is CDROMImage's unconditional true.
func (c *CDROM) preventAllowMediumRemoval(prevent bool) bool { return true }

// eject is CDROMImage.eject: drop the name, stop the image.
func (c *CDROM) eject() {
	c.mu.Lock()
	c.name = ""
	c.needInit = false
	c.mu.Unlock()
	_ = c.close()
	c.setMediaState(stateMediumNotPresent)
}

// insert is CDROMImage.insert: adopt the pending image (already swapped by
// changeDisk), drop to "not present" so the next command reports UNIT ATTENTION
// (sense 6/40), and mark the image for reopen.
func (c *CDROM) insert() error {
	if c.newDiskName != "" {
		c.setMediaState(stateMediumNotPresent)
	}
	c.needInit = true
	return nil
}

// changeDisk arms a new image, mirroring CDROMImage.prepareChangeDisk (the new
// ImageIO is opened eagerly so a bad path fails here).
//
// The Java drops the previous ImageIO without closing it (the RandomAccessFile
// is only finalized when the object is collected); the handle is closed here, a
// resource fix that does not change the wire behaviour.
func (c *CDROM) changeDisk(path string) error {
	if path != "" {
		n, err := OpenISO(path)
		if err != nil {
			return err
		}
		c.mu.Lock()
		old := c.file
		c.file = n.file
		c.size = n.size
		c.zeroOffset = n.zeroOffset
		c.name = path
		c.mu.Unlock()
		n.file = nil // ownership moved
		if old != nil {
			_ = old.Close()
		}
	}
	// MassStorageDevice.changeDisk only arms the swap; the media state is reset
	// by insert() (CDROMImage.insert does setDeviceState(0)).
	c.newDiskName = path
	c.diskChanged = true
	return nil
}

// readTOC is CDROMDriver.readTOC, ported including the arithmetic on the
// medium size and the three supported formats (0, 1, 2); anything else raises
// VMException(252).
//
// startTrack is signed like the Java's `byte startTrack = command[6]`: a value
// with bit 7 set (0xAA = the lead-out track) is negative there, which makes both
// `startTrack > 1` and `startTrack != 170` false when 170 is compared against a
// sign-extended byte, and `startTrack <= 1` true. The comparisons below keep
// that behaviour.
func (c *CDROM) readTOC(buf []byte, isMSF bool, format int, startTrack int8) (int, error) {
	size, err := c.mediumSize()
	if err != nil {
		return 0, derr(ErrNoMedium)
	}
	totalBlocks := int(size / blockLength)
	// i = totalBlocks / 75 + 2 seconds; m:s:f is its MSF form.
	i := float64(totalBlocks)/75.0 + 2.0
	m := int(i) / 60
	s := int(i) % 60
	f := int((i - float64(int(i))) * 75.0)
	n := 4
	switch format {
	case 0:
		if int(startTrack) > 1 && int(startTrack) != 170 {
			return 0, derr(ErrBadUnit)
		}
		buf[2] = 1
		buf[3] = 1
		if int(startTrack) <= 1 {
			buf[n] = 0
			n++
			buf[n] = 20
			n++
			buf[n] = 1
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			if isMSF {
				buf[n] = 2
			} else {
				buf[n] = 0
			}
			n++
			buf[n] = 0
			n++
		}
		buf[n] = 0
		n++
		buf[n] = 20
		n++
		buf[n] = 0xAA
		n++
		buf[n] = 0
		n++
		if !isMSF {
			buf[n] = byte(totalBlocks >> 24 & 0xFF)
			n++
			buf[n] = byte(totalBlocks >> 16 & 0xFF)
			n++
			buf[n] = byte(totalBlocks >> 8 & 0xFF)
			n++
			buf[n] = byte(totalBlocks & 0xFF)
			n++
		} else {
			buf[n] = 0
			n++
			buf[n] = byte(m)
			n++
			buf[n] = byte(s)
			n++
			buf[n] = byte(f)
			n++
		}
	case 1:
		buf[2] = 1
		buf[3] = 1
		for i := 0; i < 8; i++ {
			buf[n] = 0
			n++
		}
	case 2:
		buf[2] = 1
		buf[3] = 1
		for j := 0; j < 4; j++ {
			buf[n] = 1
			n++
			buf[n] = 20
			n++
			buf[n] = 0
			n++
			if j < 3 {
				buf[n] = byte(160 + j)
			} else {
				buf[n] = 1
			}
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			if j < 2 {
				buf[n] = 0
				n++
				buf[n] = 1
				n++
				buf[n] = 0
				n++
				buf[n] = 0
				n++
				continue
			}
			if j == 2 {
				if isMSF {
					buf[n] = 0
					n++
					buf[n] = byte(m)
					n++
					buf[n] = byte(s)
					n++
					buf[n] = byte(f)
					n++
				} else {
					buf[n] = byte(totalBlocks >> 24 & 0xFF)
					n++
					buf[n] = byte(totalBlocks >> 16 & 0xFF)
					n++
					buf[n] = byte(totalBlocks >> 8 & 0xFF)
					n++
					buf[n] = byte(totalBlocks & 0xFF)
					n++
				}
				continue
			}
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
			buf[n] = 0
			n++
		}
	default:
		return 0, derr(ErrBadUnit)
	}
	buf[0] = byte((n - 2) >> 8 & 0xFF)
	buf[1] = byte((n - 2) & 0xFF)
	return n, nil
}

// ---------------------------------------------------------------------------
// SFF-8020i command handler (SFF8020iProcessor)
// ---------------------------------------------------------------------------

// inquiryData is SFF8020iProcessor.inquiryData (36 bytes): header 05 80 00 21
// 1F 00 00 00 followed by the 28-character vendor string.
var cdromInquiry = []byte{
	0x05, 0x80, 0x00, 0x21, 0x1F, 0x00, 0x00, 0x00,
	'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'D', 'V', 'D', '-', 'R', 'O', 'M', ' ',
	'V', 'M', ' ', '1', '.', '1', '.', '0', ' ', '2', '2', '5',
}

// readErrLimit is SFF8020iProcessor.READ_ERR_LIMIT.
const readErrLimit = 2

// sffHandler is SFF8020iProcessor: the CD-ROM command dispatcher.
type sffHandler struct {
	*usbProcessor
	cdrom *CDROM

	cacheBlockNum int
	cacheLba      int64

	readErrNum       int
	readErrAreaBegin int64
	readErrAreaEnd   int64
}

func newSFFHandler(w wire, c *CDROM) *sffHandler {
	h := &sffHandler{cdrom: c}
	h.usbProcessor = newUSBProcessor(w)
	return h
}

// run is SFF8020iProcessor.run.
func (h *sffHandler) run() { h.usbProcessor.run(h.processCommand) }

// handle runs one CDB synchronously. The run loop does the same after taking a
// command off the queue; tests call this directly.
func (h *sffHandler) handle(cdb []byte, id byte) {
	h.mu.Lock()
	copy(h.command[:], cdb)
	h.commandID = id
	h.mu.Unlock()
	h.processCommand()
}

// processCommand is SFF8020iProcessor.processCommand, minus the blocking
// getCommand (the run loop already did that).
func (h *sffHandler) processCommand() {
	h.checkChangeDisk()
	if h.isStopped() {
		return
	}
	h.cdrom.refreshState()
	switch h.command[0] {
	case 0x12:
		h.doInquiry()
	case 0x55: // 85 MODE_SELECT
		paramListLength := GetInt16Bits(h.command[:], 8)
		if paramListLength != h.getData(h.dataBuffer, paramListLength) {
			h.setSenseKeys(5, 26, 0, 0)
		} else {
			h.setSenseKeys(0, 0, 0, 0)
		}
	case 0x5A: // 90 MODE_SENSE
		h.doModeSense()
	case 0x1E: // 30 PREVENT_ALLOW_MEDIUM_REMOVAL
		h.doPreventAllowMediumRemoval()
	case 0x28, 0xA8: // 40 READ_10, 168 READ_12
		h.doRead()
	case 0x25: // 37 READ_CAPACITY
		h.doReadCapacity()
	case 0xBE: // 190 READ_CD
		h.setSenseKeys(5, 36, 0, 0)
	case 0xB9: // 185 READ_CD_MSF
		h.setSenseKeys(5, 36, 0, 0)
	case 0x44: // 68 READ_HEADER
		h.setSenseKeys(5, 36, 0, 0)
	case 0x42: // 66 READ_SUB_CHANNEL
		h.setSenseKeys(5, 36, 0, 0)
	case 0x43: // 67 READ_TOC
		h.doReadToc()
	case 0x03: // REQUEST_SENSE
		h.sendData(senseLength, h.senseData[:], true)
	case 0x2B: // 43 SEEK_10
		h.setSenseKeys(0, 0, 0, 0)
	case 0x1B: // 27 START_STOP_UNIT
		h.doStartStopUnit()
	case 0x00, 0x4A: // TEST_UNIT_READY, TEST_UNIT_READY_EXP
		h.doTestUnitRead()
	default:
		// Unsupported opcodes (including every write command: the CD-ROM has
		// no write path) raise ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE.
		h.setSenseKeys(5, 36, 0, 0)
	}
	h.commandFinish()
}

// checkChangeDisk is SFF8020iProcessor.checkChangeDisk.
func (h *sffHandler) checkChangeDisk() {
	if !h.cdrom.isChangeDisk() {
		return
	}
	if h.cdrom.isEject() {
		h.cdrom.eject()
	} else if err := h.cdrom.insert(); err != nil {
		h.logf("换盘失败: %v", err)
	}
}

func (h *sffHandler) doInquiry() {
	h.sendData(len(cdromInquiry), cdromInquiry, true)
	h.setSenseKeys(0, 0, 0, 0)
}

func (h *sffHandler) doModeSense() {
	// Note the Java's `command[2] >> 6 & 0xFF` on a signed byte; for pc values
	// 0..3 the mask makes it identical to the unsigned shift.
	pc := int(int8(h.command[2])) >> 6 & 0xFF
	length := h.cdrom.modeSense(h.dataBuffer, pc, int(h.command[2]&0x3F))
	if length == 0 {
		h.setSenseKeys(5, 36, 0, 0)
		return
	}
	h.setSenseKeys(0, 0, 0, 0)
	h.sendData(length, h.dataBuffer, true)
}

func (h *sffHandler) doPreventAllowMediumRemoval() {
	isPrevent := h.command[4]&1 == 1
	if h.cdrom.preventAllowMediumRemoval(isPrevent) {
		h.setSenseKeys(0, 0, 0, 0)
	} else {
		h.setSenseKeys(5, 36, 0, 0)
	}
}

// doRead is SFF8020iProcessor.doRead. The cache fields implement the Java's
// read-ahead: after serving a request it reads the *next* block window into
// dataBuffer2 and remembers (lba+blockNum, blockNum), so a sequential request
// hits the cache and is answered without touching the file.
func (h *sffHandler) doRead() {
	cmd := h.command[:]
	lba := int64(GetInt32Bits(cmd, 3))
	var blockNum int
	if cmd[0] == 0x28 {
		blockNum = GetInt16Bits(cmd, 8) // READ_10: bytes 7..8
	} else {
		blockNum = GetInt32Bits(cmd, 7) // READ_12: bytes 6..9
	}
	length := blockNum * blockLength
	if h.cacheBlockNum != 0 && h.cacheBlockNum == blockNum && h.cacheLba != 0 && h.cacheLba == lba {
		h.sendData(length, h.dataBuffer2, true)
		h.setSenseKeys(0, 0, 0, 0)
	} else {
		curRead := h.read(lba, blockNum, false)
		if curRead <= 0 {
			return
		}
		h.sendData(curRead, h.dataBuffer2, true)
		h.setSenseKeys(0, 0, 0, 0)
	}
	h.cacheBlockNum = blockNum
	h.cacheLba = lba + int64(blockNum)
	h.read(h.cacheLba, h.cacheBlockNum, true)
}

// read is SFF8020iProcessor.read. cache == true is the read-ahead: it never
// touches the sense data and never reports an error.
func (h *sffHandler) read(lba int64, blockNum int, cache bool) int {
	startPos := lba * blockLength
	length := blockNum * blockLength
	curRead := 0
	if h.readErrNum >= readErrLimit && h.readErrAreaBegin <= lba && lba < h.readErrAreaEnd {
		if !cache {
			h.setSenseKeys(3, 16, 0, int(startPos/blockLength))
		}
		h.cacheBlockNum = 0
		h.cacheLba = 0
		return curRead
	}
	size, err := h.cdrom.mediumSize()
	if err != nil {
		return h.readError(startPos, lba, blockNum, cache, curRead, err)
	}
	if startPos < 0 || startPos >= size {
		h.logf("SFF 读地址越界 (lba=%d)", lba)
		if !cache {
			h.setSenseKeys(5, 33, 0, 0)
		}
		h.cacheBlockNum = 0
		h.cacheLba = 0
		return curRead
	}
	readLength := len(h.dataBuffer2)
	if readLength > length {
		readLength = length
	}
	curRead, err = h.cdrom.read(h.dataBuffer2, startPos, readLength)
	if err != nil {
		return h.readError(startPos, lba, blockNum, cache, curRead, err)
	}
	if curRead == readLength {
		length -= readLength
	} else {
		length = -1
	}
	if length == 0 {
		if !cache {
			h.setSenseKeys(0, 0, 0, 0)
		}
	} else {
		h.logf("SFF 读越界（多于一个缓冲区，%d 字节）", length)
		if !cache {
			h.setSenseKeys(5, 33, 0, 0)
		}
		h.cacheBlockNum = 0
		h.cacheLba = 0
	}
	h.readErrNum = 0
	return curRead
}

// readError is the Java's catch (VMException) block inside read().
func (h *sffHandler) readError(startPos int64, lba int64, blockNum int, cache bool, curRead int, err error) int {
	h.cacheBlockNum = 0
	h.cacheLba = 0
	switch {
	case isDeviceCode(err, ErrRead):
		h.logf("SFF 读错误 (ID CRC ERROR)")
		if !cache {
			h.setSenseKeys(3, 16, 0, int(startPos/blockLength))
		}
		h.readErrNum++
		h.readErrAreaBegin = lba
		h.readErrAreaEnd = lba + int64(blockNum)
		return curRead
	case isDeviceCode(err, ErrBadAddress):
		if !cache {
			h.setSenseKeys(5, 33, 0, 0)
		}
		return curRead
	case isDeviceCode(err, ErrNoMedium):
		h.cdrom.setMediaState(stateMediumNotPresent)
		if !cache {
			h.setSenseKeys(2, 58, 0, 0)
		}
		return curRead
	}
	if !cache {
		h.setSenseKeys(5, 36, 0, 0)
	}
	return curRead
}

// doReadCapacity is SFF8020iProcessor.doReadCapacity: an 8-byte response with
// the last LBA and a 2048-byte block length (bytes 6..7 = 0x0800).
func (h *sffHandler) doReadCapacity() {
	switch h.cdrom.testUnitReady() {
	case 0:
		h.setSenseKeys(2, 58, 0, 0)
	case 2:
		h.setSenseKeys(6, 40, 0, 0)
	case 3:
		size, err := h.cdrom.mediumSize()
		if err != nil {
			h.cdrom.setMediaState(stateMediumNotPresent)
			h.setSenseKeys(2, 58, 0, 0)
			return
		}
		lba := size/blockLength - 1
		IntToByte(h.dataBuffer, 0, int(lba))
		h.dataBuffer[4] = 0
		h.dataBuffer[5] = 0
		h.dataBuffer[6] = 8
		h.dataBuffer[7] = 0
		h.setSenseKeys(0, 0, 0, 0)
		h.sendData(8, h.dataBuffer, true)
	}
}

// doReadToc is SFF8020iProcessor.doReadToc, including the Java's fall-through:
// a VMException(252) sets sense 5/36 *and then* the block continues with
// setDeviceState(0) + sense 2/58, so 252 ends up reported as NOT READY.
func (h *sffHandler) doReadToc() {
	cmd := h.command[:]
	isMSF := cmd[1]&2 == 2
	format := int(cmd[2] & 7)
	if format == 0 {
		format = int(cmd[9] >> 6 & 3)
	}
	allocLength := GetInt16Bits(cmd, 8)
	// The Java reads this byte as signed (`byte startTrack = command[6]`); see
	// readTOC for why that matters.
	startTrack := int8(cmd[6])
	tocDataLen := 0
	n, err := h.cdrom.readTOC(h.dataBuffer, isMSF, format, startTrack)
	if err != nil {
		if isDeviceCode(err, ErrBadUnit) {
			h.setSenseKeys(5, 36, 0, 0)
		}
		h.cdrom.setMediaState(stateMediumNotPresent)
		h.setSenseKeys(2, 58, 0, 0)
	} else {
		tocDataLen = n
		h.setSenseKeys(0, 0, 0, 0)
	}
	if allocLength < tocDataLen {
		tocDataLen = allocLength
	}
	h.sendData(tocDataLen, h.dataBuffer, true)
}

func (h *sffHandler) doStartStopUnit() {
	isEject := h.command[4]&2 == 2
	isStart := h.command[4]&1 == 1
	if err := h.cdrom.startStopUnit(isEject, isStart); err != nil {
		h.setSenseKeys(5, 36, 0, 0)
		return
	}
	h.setSenseKeys(0, 0, 0, 0)
}

// doTestUnitRead is SFF8020iProcessor.doTestUnitRead (shared by opcodes 0 and
// 74).
func (h *sffHandler) doTestUnitRead() {
	switch h.cdrom.testUnitReady() {
	case 2:
		h.cdrom.setMediaState(stateMediumChange)
		h.setSenseKeys(6, 40, 0, 0)
		h.readErrNum = 0
	case 3:
		h.cdrom.setMediaState(stateMediumReady)
		h.setSenseKeys(0, 0, 0, 0)
	case 5:
		h.cdrom.setMediaState(stateMediumNotPresent)
		h.setSenseKeys(2, 48, 0, 0)
		h.readErrNum = 0
	case 4:
		h.cdrom.setMediaState(stateMediumChange)
		h.setSenseKeys(2, 4, 0, 0)
		h.readErrNum = 0
	default:
		h.cdrom.setMediaState(stateMediumNotPresent)
		h.setSenseKeys(2, 58, 0, 0)
		h.readErrNum = 0
	}
}

// sendData is SFF8020iProcessor.sendData: split the buffer into chunks of at
// most CDROM_PACKET_SIZE, encrypting each chunk when vmm_compress is on, and
// mark the last chunk with state END. A zero-length call with isLast still emits
// a 12-byte END frame with length 0, which the SFF side allows.
func (h *sffHandler) sendData(dataLength int, dataBuffer []byte, isLast bool) {
	if h.isStopped() {
		return
	}
	if dataLength == 0 && isLast {
		h.writeFrame(SFFDataPak(SubData, SubEnd, 0, int(h.commandID)))
	}
	off := 0
	for dataLength > 0 && !h.isStopped() {
		var curLength, state int
		if CDROMPacketSize < dataLength {
			curLength, state = CDROMPacketSize, SubContinue
		} else {
			curLength = dataLength
			if isLast {
				state = SubEnd
			} else {
				state = SubContinue
			}
		}
		if off+curLength > len(dataBuffer) {
			h.logf("SFF 发送缓冲不足: off=%d len=%d", off, curLength)
			return
		}
		chunk := dataBuffer[off : off+curLength]
		var frame []byte
		if h.wire.encryptPayloads() {
			key, iv := h.wire.secret()
			body, err := WrapPayload(chunk, key, iv)
			if err != nil || len(body) == 0 {
				h.logf("SFF 加密失败: %v", err)
				return
			}
			hdr := SFFDataPak(SubData, state, len(body), int(h.commandID))
			frame = make([]byte, 0, HeaderSize+len(body))
			frame = append(frame, hdr...)
			frame = append(frame, body...)
		} else {
			body := chunk
			hdr := SFFDataPak(SubData, state, curLength, int(h.commandID))
			frame = make([]byte, 0, HeaderSize+len(body))
			frame = append(frame, hdr...)
			frame = append(frame, body...)
		}
		h.writeFrame(frame)
		off += curLength
		dataLength -= curLength
	}
}

// commandFinish is SFF8020iProcessor.commandFinish: result 1 when a sense key
// is pending (unless this *is* REQUEST_SENSE) or for TEST_UNIT_READY_EXP (74),
// which always reports failure.
func (h *sffHandler) commandFinish() {
	result := 0
	if (h.getSenseKey() != 0 && h.command[0] != 0x03) || h.command[0] == 0x4A {
		result = 1
	}
	pack := make([]byte, HeaderSize)
	SFFCmpltPak(pack, 0, result, int(h.commandID))
	h.writeFrame(pack)
}

// writeFrame sends one frame and logs a failure. The Java's sendData spins
// (`while (!flag && !exitFlag) sleep(100)`) until the frame is queued; here a
// write error means the socket is gone, which tears the session down anyway, so
// the error is logged instead of retried forever.
func (h *sffHandler) writeFrame(frame []byte) {
	if err := h.wire.send(frame); err != nil && !h.isStopped() {
		h.logf("SFF 发送失败: %v", err)
	}
}

func (h *sffHandler) logf(format string, args ...any) { logf(h.wire, format, args...) }
