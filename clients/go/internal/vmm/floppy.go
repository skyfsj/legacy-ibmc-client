package vmm

import (
	"errors"
	"io"
	"os"
	"sync"
)

// ---------------------------------------------------------------------------
// IMG-backed floppy (FloppyImage + FloppyDriver + ImageIO)
// ---------------------------------------------------------------------------

// Floppy geometry (FloppyDriver): the vendor only ever presents a 1.44 MB
// 3.5" disk, and FloppyImage refuses any image whose size is not exactly
// TOTAL_BLOCKS * BLOCK_LENGTH.
const (
	floppyMediumTypeCode = 148
	floppyTotalBlocks    = 2880
	floppyBlockLength    = 512
	// FloppyImageSize is the only accepted .img size: 2880 * 512 = 1474560.
	FloppyImageSize = floppyTotalBlocks * floppyBlockLength
)

// Floppy is the .img-file-backed floppy device (the Java's FloppyImage,
// srcType 1).
type Floppy struct {
	baseDevice

	mu         sync.Mutex
	file       *os.File
	size       int64
	zeroOffset int
	canWrite   bool
}

// OpenFloppy opens a floppy image. writeProtect mirrors the vendor UI's
// "write protect" checkbox (VirtualMedia.isFWP); MassStorageDevice's default is
// protected, and the image file's own writability can only make it *more*
// protected (FloppyImage.isWriteProtect).
//
// The image size must be exactly 1474560 bytes (2880 x 512), otherwise the
// error carries code 335 like FloppyImage.validCapacity.
func OpenFloppy(path string, writeProtect bool) (*Floppy, error) {
	f := &Floppy{}
	f.wp = writeProtect
	f.media = stateMediumReady
	f.needInit = true
	f.name = path
	if err := f.open(path); err != nil {
		return nil, err
	}
	if int64(floppyBlockLength*floppyTotalBlocks) != f.size {
		_ = f.close()
		return nil, &Error{
			Code: ErrCapacity, DeviceType: DeviceFloppy, Op: "open",
			Err: errors.New("floppy image size mismatch"),
		}
	}
	return f, nil
}

// Path returns the image path.
func (f *Floppy) Path() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.name
}

// open mirrors ImageIO.open(path, mustExist, isFloppy): the file is opened
// read-write when it is writable, read-only otherwise.
func (f *Floppy) open(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file != nil {
		_ = f.file.Close()
		f.file = nil
		f.size = -1
	}
	if path == "" {
		return &Error{Code: ErrBadPath, DeviceType: DeviceFloppy, Op: "open"}
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Error{Code: ErrImageMissing, DeviceType: DeviceFloppy, Op: "open", Err: err}
		}
		return &Error{Code: ErrImageOpen, DeviceType: DeviceFloppy, Op: "open", Err: err}
	}
	if st.IsDir() {
		return &Error{Code: ErrImageIsDir, DeviceType: DeviceFloppy, Op: "open"}
	}
	// ImageIO.open(..., isFloppy=true) switches to read-write only when
	// File.canWrite() says so, and keeps "r" otherwise. Trying O_RDWR first and
	// falling back mirrors canWrite() (which uses access(2), not the mode bits).
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	canWrite := err == nil
	if err != nil {
		file, err = os.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return &Error{Code: ErrImageOpen, DeviceType: DeviceFloppy, Op: "open", Err: err}
		}
	}
	f.file = file
	f.name = path
	f.canWrite = canWrite
	f.zeroOffset = 0
	var head [512]byte
	n, _ := file.ReadAt(head[:], 0)
	if n >= 512 && string(head[0:8]) == "CPQRFBLO" {
		// Same signed-byte quirk as the CD-ROM path; see CDROM.open.
		f.zeroOffset = int(head[14])&0xFF | int(int8(head[15]))<<8
	}
	if fi, err := file.Stat(); err == nil {
		f.size = fi.Size() - int64(f.zeroOffset)
	} else {
		f.size = -1
	}
	return nil
}

// Close releases the image.
func (f *Floppy) Close() error { return f.close() }

func (f *Floppy) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file != nil {
		err := f.file.Close()
		f.file = nil
		f.size = -1
		return err
	}
	return nil
}

// isWriteProtect is FloppyImage.isWriteProtect: the UI flag OR the image not
// being writable.
func (f *Floppy) isWriteProtect() bool {
	f.mu.Lock()
	w := f.canWrite
	f.mu.Unlock()
	return f.wp || !w
}

func (f *Floppy) mediumSize() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return -1, derr(ErrNoMedium)
	}
	if f.size < 0 {
		if fi, err := f.file.Stat(); err == nil {
			f.size = fi.Size() - int64(f.zeroOffset)
		}
	}
	if f.size < 0 {
		return -1, derr(ErrNoMedium)
	}
	return f.size, nil
}

func (f *Floppy) read(buf []byte, off int64, n int) (int, error) {
	f.mu.Lock()
	file := f.file
	z := int64(f.zeroOffset)
	f.mu.Unlock()
	if file == nil {
		return 0, derr(ErrNoMedium)
	}
	if n <= 0 {
		return 0, nil
	}
	if n > len(buf) {
		n = len(buf)
	}
	got, err := file.ReadAt(buf[:n], off+z)
	if err != nil && !errors.Is(err, io.EOF) {
		return got, derr(ErrRead)
	}
	return got, nil
}

// write is FloppyImage.write: refuse outright when protected, otherwise write
// through. ImageIO turns an IOException into 250 (or 254 for a read-only file).
func (f *Floppy) write(buf []byte, off int64, n int) error {
	if f.isWriteProtect() {
		return derr(ErrWriteProtect)
	}
	f.mu.Lock()
	file, z := f.file, int64(f.zeroOffset)
	f.mu.Unlock()
	if file == nil {
		return derr(ErrNoMedium)
	}
	if n <= 0 {
		return nil
	}
	if n > len(buf) {
		n = len(buf)
	}
	if _, err := file.WriteAt(buf[:n], off+z); err != nil {
		return derr(ErrRead)
	}
	return nil
}

// formatUnit is FloppyImage.formatUnit: a no-op.
func (f *Floppy) formatUnit(mediumType, startCyl, endCyl, startHead, endHead int) error {
	return nil
}

func (f *Floppy) isInited() bool {
	f.mu.Lock()
	active := f.file != nil
	f.mu.Unlock()
	return active && f.needInit
}

func (f *Floppy) blockLength() int { return floppyBlockLength }
func (f *Floppy) totalBlocks() int { return floppyTotalBlocks }

func (f *Floppy) testUnitReady() int {
	size, err := f.mediumSize()
	return f.baseDevice.testUnitReady(size, err)
}

func (f *Floppy) refreshState() {
	if f.isInited() {
		return
	}
	if err := f.open(f.Path()); err != nil {
		f.setMediaState(stateMediumNotPresent)
		return
	}
	f.setMediaState(stateMediumNotPresent)
}

// modeSense is FloppyDriver.modeSense: an 8-byte header (medium type code and
// the write-protect bit) plus the pages selected by pageCode; 0x3F selects all
// of them.
func (f *Floppy) modeSense(buf []byte, pc, pageCode int) int {
	if len(buf) < 8 {
		return 0
	}
	size := 8
	buf[0] = 0
	buf[2] = floppyMediumTypeCode
	if f.isWriteProtect() {
		buf[3] = 0x80
	} else {
		buf[3] = 0
	}
	buf[4], buf[5], buf[6], buf[7] = 0, 0, 0, 0
	if pageCode == 1 || pageCode == 63 {
		p := buf[size:]
		p[0], p[1], p[2], p[3] = 1, 10, 0, 3
		p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11] = 0, 0, 0, 0, 3, 0, 0, 0
		size += 12
	}
	if pageCode == 5 || pageCode == 63 {
		p := buf[size:]
		p[0], p[1], p[2], p[3] = 5, 30, 3, 0xE8
		p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11] = 2, 18, 2, 0, 0, 80, 0, 0
		p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19] = 0, 0, 0, 0, 0, 0, 0, 8
		p[20], p[21], p[22], p[23], p[24], p[25], p[26], p[27] = 30, 0, 0, 0, 0, 0, 0, 0
		p[28], p[29], p[30], p[31] = 2, 88, 0, 0
		size += 32
	}
	if pageCode == 27 || pageCode == 63 {
		p := buf[size:]
		p[0], p[1], p[2], p[3] = 27, 10, 0x80, 1
		p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11] = 0, 0, 0, 0, 0, 0, 0, 0
		size += 12
	}
	if pageCode == 28 || pageCode == 63 {
		p := buf[size:]
		p[0], p[1], p[2], p[3] = 28, 6, 0, 5
		p[4], p[5], p[6], p[7] = 0, 0, 0, 0
		size += 8
	}
	buf[1] = byte(size - 2)
	return size
}

// eject is FloppyImage.eject: clear the state and the name, close the image.
func (f *Floppy) eject() {
	f.setMediaState(stateMediumNotPresent)
	f.mu.Lock()
	f.name = ""
	f.needInit = false
	f.mu.Unlock()
	_ = f.close()
}

// insert is FloppyImage.insert: adopt the pending image and drop to "not
// present" (FloppyImage.insert calls setDeviceState(0)).
func (f *Floppy) insert() error {
	if f.newDiskName != "" {
		f.setMediaState(stateMediumNotPresent)
	}
	f.needInit = true
	return nil
}

// changeDisk arms a new image, mirroring FloppyImage.prepareChangeDisk
// (including the capacity validation of the replacement). The previous handle is
// closed, which the Java leaves to the garbage collector.
func (f *Floppy) changeDisk(path string) error {
	if path != "" {
		n, err := OpenFloppy(path, f.wp)
		if err != nil {
			return err
		}
		f.mu.Lock()
		old := f.file
		f.file = n.file
		f.size = n.size
		f.zeroOffset = n.zeroOffset
		f.canWrite = n.canWrite
		f.name = path
		f.mu.Unlock()
		n.file = nil // ownership moved
		if old != nil {
			_ = old.Close()
		}
	}
	// The media state is reset by insert(), not by changeDisk (see the Java).
	f.newDiskName = path
	f.diskChanged = true
	return nil
}

// ---------------------------------------------------------------------------
// UFI command handler (UFIProcessor)
// ---------------------------------------------------------------------------

// inquiryData is UFIProcessor.inquiryData (36 bytes): 00 80 00 01 1F 00 00 00
// followed by the 28-character vendor string.
var floppyInquiry = []byte{
	0x00, 0x80, 0x00, 0x01, 0x1F, 0x00, 0x00, 0x00,
	'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'F', 'L', 'O', 'P', 'P', 'Y', ' ',
	'V', 'M', ' ', '1', '.', '1', '.', '0', ' ', ' ', ' ', ' ', ' ',
}

// capacityList is UFIProcessor.capacityList: the READ_FORMAT_CAPACITY reply
// template (20 bytes). It is a mutable field in the Java, so the values written
// here persist across calls; doFormatCapacity overwrites bytes 4..7 with the
// block count and 9..11 with the block length.
var floppyCapacityList = []byte{
	0, 0, 0, 16,
	0, 0, 0, 0,
	2, 0, 0, 0,
	0, 0, 11, 64,
	0, 0, 2, 0,
}

// ufiHandler is UFIProcessor: the floppy command dispatcher.
type ufiHandler struct {
	*usbProcessor
	floppy *Floppy
	// capacityList mirrors the Java's mutable instance field.
	capacityList []byte
}

func newUFIHandler(w wire, f *Floppy) *ufiHandler {
	h := &ufiHandler{floppy: f, capacityList: append([]byte(nil), floppyCapacityList...)}
	h.usbProcessor = newUSBProcessor(w)
	return h
}

// run is UFIProcessor.run.
func (h *ufiHandler) run() { h.usbProcessor.run(h.processCommand) }

// handle runs one CDB synchronously (the run loop does the same after taking a
// command off the queue; tests call this directly).
func (h *ufiHandler) handle(cdb []byte, id byte) {
	h.mu.Lock()
	copy(h.command[:], cdb)
	h.commandID = id
	h.mu.Unlock()
	h.processCommand()
}

// processCommand is UFIProcessor.processCommand, minus the blocking getCommand.
func (h *ufiHandler) processCommand() {
	h.checkChangeDisk()
	if h.isStopped() {
		return
	}
	h.floppy.refreshState()
	switch h.command[0] {
	case 0x04: // FORMAT_UNIT
		h.doFormat()
	case 0x12: // INQUIRY
		h.doInquiry()
	case 0x55: // MODE_SELECT
		h.doModeSelect()
	case 0x5A: // MODE_SENSE
		h.doModeSense()
	case 0x1E: // PREVENT_ALLOW_MEDIUM_REMOVAL
		h.doPreventAllowMediumRemoval()
	case 0x28, 0xA8: // READ_10, READ_12
		h.doRead()
	case 0x25: // READ_CAPACITY
		h.doReadCapacity()
	case 0x23: // READ_FORMAT_CAPACITY
		h.doReadFormatCapacity()
	case 0x03: // REQUEST_SENSE
		h.sendData(senseLength, h.senseData[:], true)
	case 0x01, 0x2B: // REZERO_UNIT, SEEK_10
		h.setSenseKeys(0, 0, 0, 0)
	case 0x1D: // SEND_DIAGNOSTIC
		h.floppy.setMediaState(stateMediumChange)
		h.setSenseKeys(0, 0, 0, 0)
	case 0x1B: // START_STOP_UNIT
		h.doStartStopUnit()
	case 0x00: // TEST_UNIT_READY
		h.doTestUnitRead()
	case 0x2F: // VERIFY
		h.setSenseKeys(0, 0, 0, 0)
	case 0x2A, 0x2E, 0xAA: // WRITE_10, WRITE_AND_VERIFY, WRITE_12
		h.doWrite()
	default:
		h.setSenseKeys(5, 36, 0, 0)
	}
	h.commandFinish()
}

func (h *ufiHandler) checkChangeDisk() {
	if !h.floppy.isChangeDisk() {
		return
	}
	if h.floppy.isEject() {
		h.floppy.eject()
	} else if err := h.floppy.insert(); err != nil {
		h.logf("换盘失败: %v", err)
	}
}

// doFormat is UFIProcessor.doFormat.
func (h *ufiHandler) doFormat() {
	paramListLength := GetInt16Bits(h.command[:], 8)
	paramList := make([]byte, paramListLength)
	paramListLength = h.getData(paramList, paramListLength)
	if paramListLength == 0 {
		h.setSenseKeys(5, 26, 0, 0)
		return
	}
	switch {
	case h.floppy.isWriteProtect():
		h.setSenseKeys(7, 39, 0, 0)
	case h.floppy.totalBlocks() == GetInt32Bits(paramList, 5) &&
		h.floppy.blockLength() == GetInt24Bits(paramList, 10):
		track := int(h.command[2])
		side := int(paramList[1] & 1)
		if err := h.floppy.formatUnit(2, track, track, side, side); err != nil {
			h.setSenseKeys(3, 49, 1, 0)
			return
		}
		h.setSenseKeys(0, 0, 0, 0)
	default:
		h.setSenseKeys(5, 38, 0, 0)
	}
}

// doInquiry is UFIProcessor.doInquiry.
func (h *ufiHandler) doInquiry() {
	if h.command[1]&0xE0 != 0 {
		h.setSenseKeys(5, 37, 0, 0)
	} else if h.command[1]&1 != 0 {
		h.setSenseKeys(5, 36, 0, 0)
	} else {
		h.sendData(len(floppyInquiry), floppyInquiry, true)
		h.setSenseKeys(0, 0, 0, 0)
	}
}

// doModeSelect is UFIProcessor.doModeSelect.
func (h *ufiHandler) doModeSelect() {
	paramListLength := GetInt16Bits(h.command[:], 8)
	if h.getData(h.dataBuffer, paramListLength) == 0 {
		h.setSenseKeys(5, 26, 0, 0)
	} else {
		h.setSenseKeys(0, 0, 0, 0)
	}
}

// doModeSense is UFIProcessor.doModeSense (page control from bits 6..7 of
// CDB byte 2, page code from bits 0..5).
func (h *ufiHandler) doModeSense() {
	pc := int(h.command[2]) >> 6 & 3
	length := h.floppy.modeSense(h.dataBuffer, pc, int(h.command[2]&0x3F))
	h.setSenseKeys(0, 0, 0, 0)
	h.sendData(length, h.dataBuffer, true)
}

func (h *ufiHandler) doPreventAllowMediumRemoval() {
	if h.command[4]&1 != 0 {
		h.setSenseKeys(5, 36, 0, 0)
	} else {
		h.setSenseKeys(0, 0, 0, 0)
	}
}

// doRead is UFIProcessor.doRead: the CDB length is in blocks, the handler walks
// the image in dataBuffer-sized windows and sends each window as 4096-byte
// fragments.
func (h *ufiHandler) doRead() {
	cmd := h.command[:]
	blockLen := int64(h.floppy.blockLength())
	startPos := int64(GetInt32Bits(cmd, 3)) * blockLen
	var length int
	if cmd[0] == 0x28 {
		length = GetInt16Bits(cmd, 8) * int(blockLen)
	} else {
		length = GetInt32Bits(cmd, 7) * int(blockLen)
	}
	size, err := h.floppy.mediumSize()
	if err != nil {
		h.readError(startPos, blockLen, err)
		return
	}
	if startPos < 0 || startPos >= size {
		h.setSenseKeys(5, 33, 0, 0)
		return
	}
	bufferLen := len(h.dataBuffer)
	isLast := false
	for length > 0 {
		readLength := bufferLen
		if bufferLen >= length {
			readLength = length
			isLast = true
		}
		n, err := h.floppy.read(h.dataBuffer, startPos, readLength)
		if err != nil {
			h.readError(startPos, blockLen, err)
			return
		}
		startPos += int64(n)
		if n == readLength {
			h.sendData(readLength, h.dataBuffer, isLast)
			length -= readLength
			continue
		}
		h.sendData(n, h.dataBuffer, true)
		length = -1
	}
	if length == 0 {
		h.setSenseKeys(0, 0, 0, 0)
	} else {
		h.setSenseKeys(5, 33, 0, 0)
	}
}

// readError is UFIProcessor.doRead's catch block. blockLen is the device block
// length, used for the FOUND information field on a read error.
func (h *ufiHandler) readError(startPos, blockLen int64, err error) {
	switch {
	case isDeviceCode(err, ErrRead):
		h.setSenseKeys(3, 16, 0, int(startPos/blockLen))
	case isDeviceCode(err, ErrNoMedium):
		h.floppy.setMediaState(stateMediumNotPresent)
		h.setSenseKeys(2, 58, 0, 0)
	case isDeviceCode(err, ErrBadAddress):
		h.setSenseKeys(5, 33, 0, 0)
	case isDeviceCode(err, ErrWriteProtect):
		h.setSenseKeys(7, 39, 0, 0)
	default:
		h.setSenseKeys(5, 36, 0, 0)
	}
}

// doReadCapacity is UFIProcessor.doReadCapacity: the last block index and the
// block length, both taken from the *device constants*, not from the image size.
func (h *ufiHandler) doReadCapacity() {
	switch h.floppy.testUnitReady() {
	case 0:
		h.setSenseKeys(2, 58, 0, 0)
	case 2:
		h.setSenseKeys(6, 40, 0, 0)
	case 3:
		lba := h.floppy.totalBlocks() - 1
		blockLen := h.floppy.blockLength()
		IntToByte(h.dataBuffer, 0, lba)
		IntToByte(h.dataBuffer, 4, blockLen)
		h.setSenseKeys(0, 0, 0, 0)
		h.sendData(8, h.dataBuffer, true)
	}
}

// doReadFormatCapacity is UFIProcessor.doReadFormatCapacity. The Java sets the
// media state to 3 (ready) when the unit reports state 2, which looks like a
// typo for 2 but is reproduced.
func (h *ufiHandler) doReadFormatCapacity() {
	if h.floppy.testUnitReady() == 2 {
		h.floppy.setMediaState(stateMediumReady)
		h.setSenseKeys(6, 40, 0, 0)
	} else {
		h.setSenseKeys(0, 0, 0, 0)
	}
	list := h.capacityList
	totalBlocks := h.floppy.totalBlocks()
	blockLen := h.floppy.blockLength()
	list[4] = byte(totalBlocks >> 24 & 0xFF)
	list[5] = byte(totalBlocks >> 16 & 0xFF)
	list[6] = byte(totalBlocks >> 8 & 0xFF)
	list[7] = byte(totalBlocks & 0xFF)
	list[9] = byte(blockLen >> 16 & 0xFF)
	list[10] = byte(blockLen >> 8 & 0xFF)
	list[11] = byte(blockLen & 0xFF)
	h.sendData(len(list), list, true)
}

func (h *ufiHandler) doStartStopUnit() {
	if h.command[4]&2 != 0 {
		h.setSenseKeys(5, 36, 0, 0)
	} else {
		h.setSenseKeys(0, 0, 0, 0)
	}
}

// doTestUnitRead is UFIProcessor.doTestUnitRead; the media state 2 branch
// writes 3, exactly as the Java does.
func (h *ufiHandler) doTestUnitRead() {
	if h.command[1]&0xE0 != 0 {
		h.setSenseKeys(5, 36, 0, 0)
		return
	}
	switch h.floppy.testUnitReady() {
	case 0:
		h.setSenseKeys(2, 58, 0, 0)
	case 2:
		h.setSenseKeys(6, 40, 0, 0)
		h.floppy.setMediaState(stateMediumReady)
	case 3:
		h.setSenseKeys(0, 0, 0, 0)
	}
}

// doWrite is UFIProcessor.doWrite. The CDB carries the byte offset; each
// incoming data element is consumed either raw or (vmm_compress == 1) as
// 4-byte length + ciphertext.
func (h *ufiHandler) doWrite() {
	blockLen := h.floppy.blockLength()
	startPos := int64(GetInt32Bits(h.command[:], 3)) * int64(blockLen)
	var length int
	if h.command[0] == 0xAA {
		length = GetInt32Bits(h.command[:], 7) // WRITE_12: bytes 6..9
	} else {
		length = GetInt16Bits(h.command[:], 8) // WRITE_10 / WRITE_AND_VERIFY
	}
	length *= blockLen
	if length == 0 {
		h.setSenseKeys(0, 0, 0, 0)
		return
	}
	size, err := h.floppy.mediumSize()
	if err != nil {
		h.readError(startPos, int64(blockLen), err)
		return
	}
	if startPos < 0 || startPos+int64(length) > size {
		h.setSenseKeys(5, 33, 0, 0)
		return
	}
	bufferLen := len(h.dataBuffer)
	for length > 0 {
		curWrite := bufferLen
		if bufferLen >= length {
			curWrite = length
		}
		var n int
		if h.wire.encryptPayloads() {
			key, iv := h.wire.secret()
			n, err = h.queue.getDataEncry(h.dataBuffer, curWrite, key, iv)
			if err != nil {
				h.logf("UFI 解密失败: %v", err)
				h.setSenseKeys(5, 36, 0, 0)
				return
			}
		} else {
			n = h.queue.getData(h.dataBuffer, curWrite)
		}
		if n == 0 {
			h.setSenseKeys(5, 36, 0, 0)
			return
		}
		if err := h.floppy.write(h.dataBuffer, startPos, n); err != nil {
			h.readError(startPos, int64(blockLen), err)
			return
		}
		startPos += int64(n)
		length -= n
	}
	h.setSenseKeys(0, 0, 0, 0)
}

// sendData is UFIProcessor.sendData: fragments of at most FLOPPY_PACKET_SIZE,
// each carrying a state nibble; a non-positive length sends nothing (unlike the
// SFF side, which emits a zero-length END frame).
func (h *ufiHandler) sendData(dataLength int, dataBuffer []byte, isLast bool) {
	if dataLength <= 0 || h.isStopped() {
		return
	}
	off := 0
	for dataLength > 0 && !h.isStopped() {
		var curLength, state int
		if FloppyPacketSize < dataLength {
			curLength, state = FloppyPacketSize, SubContinue
		} else {
			curLength = dataLength
			if isLast {
				state = SubEnd
			} else {
				state = SubContinue
			}
		}
		if off+curLength > len(dataBuffer) {
			h.logf("UFI 发送缓冲不足: off=%d len=%d", off, curLength)
			return
		}
		chunk := dataBuffer[off : off+curLength]
		pack := make([]byte, 0, HeaderSize+curLength)
		if h.wire.encryptPayloads() {
			key, iv := h.wire.secret()
			body, err := WrapPayload(chunk, key, iv)
			if err != nil || len(body) == 0 {
				h.logf("UFI 加密失败: %v", err)
				return
			}
			pack = make([]byte, HeaderSize+len(body))
			UFIDataPak(pack, 0, SubData, state, len(body), int(h.commandID))
			copy(pack[HeaderSize:], body)
		} else {
			pack = make([]byte, HeaderSize+curLength)
			UFIDataPak(pack, 0, SubData, state, curLength, int(h.commandID))
			copy(pack[HeaderSize:], chunk)
		}
		if err := h.wire.send(pack); err != nil && !h.isStopped() {
			h.logf("UFI 发送失败: %v", err)
			return
		}
		off += curLength
		dataLength -= curLength
	}
}

// commandFinish is UFIProcessor.commandFinish.
func (h *ufiHandler) commandFinish() {
	result := 0
	if h.getSenseKey() != 0 && h.command[0] != 0x03 {
		result = 1
	}
	pack := make([]byte, HeaderSize)
	UFICmpltPak(pack, 0, result, int(h.commandID))
	if err := h.wire.send(pack); err != nil && !h.isStopped() {
		h.logf("UFI 完成帧发送失败: %v", err)
	}
}

func (h *ufiHandler) logf(format string, args ...any) { logf(h.wire, format, args...) }
