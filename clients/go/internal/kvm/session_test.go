package kvm

// Session state-machine tests.
//
// The captured stream in the sibling repository cannot be decrypted without the
// JNLP that produced it (the decrykey is not in the evidence), so the session's
// key handling, sub-packet reassembly and input encoders are exercised with
// synthetic traffic built to the same layout the protocol notes describe:
//
//	02-handshake-and-crypto.md  §2 (suite list, SET_SUITE, CONNECT_BLADE)
//	02-handshake-and-crypto.md  §3.2 (KVM_KEY_SET -> kvm_key)
//	03-video-channel.md          §1 (sub-packet headers, encryption, combine)
//	04-input-channel.md          §1.4 / §2.2 (keyboard and mouse payloads)

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test harness
// ---------------------------------------------------------------------------

// recorder captures everything the session emits and every frame it delivers.
type recorder struct {
	mu     sync.Mutex
	sent   [][]byte
	labels []string
	frames []Frame
}

func (r *recorder) onSent(frame []byte, label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, bytes.Clone(frame))
	r.labels = append(r.labels, label)
}

func (r *recorder) onFrame(f Frame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, f)
}

// payloadOf returns a client frame's payload. Regular frames have a 10-byte
// header; the "compressed" CONNECT_BLADE variant carries the 24-byte encodeKey
// header and starts its payload at offset 30.
func payloadOf(frame []byte) ([]byte, bool) {
	if len(frame) < 10 || frame[0] != 0xfe || frame[1] != 0xf6 {
		return nil, false
	}
	if frame[2]&0x80 != 0 {
		if len(frame) < 30 {
			return nil, false
		}
		return frame[30:], true
	}
	return frame[10:], true
}

// sentPayloads returns the wire payloads of every frame sent so far.
func (r *recorder) sentPayloads() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, 0, len(r.sent))
	for _, f := range r.sent {
		if p, ok := payloadOf(f); ok {
			out = append(out, bytes.Clone(p))
		}
	}
	return out
}

// sentOf returns every sent payload whose command byte matches cmd.
func (r *recorder) sentOf(cmd byte) [][]byte {
	var out [][]byte
	for _, p := range r.sentPayloads() {
		if len(p) > 0 && p[0] == cmd {
			out = append(out, p)
		}
	}
	return out
}

func (r *recorder) framesSnapshot() []Frame {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Frame(nil), r.frames...)
}

// waitForCmd polls until a frame with the given command byte has been sent.
func (r *recorder) waitForCmd(cmd byte, timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if got := r.sentOf(cmd); len(got) > 0 {
			return got[len(got)-1], true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

const (
	testVerifyValueExt = "00000000000000000000000000000000"
	// 32 hex bytes: user_key = 00..0f, user_iv = 10..1f
	testDecryKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	// 48-byte KVM_KEY_SET plaintext: 32 ASCII chars + 16-byte salt
	testPlain48 = "0123456789abcdef0123456789abcdef" + "SALTsaltSALTsalt"
)

func testUserKey() []byte {
	k := make([]byte, 16)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func testUserIV() []byte {
	k := make([]byte, 16)
	for i := range k {
		k[i] = byte(16 + i)
	}
	return k
}

func newTestSession(t *testing.T) (*Session, *recorder) {
	t.Helper()
	rec := &recorder{}
	s := New(Options{
		Host: "127.0.0.1",
		Port: 1,
		Params: map[string]string{
			"verifyValue":    "1000000002",
			"verifyValueExt": testVerifyValueExt,
			"decrykey":       testDecryKeyHex,
		},
		ColorBit: 2,
		Quiet:    true,
	})
	s.OnSent = rec.onSent
	s.OnFrame = rec.onFrame
	t.Cleanup(s.Close)
	return s, rec
}

// suiteListPayload mirrors the real 0x43 frame: algo 1/5000, 2/10000, 3/10000.
func suiteListPayload() []byte {
	return []byte{
		0x00, 0x00, 0x43, 0x00, 0x03,
		0x01, 0x00, 0x00, 0x13, 0x88,
		0x02, 0x00, 0x00, 0x27, 0x10,
		0x03, 0x00, 0x00, 0x27, 0x10,
	}
}

// keySetPayload builds KVM_KEY_SET(0x40) whose ciphertext decrypts to plain.
func keySetPayload(t *testing.T, plain []byte) []byte {
	t.Helper()
	if len(plain)%16 != 0 {
		t.Fatalf("KVM_KEY_SET 明文必须是 16 的倍数，得到 %d", len(plain))
	}
	ct, err := AESEncryptNoPad(plain, testUserKey(), testUserIV())
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0x00, 0x00, 0x40, 0x00}, ct...)
}

// keySet48Payload is the 48-byte form: 32 ASCII password + 16-byte salt.
func keySet48Payload(t *testing.T) []byte {
	t.Helper()
	return keySetPayload(t, []byte(testPlain48))
}

// expectedKvmKey is what the session must derive from keySet48Payload.
func expectedKvmKey(t *testing.T) []byte {
	t.Helper()
	key, err := DeriveKvmKey([]byte(testPlain48), 10000, 3)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// headerSubpacket builds the plaintext seq-0 sub-packet (buf, i.e. payload[4:]).
func headerSubpacket(frameNo, total, diff, dqt, iframe, width, height int) []byte {
	buf := make([]byte, 17)
	binary.BigEndian.PutUint16(buf[0:], 0)
	buf[2] = byte(frameNo)
	binary.BigEndian.PutUint32(buf[3:], uint32(total))
	buf[7] = byte(diff<<7) | byte(width>>8)
	buf[8] = byte(width)
	binary.BigEndian.PutUint16(buf[9:], uint16(height))
	buf[11] = 0xdc
	binary.BigEndian.PutUint16(buf[12:], 0xffff)
	binary.BigEndian.PutUint16(buf[14:], 0xffff)
	buf[16] = byte(iframe<<7) | byte(dqt)
	return append([]byte{0x00, 0x00, 0x02, 0x00}, buf...)
}

// dataSubpacket builds an encrypted seq>=1 sub-packet for chunk.
func dataSubpacket(t *testing.T, kvmKey []byte, frameNo, seq int, chunk []byte) []byte {
	t.Helper()
	ct, err := AESEncryptNoPad(ZeroPad(chunk), kvmKey[0:16], kvmKey[32:48])
	if err != nil {
		t.Fatal(err)
	}
	head := []byte{0x00, 0x00, 0x02, 0x00, byte(seq >> 8), byte(seq), byte(frameNo), byte(len(chunk))}
	out := append(head, ct...)
	if len(out) > 250 {
		t.Fatalf("子包 %d 字节超过 dlen 上限 250", len(out))
	}
	return out
}

// ---------------------------------------------------------------------------
// suite list -> SET_SUITE / CONNECT_BLADE
// ---------------------------------------------------------------------------

func TestSessionSuiteListNegotiation(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(suiteListPayload())

	st := s.Status()
	if st.Algo != 3 || st.Iterations != 10000 {
		t.Errorf("选中 algo=%d iterations=%d，期望 algo=3 / 10000", st.Algo, st.Iterations)
	}

	wantKey, err := DeriveEncodeKey(testVerifyValueExt, testUserIV(), 10000, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.EncodeKey(); hexOf(got) != hexOf(wantKey) {
		t.Errorf("encodeKey = %s，期望 %s", hexOf(got), hexOf(wantKey))
	}

	setSuite, ok := rec.waitForCmd(CmdSetSuite, time.Second)
	if !ok {
		t.Fatal("没有发出 SET_SUITE")
	}
	if want := "44000300002710"; hexOf(setSuite) != want {
		t.Errorf("SET_SUITE payload = %s，期望 %s", hexOf(setSuite), want)
	}

	connect, ok := rec.waitForCmd(CmdConnectBlade, time.Second)
	if !ok {
		t.Fatal("没有发出 CONNECT_BLADE")
	}
	if hexOf(connect) != "0600020101" {
		t.Errorf("CONNECT_BLADE payload = %s，期望 0600020101", hexOf(connect))
	}
	// The frame itself must use the 0x8000 variant carrying the 24-byte key proof.
	var frame []byte
	for _, f := range rec.sent {
		if p, ok := payloadOf(f); ok && len(p) > 0 && p[0] == CmdConnectBlade {
			frame = f
		}
	}
	if frame == nil {
		t.Fatal("找不到 CONNECT_BLADE 原始帧")
	}
	if len(frame) != 35 {
		t.Errorf("CONNECT_BLADE 帧长 = %d，期望 35", len(frame))
	}
	if got := binary.BigEndian.Uint16(frame[2:]); got != 0x8007 {
		t.Errorf("CONNECT_BLADE 长度字段 = 0x%04x，期望 0x8007", got)
	}
	if hexOf(frame[4:28]) != hexOf(wantKey) {
		t.Errorf("CONNECT_BLADE 密钥头 = %s，期望 encodeKey %s", hexOf(frame[4:28]), hexOf(wantKey))
	}
}

// TestSessionDoesNotPushDqtOnConnect pins the deliberate omission documented in
// session.js: the 0x27 quality value is never sent on connect, because only the
// firmware's own default (70 -> table index 6) is verified.
func TestSessionDoesNotPushDqtOnConnect(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(suiteListPayload())

	// wait past the 200ms MOUSE_MODE_SET(2) and 400ms FRAME_COMM(35) timers
	if _, ok := rec.waitForCmd(CmdFrameComm, time.Second); !ok {
		t.Fatal("没有发出 FRAME_COMM(35)")
	}
	time.Sleep(150 * time.Millisecond)

	if got := rec.sentOf(CmdDqtModeSet); len(got) != 0 {
		t.Errorf("连接时不应自动下发 DQT 档位，实际发了 %d 次：%s", len(got), hexOf(got[0]))
	}
	if got := rec.sentOf(CmdMouseModeSet); len(got) != 1 || hexOf(got[0]) != "2400020000" {
		t.Errorf("MOUSE_MODE_SET = %v，期望恰好一次 2400020000", hexOf2(got))
	}
}

func hexOf2(list [][]byte) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, hexOf(b))
	}
	return out
}

// ---------------------------------------------------------------------------
// CONNECT_STATE / MOUSE_MODE / DQT_MODE dispatch
// ---------------------------------------------------------------------------

func TestSessionStatusCallbacks(t *testing.T) {
	s, rec := newTestSession(t)
	var states, modes, dqts []int
	s.OnConnectState = func(v int) { states = append(states, v) }
	s.OnMouseMode = func(v int) { modes = append(modes, v) }
	s.OnDqt = func(v int) { dqts = append(dqts, v) }
	s.OnKeyState = func(v int) {}
	s.OnNotPri = func(v int) {}

	s.onFrame([]byte{0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}) // state 3
	// The real 0x25 frame reports mode 1 (absolute) — no switch should be requested.
	s.onFrame([]byte{0x00, 0x00, 0x25, 0x02, 0x01, 0x00, 0x00, 0x00})
	// The real 0x28 frame reports quality 70 -> table index 6.
	s.onFrame([]byte{0x00, 0x00, 0x28, 0x00, 0x46, 0x00, 0x00, 0x00})

	if len(states) != 1 || states[0] != 3 {
		t.Errorf("OnConnectState = %v，期望 [3]", states)
	}
	if len(modes) != 1 || modes[0] != 1 {
		t.Errorf("OnMouseMode = %v，期望 [1]", modes)
	}
	if len(dqts) != 1 || dqts[0] != 70 {
		t.Errorf("OnDqt = %v，期望 [70]", dqts)
	}
	if st := s.Status(); st.Dqt != 6 || !st.DqtSeen {
		t.Errorf("Dqt = %d (seen=%v)，期望 6 / true", st.Dqt, st.DqtSeen)
	}
	if got := rec.sentOf(CmdMouseModeSet); len(got) != 0 {
		t.Errorf("BMC 已报绝对模式，不应再请求切换：%v", hexOf2(got))
	}
}

func TestSessionForcesAbsoluteMouseOnce(t *testing.T) {
	s, rec := newTestSession(t)
	// mode 0 = relative: the GUI needs absolute, so one switch request goes out
	s.onFrame([]byte{0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00})
	got, ok := rec.waitForCmd(CmdMouseModeSet, 2*time.Second)
	if !ok {
		t.Fatal("相对模式下应请求切换到绝对值模式")
	}
	if hexOf(got) != "2400010000" {
		t.Errorf("MOUSE_MODE_SET payload = %s，期望 2400010000", hexOf(got))
	}
	// a second "relative" report must not re-send (forced only once)
	s.onFrame([]byte{0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00})
	time.Sleep(250 * time.Millisecond)
	if n := len(rec.sentOf(CmdMouseModeSet)); n != 1 {
		t.Errorf("MOUSE_MODE_SET(1) 发了 %d 次，期望 1 次", n)
	}
}

// ---------------------------------------------------------------------------
// KVM_KEY_SET -> kvm_key / reconnKey
// ---------------------------------------------------------------------------

func TestSessionKeySetDerivesKvmKey(t *testing.T) {
	s, _ := newTestSession(t)
	authenticated := 0
	s.OnAuthenticated = func() { authenticated++ }

	s.onFrame(keySet48Payload(t))

	if !s.Status().Authenticated {
		t.Fatal("收到 48 字节 KVM_KEY_SET 后应标记为已认证")
	}
	if authenticated != 1 {
		t.Errorf("OnAuthenticated 触发 %d 次，期望 1 次", authenticated)
	}
	if got, want := s.KvmKey(), expectedKvmKey(t); hexOf(got) != hexOf(want) {
		t.Errorf("kvm_key = %s，期望 %s", hexOf(got), hexOf(want))
	}

	// 128-byte form = reconnection key, same AES-CBC unwrap
	reconn := bytes.Repeat([]byte{0x5a}, 128)
	s.onFrame(keySetPayload(t, reconn))
	if !s.Status().HasReconnKey {
		t.Error("收到 128 字节 KVM_KEY_SET 后应保存重连密钥")
	}
}

// ---------------------------------------------------------------------------
// IMAGE_DATA sub-packet reassembly
// ---------------------------------------------------------------------------

func TestSessionReassemblesFrame(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(keySet48Payload(t))
	kvmKey := expectedKvmKey(t)

	// 500 bytes of block data: the vendor's sizing gives 4 slots (1 header + 3 data)
	payload := make([]byte, 500)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	chunks := [][]byte{payload[0:220], payload[220:440], payload[440:500]}
	if n := 500/SubpacketChunk + 1 + 1; len(chunks) != n-1 {
		t.Fatalf("测试数据分块数 %d 与协议槽位 %d 不匹配", len(chunks), n)
	}

	var header []int
	s.OnHdrDqt = func(index int) { header = append(header, index) }

	s.onFrame(headerSubpacket(7, 500, 0, 7, 0, 800, 600))
	for i, chunk := range chunks {
		s.onFrame(dataSubpacket(t, kvmKey, 7, i+1, chunk))
	}

	frames := rec.framesSnapshot()
	if len(frames) != 1 {
		t.Fatalf("收到 %d 帧，期望 1 帧", len(frames))
	}
	f := frames[0]
	if f.NoChange {
		t.Error("该帧不是「无变化」帧")
	}
	if f.FrameNo != 7 || f.Width != 800 || f.Height != 600 {
		t.Errorf("帧元数据 = no=%d %dx%d，期望 no=7 800x600", f.FrameNo, f.Width, f.Height)
	}
	if f.BlockX != 13 || f.BlockY != 10 {
		t.Errorf("块网格 = %dx%d，期望 13x10", f.BlockX, f.BlockY)
	}
	if f.DQT != 7 || f.IFrame != 0 || f.Diff != 0 {
		t.Errorf("dqt/iframe/diff = %d/%d/%d，期望 7/0/0", f.DQT, f.IFrame, f.Diff)
	}
	if len(header) != 1 || header[0] != 7 {
		t.Errorf("OnHdrDqt = %v，期望 [7]", header)
	}

	want := append([]byte{0}, payload...)
	if !bytes.Equal(f.Stream, want) {
		t.Errorf("重组缓冲长度 %d（期望 %d），内容不一致", len(f.Stream), len(want))
	}
	if len(f.Stream) != 501 {
		t.Errorf("重组缓冲 %d 字节，期望 packLenght+1 = 501", len(f.Stream))
	}
}

func TestSessionNoChangeFrame(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(keySet48Payload(t))
	s.onFrame(headerSubpacket(3, 0, 1, 7, 1, 800, 600))

	frames := rec.framesSnapshot()
	if len(frames) != 1 {
		t.Fatalf("收到 %d 帧，期望 1 帧「无变化」", len(frames))
	}
	f := frames[0]
	if !f.NoChange || f.FrameNo != 3 || f.Stream != nil {
		t.Errorf("无变化帧 = %+v，期望 NoChange=true frameNo=3 无数据", f)
	}
	if f.Diff != 1 || f.IFrame != 1 {
		t.Errorf("diff/iframe = %d/%d，期望 1/1", f.Diff, f.IFrame)
	}
	if st := s.Status(); st.FramesReceived != 1 {
		t.Errorf("framesReceived = %d，期望 1", st.FramesReceived)
	}
}

// TestSessionMissingSubpacketRequestsIFrame covers completeFrame's missing-slot
// branch: the accounting says the frame is complete but a middle slot never
// arrived, so the frame is dropped and an I frame is requested.
func TestSessionMissingSubpacketRequestsIFrame(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(keySet48Payload(t))
	kvmKey := expectedKvmKey(t)

	// total 240 -> slots = 240/220+1+1 = 3, so seq 1 and 2 are expected
	chunk := bytes.Repeat([]byte{0x11}, 240)
	s.onFrame(headerSubpacket(9, 240, 1, 6, 0, 640, 480))
	s.onFrame(dataSubpacket(t, kvmKey, 9, 1, chunk)) // seq 2 never arrives, yet sum == total

	if frames := rec.framesSnapshot(); len(frames) != 0 {
		t.Errorf("缺子包的帧应被丢弃，却交付了 %d 帧", len(frames))
	}
	if _, ok := rec.waitForCmd(CmdIReq, time.Second); !ok {
		t.Error("缺子包后应发 I_REQ(0x08) 请求 I 帧")
	}
}

// TestSessionIgnoresSubpacketsWithoutKey pins the guard the JS reference has:
// nothing is decoded (and nothing is emitted) before the kvm_key arrives.
func TestSessionIgnoresSubpacketsWithoutKey(t *testing.T) {
	s, rec := newTestSession(t)
	s.onFrame(headerSubpacket(1, 0, 1, 7, 1, 800, 600))
	if frames := rec.framesSnapshot(); len(frames) != 0 {
		t.Errorf("没有 kvm_key 时不应交付任何帧，实际 %d", len(frames))
	}
	if st := s.Status(); st.Width != 0 || st.Height != 0 {
		t.Errorf("没有 kvm_key 时不应解析帧头，得到 %dx%d", st.Width, st.Height)
	}
}

// ---------------------------------------------------------------------------
// Input encoders
// ---------------------------------------------------------------------------

func newReadySession(t *testing.T) (*Session, *recorder, []byte) {
	t.Helper()
	s, rec := newTestSession(t)
	s.onFrame(keySet48Payload(t))
	s.onFrame(headerSubpacket(1, 0, 1, 7, 1, 800, 600)) // establishes 800x600
	return s, rec, expectedKvmKey(t)
}

// decryptInputPayload unwraps the 16-byte AES body of a KEY_PACK/MOUSE_PACK payload.
func decryptInputPayload(t *testing.T, kvmKey, payload []byte) []byte {
	t.Helper()
	if len(payload) != 18 {
		t.Fatalf("加密输入 payload 长度 = %d，期望 18", len(payload))
	}
	pt, err := AESDecryptNoPad(payload[2:], kvmKey[16:32], kvmKey[32:48])
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestSessionSendKeyboard(t *testing.T) {
	s, rec, kvmKey := newReadySession(t)
	s.SendKeyboard([8]byte{0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00})

	got := rec.sentOf(CmdKeyPack)
	if len(got) != 1 {
		t.Fatalf("KEY_PACK 发了 %d 次，期望 1 次", len(got))
	}
	if got[0][0] != CmdKeyPack || got[0][1] != Blade {
		t.Errorf("KEY_PACK 头 = %s，期望 03 00", hexOf(got[0][:2]))
	}
	want := []byte{0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	if pt := decryptInputPayload(t, kvmKey, got[0]); !bytes.Equal(pt, want) {
		t.Errorf("键盘明文 = %s，期望 %s", hexOf(pt), hexOf(want))
	}
}

func TestSessionCtrlAltDel(t *testing.T) {
	s, rec, kvmKey := newReadySession(t)
	s.CtrlAltDel()

	got := rec.sentOf(CmdKeyPack)
	if len(got) != 1 {
		t.Fatalf("按下时应立即发一次 KEY_PACK，实际 %d 次", len(got))
	}
	if pt := decryptInputPayload(t, kvmKey, got[0]); !bytes.Equal(pt[:3], []byte{0x05, 0x00, 0x4c}) {
		t.Errorf("Ctrl+Alt+Del 报告 = %s，期望 05 00 4c…", hexOf(pt))
	}
	// the release follows 90ms later
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(rec.sentOf(CmdKeyPack)) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got = rec.sentOf(CmdKeyPack)
	if len(got) != 2 {
		t.Fatalf("松开的 KEY_PACK 没发出（%d 次）", len(got))
	}
	if pt := decryptInputPayload(t, kvmKey, got[1]); !bytes.Equal(pt, make([]byte, 16)) {
		t.Errorf("松开的报告 = %s，期望全 0", hexOf(pt))
	}
}

func TestSessionSendMouseAbs(t *testing.T) {
	s, rec, kvmKey := newReadySession(t)
	s.SendMouseAbs(400, 300, 1, 0) // -> 1500,1500 in the BMC's 0..3000 space

	got := rec.sentOf(CmdMousePack)
	if len(got) != 1 {
		t.Fatalf("MOUSE_PACK 发了 %d 次，期望 1 次", len(got))
	}
	pt := decryptInputPayload(t, kvmKey, got[0])
	want := []byte{0x01, 0x05, 0xdc, 0x05, 0xdc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(pt, want) {
		t.Errorf("绝对鼠标明文 = %s，期望 %s", hexOf(pt), hexOf(want))
	}

	// identical normalised position with the same buttons is deduplicated
	s.SendMouseAbs(400, 300, 1, 0)
	if n := len(rec.sentOf(CmdMousePack)); n != 1 {
		t.Errorf("重复位置被发了 %d 次，期望去重（1 次）", n)
	}
	// a button change must go through
	s.SendMouseAbs(400, 300, 0, 0)
	if n := len(rec.sentOf(CmdMousePack)); n != 2 {
		t.Errorf("按键变化后 %d 次，期望 2 次", n)
	}
	// wheel movement must go through even at the same position
	s.SendMouseAbs(400, 300, 0, 1)
	if n := len(rec.sentOf(CmdMousePack)); n != 3 {
		t.Errorf("滚轮事件后 %d 次，期望 3 次", n)
	}
}

func TestSessionSendMouseRelClamps(t *testing.T) {
	s, rec, kvmKey := newReadySession(t)

	s.SendMouseRel(300, -150, 2)
	got := rec.sentOf(CmdMousePack)
	if len(got) != 1 {
		t.Fatalf("MOUSE_PACK 发了 %d 次，期望 1 次", len(got))
	}
	// NB: the vendor's splitting loop can never run more than once — both deltas
	// are clamped to +/-120 *before* the loop, and each iteration subtracts
	// exactly the clamped value, leaving zero. The JS reference behaves
	// identically (verified by running its loop), so one packet is correct here.
	pt := decryptInputPayload(t, kvmKey, got[0])
	if want := []byte{0x02, 0x78, 0x88}; !bytes.Equal(pt[:3], want) { // +120, -120
		t.Errorf("夹紧后的明文 = %s，期望 %s", hexOf(pt[:3]), hexOf(want))
	}

	s.SendMouseRel(10, -5, 0)
	got = rec.sentOf(CmdMousePack)
	if len(got) != 2 {
		t.Fatalf("第二次 MOUSE_PACK 后共 %d 帧，期望 2", len(got))
	}
	if pt := decryptInputPayload(t, kvmKey, got[1]); !bytes.Equal(pt[:3], []byte{0x00, 0x0a, 0xfb}) {
		t.Errorf("小位移明文 = %s，期望 000afb", hexOf(pt[:3]))
	}

	// no movement, no packet (the loop body never runs)
	s.SendMouseRel(0, 0, 0)
	if n := len(rec.sentOf(CmdMousePack)); n != 2 {
		t.Errorf("零位移不应发包，实际共 %d 帧", n)
	}
}

func TestSessionRequestIFrameAndSetDqt(t *testing.T) {
	s, rec, _ := newReadySession(t)
	s.RequestIFrame()
	s.SetDqt(70, 2)

	if got := rec.sentOf(CmdIReq); len(got) != 1 || hexOf(got[0]) != "0800" {
		t.Errorf("I_REQ payload = %v，期望 0800", hexOf2(got))
	}
	if got := rec.sentOf(CmdDqtModeSet); len(got) != 1 || hexOf(got[0]) != "2700460200" {
		t.Errorf("DQT_MODE_SET payload = %v，期望 2700460200", hexOf2(got))
	}
	// dqtType 0 defaults to 1 (commit), matching the JS default parameter
	s.SetDqt(40, 0)
	if got := rec.sentOf(CmdDqtModeSet); len(got) != 2 || hexOf(got[1]) != "2700280100" {
		t.Errorf("DQT_MODE_SET(40, 0) = %v，期望 2700280100", hexOf2(got))
	}
}

// ---------------------------------------------------------------------------
// Heartbeat / lifecycle
// ---------------------------------------------------------------------------

func TestSessionStartHandshakeFrames(t *testing.T) {
	s, rec := newTestSession(t)
	s.StartHandshake()

	payloads := rec.sentPayloads()
	if len(payloads) != 2 {
		t.Fatalf("StartHandshake 应发 2 帧，实际 %d", len(payloads))
	}
	if hexOf(payloads[0]) != "0900" {
		t.Errorf("第一帧 = %s，期望 HEART_BEAT 0900", hexOf(payloads[0]))
	}
	if hexOf(payloads[1]) != "4200" {
		t.Errorf("第二帧 = %s，期望 GET_SUITE 4200", hexOf(payloads[1]))
	}
	// the first frame must be byte-identical to the captured heartbeat
	if got := hexOf(rec.sent[0]); got != "fef600043b9aca02ba980900" {
		t.Errorf("心跳帧 = %s，期望 fef600043b9aca02ba980900", got)
	}
}

func TestSessionCloseStopsTimers(t *testing.T) {
	s, rec := newTestSession(t)
	s.StartHandshake()
	s.onFrame(suiteListPayload()) // schedules MOUSE_MODE_SET(2) and FRAME_COMM(35)
	s.Close()
	if !s.Closed() {
		t.Fatal("Close 后 Closed() 应为 true")
	}
	time.Sleep(500 * time.Millisecond) // the 200/400ms timers would have fired by now
	if got := rec.sentOf(CmdMouseModeSet); len(got) != 0 {
		t.Errorf("Close 之后定时器仍发出了 MOUSE_MODE_SET：%v", hexOf2(got))
	}
	if got := rec.sentOf(CmdFrameComm); len(got) != 0 {
		t.Errorf("Close 之后定时器仍发出了 FRAME_COMM：%v", hexOf2(got))
	}
}
