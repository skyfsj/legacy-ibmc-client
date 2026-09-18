// Huawei iBMC KVM console — native shell.
//
// Replaces the Electron build: the protocol layer lives in Go (net / crypto/*,
// no bundled browser) and the UI renders in the OS webview via WKWebView, so the
// shipped app is a few MB instead of a few hundred.
//
// Web assets are served from an in-process loopback HTTP server on a random port.
// That is not a backend: same process, 127.0.0.1 only, started and stopped with the
// window. It gives the webview a real origin so ES modules and localStorage work
// (file:// origins restrict both).
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webview "github.com/webview/webview_go"

	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/ibmc"
	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/kvm"
	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/store"
	"github.com/skyfsj/legacy-ibmc-client/clients/go/internal/vmm"
)

var (
	readyCh   = make(chan struct{})
	readyOnce sync.Once
	wv        webview.WebView
	theStore  = store.New()

	mu      sync.Mutex
	session *kvm.Session
)

// ---------- event fan-out ----------
//
// The webview path calls JS directly. An external browser (the fallback when no
// system webview is usable) instead subscribes over Server-Sent Events on the same
// loopback server, so both transports deliver the identical event stream.

type event struct {
	Name string `json:"name"`
	Data any    `json:"data"`
}

var (
	evMu     sync.Mutex
	evSubs   = map[chan event]struct{}{}
	evRecent []event // small replay buffer so a late subscriber still gets state
)

func broadcast(name string, data any) {
	evMu.Lock()
	evRecent = append(evRecent, event{name, data})
	if len(evRecent) > 512 {
		evRecent = evRecent[len(evRecent)-256:]
	}
	subs := make([]chan event, 0, len(evSubs))
	for ch := range evSubs {
		subs = append(subs, ch)
	}
	evMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- event{name, data}:
		default: // slow consumer: drop rather than block the session
		}
	}
}

func subscribe() chan event {
	ch := make(chan event, 256)
	evMu.Lock()
	evSubs[ch] = struct{}{}
	evMu.Unlock()
	return ch
}

func unsubscribe(ch chan event) {
	evMu.Lock()
	delete(evSubs, ch)
	evMu.Unlock()
}

// ---------- Go -> JS ----------

// eventName maps the webview JS global to the transport-neutral event name.
var eventName = map[string]string{
	"__kvmLog": "log", "__kvmStatus": "status",
	"__kvmFrame": "frame", "__kvmSessions": "sessions",
	"__kvmConnectResult": "connectResult",
}

func jsCall(fn string, arg any) {
	if n, ok := eventName[fn]; ok {
		broadcast(n, arg)
	}
	if wv == nil {
		return
	}
	b, err := json.Marshal(arg)
	if err != nil {
		return
	}
	// JSON.stringify(...) keeps the payload safe inside the JS string literal.
	expr := fmt.Sprintf("window.%s && window.%s(JSON.parse(%s))", fn, fn, jsString(string(b)))
	wv.Dispatch(func() { wv.Eval(expr) })
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func emitLog(msg string) { jsCall("__kvmLog", msg) }

func emitStatus(state string, extra map[string]any) {
	m := map[string]any{"state": state}
	for k, v := range extra {
		m[k] = v
	}
	jsCall("__kvmStatus", m)
}

// ---------- JS-callable bindings ----------

type connectOpts struct {
	JnlpXML   string `json:"jnlpXml"`
	Host      string `json:"host"`
	HTTPSPort int    `json:"httpsPort"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Name      string `json:"name"`
	ColorBit  int    `json:"colorBit"`
	DQT       int    `json:"dqt"`
	Remember  bool   `json:"remember"`
}

// saveReq carries the password separately: store.Record.Password is json:"-"
// (input-only), so it cannot be populated by unmarshalling the record itself.
type saveReq struct {
	store.Record
	Password string `json:"password"`
}

type connectResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Host  string `json:"host,omitempty"`
	Port  int    `json:"port,omitempty"`
}

// connectAsync runs the (slow: HTTPS login + TCP dial) connect off the UI thread and
// reports the result through an event. A synchronous binding would freeze the window
// for the whole login, which also made the video stream back up and drop frames.
func connectAsync(optsJSON string) {
	go func() {
		res := doConnectJSON(optsJSON)
		jsCall("__kvmConnectResult", json.RawMessage(res))
	}()
}

func doConnectJSON(optsJSON string) string {
	var opts connectOpts
	if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
		return mustJSON(connectResult{Error: "参数解析失败: " + err.Error()})
	}
	return mustJSON(doConnect(&opts))
}

func saveJSON(recJSON string) string {
	var req saveReq
	if err := json.Unmarshal([]byte(recJSON), &req); err != nil {
		return mustJSON(map[string]any{"ok": false, "error": err.Error()})
	}
	rec := req.Record
	rec.Password = req.Password
	saved, err := theStore.Save(rec)
	if err != nil {
		return mustJSON(map[string]any{"ok": false, "error": err.Error()})
	}
	pushSessions()
	return mustJSON(map[string]any{"ok": true, "session": saved, "list": theStore.List()})
}

func doConnect(opts *connectOpts) connectResult {
	mu.Lock()
	if session != nil {
		session.Close()
		session = nil
	}
	mu.Unlock()

	var jnlpXML string
	var params map[string]string
	host := opts.Host
	kvmPort := 2198

	if opts.JnlpXML != "" {
		jnlpXML = opts.JnlpXML
		params = ibmc.ParseJnlpParams(jnlpXML)
		if m := jnlpCodebase(jnlpXML); m != "" {
			host = m
		}
		if p, ok := atoiSafe(params["port"]); ok {
			kvmPort = p
		}
		emitLog("使用手动提供的 JNLP")
	} else {
		resolved, err := theStore.ResolvePassword(store.ResolveOptions{
			ID: opts.ID, SessionID: opts.SessionID, Password: opts.Password,
		})
		if err != nil {
			return connectResult{Error: err.Error()}
		}
		pw := resolved.Password
		if resolved.Source == store.SourceKeychain {
			emitLog("使用已保存的密码（系统钥匙串）")
		}
		if opts.Host == "" || opts.Username == "" {
			return connectResult{Error: "缺少地址或用户名"}
		}
		if pw == "" {
			return connectResult{Error: "缺少密码"}
		}
		port := opts.HTTPSPort
		if port == 0 {
			port = 443
		}
		r, err := ibmc.Login(ibmc.LoginOptions{
			Host: host, Port: port, Username: opts.Username, Password: pw,
			Log: emitLog,
		})
		if err != nil {
			return connectResult{Error: err.Error()}
		}
		jnlpXML, params = r.JNLP, r.Params
		if r.Host != "" {
			host = r.Host
		}
		if p, ok := atoiSafe(params["port"]); ok {
			kvmPort = p
		}
		emitLog(fmt.Sprintf("JNLP 获取成功，刀片数=%s，KVM 端口=%d", params["bladesize"], kvmPort))

		// persist the machine; the password only when the user opted in
		rec := store.Record{
			ID: opts.ID, Name: opts.Name, Host: host, HTTPSPort: port,
			Username: opts.Username, ColorBit: opts.ColorBit, DQT: opts.DQT, Remember: opts.Remember,
		}
		if opts.Remember {
			rec.Password = pw
		}
		if saved, err := theStore.Save(rec); err == nil {
			if saved.HasPassword {
				emitLog(fmt.Sprintf("已保存机器「%s」（密码已加密存储）", saved.Name))
			} else {
				emitLog(fmt.Sprintf("已保存机器「%s」（未保存密码）", saved.Name))
			}
			pushSessions()
		} else {
			emitLog("会话保存失败：" + err.Error())
		}
	}

	colorBit := opts.ColorBit
	if jnlpXML != "" && colorBit == 0 {
		colorBit = 2
	}
	s := kvm.New(kvm.Options{
		Host: host, Port: kvmPort, Params: params, ColorBit: colorBit,
		Log: emitLog,
	})
	s.OnFrame = func(f kvm.Frame) {
		if f.NoChange {
			jsCall("__kvmFrame", map[string]any{"nochange": true, "frameNo": f.FrameNo})
			return
		}
		jsCall("__kvmFrame", map[string]any{
			"frameNo": f.FrameNo, "width": f.Width, "height": f.Height,
			"blockX": f.BlockX, "blockY": f.BlockY,
			"diff": f.Diff, "dqt": f.DQT, "iframe": f.IFrame,
			"stream": base64.StdEncoding.EncodeToString(f.Stream),
		})
	}
	s.OnAuthenticated = func() { emitStatus("authenticated", nil) }
	s.OnConnected = func() { emitStatus("tcp-connected", nil) }
	s.OnClosed = func() { emitStatus("closed", nil) }
	s.OnConnectState = func(v int) { emitStatus("connectstate", map[string]any{"value": v}) }
	s.OnMouseMode = func(v int) { emitStatus("mousemode", map[string]any{"value": v}) }
	s.OnDqt = func(v int) { emitStatus("dqt", map[string]any{"value": v}) }
	s.OnKeyState = func(v int) { emitStatus("keystate", map[string]any{"value": v}) }
	s.OnNotPri = func(v int) { emitStatus("notpri", map[string]any{"value": v}) }
	s.OnError = func(err error) { emitStatus("error", map[string]any{"message": err.Error()}) }

	mu.Lock()
	session = s
	mediaHost = host
	mu.Unlock()

	if err := s.Connect(); err != nil {
		return connectResult{Error: err.Error()}
	}
	s.StartHandshake()
	return connectResult{OK: true, Host: host, Port: kvmPort}
}

func withSession(f func(*kvm.Session)) {
	mu.Lock()
	s := session
	mu.Unlock()
	if s != nil {
		f(s)
	}
}

func pushSessions() {
	l := theStore.List()
	jsCall("__kvmSessions", map[string]any{"sessions": l.Sessions, "lastUsed": l.LastUsed})
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"marshal failed"}`
	}
	return string(b)
}

// ---------- small helpers ----------

func jnlpCodebase(xml string) string {
	const k = `codebase="`
	i := strings.Index(xml, k)
	if i < 0 {
		return ""
	}
	rest := xml[i+len(k):]
	j := strings.IndexAny(rest, `"/`)
	if j < 0 {
		return ""
	}
	h := rest[:j]
	return strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
}

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// ---------- web assets ----------

// listenPort is fixed on purpose: the webview's localStorage is keyed by
// scheme://host:port, so a random port would silently discard every saved setting
// (zoom, quality, debug) on each launch. If the port is taken we fall back to a
// random one — settings then reset for that run, which is better than not starting.
const listenPort = 47821

func serveAssets(dir string) (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/", loggingHandler(noStore(http.FileServer(http.Dir(dir)))))
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/call", handleCall)
	// Binding-independent trace channel: the page can report progress even when the
	// Go bindings are missing or broken, which is exactly when we need to know.
	mux.HandleFunc("/api/trace", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("[page]", r.URL.Query().Get("m"))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String() + "/", nil
}

// noStore keeps the webview from serving a cached copy of a JS file we just
// rebuilt, which otherwise looks like "my change did nothing".
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		h.ServeHTTP(w, r)
	})
}

// loggingHandler prints every asset request: a missing or mis-served file is the
// usual reason a webview shows nothing, and there is no other window into it.
func loggingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		h.ServeHTTP(rec, r)
		fmt.Printf("[assets] %s %s -> %d\n", r.Method, r.URL.Path, rec.code)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

// handleEvents streams events to an external browser over SSE. Same payloads the
// webview receives via jsCall, so app.js/bridge.js behave identically either way.
func handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := subscribe()
	defer unsubscribe(ch)

	// replay recent events so a late subscriber still gets resolution/status
	evMu.Lock()
	recent := append([]event(nil), evRecent...)
	evMu.Unlock()
	send := func(e event) bool {
		b, err := json.Marshal(e.Data)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Name, b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	for _, e := range recent {
		if !send(e) {
			return
		}
	}
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case e := <-ch:
			if !send(e) {
				return
			}
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleCall exposes the same operations the webview binds, over HTTP, for the
// external-browser fallback. Body: {"name":"goConnect","args":["{...}"]}
func handleCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string            `json:"name"`
		Args []json.RawMessage `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	arg := func(i int) string {
		if i >= len(req.Args) {
			return ""
		}
		var s string
		json.Unmarshal(req.Args[i], &s)
		return s
	}
	argInt := func(i int) int {
		if i >= len(req.Args) {
			return 0
		}
		var n int
		json.Unmarshal(req.Args[i], &n)
		return n
	}
	w.Header().Set("Content-Type", "application/json")
	var out string
	switch req.Name {
	case "goConnect", "goConnectAsync":
		// async: the HTTP client is not blocked either way, but keep one code path
		connectAsync(arg(0))
		out = `{"accepted":true}`
	case "goSessionsList":
		out = mustJSON(theStore.List())
	case "goSessionsSave":
		out = saveJSON(arg(0))
	case "goSessionsRemove":
		theStore.Remove(arg(0))
		pushSessions()
		out = mustJSON(map[string]any{"ok": true, "list": theStore.List()})
	case "goStorageInfo":
		out = mustJSON(map[string]any{"keyringAvailable": theStore.KeyringAvailable(), "file": theStore.File()})
	case "goDisconnect":
		withSession(func(s *kvm.Session) { s.Close() })
		out = "{}"
	case "goCtrlAltDel":
		withSession(func(s *kvm.Session) { s.CtrlAltDel() })
		out = "{}"
	case "goRequestIFrame":
		withSession(func(s *kvm.Session) { s.RequestIFrame() })
		out = "{}"
	case "goPower":
		var perr error
		withSession(func(s *kvm.Session) { perr = s.SendPower(byte(argInt(0))) })
		if perr != nil {
			out = mustJSON(map[string]any{"ok": false, "error": perr.Error()})
		} else {
			out = mustJSON(map[string]any{"ok": true})
		}
	case "goMouse":
		withSession(func(s *kvm.Session) { s.SendMouseAbs(argInt(0), argInt(1), argInt(2), argInt(3)) })
		out = "{}"
	case "goKey":
		var rep []int
		if len(req.Args) > 0 {
			json.Unmarshal(req.Args[0], &rep)
		}
		if len(rep) == 8 {
			var r [8]byte
			for i, v := range rep {
				r[i] = byte(v)
			}
			withSession(func(s *kvm.Session) { s.SendKeyboard(r) })
		}
		out = "{}"
	case "goSetDqt":
		withSession(func(s *kvm.Session) { s.SetDqt(argInt(0), argInt(1)) })
		out = "{}"
	case "goReady":
		out = "{}"
	case "goMedia":
		out = mustJSON(mediaAction(arg(0), arg(1)))
	case "goOpenBrowser":
		name, err := launchBrowser(arg(0))
		if err != nil {
			out = mustJSON(map[string]any{"ok": false, "error": err.Error()})
		} else {
			out = mustJSON(map[string]any{"ok": true, "browser": name})
		}
	default:
		http.Error(w, "unknown op "+req.Name, http.StatusBadRequest)
		return
	}
	w.Write([]byte(out))
}

func assetsDir() string {
	// .app layout first (Contents/MacOS/<exe> + Contents/Resources/web), then the
	// source tree so `go run .` works during development.
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, p := range []string{
			filepath.Join(dir, "..", "Resources", "web"),
			filepath.Join(dir, "web"),
		} {
			if _, err := os.Stat(filepath.Join(p, "index.html")); err == nil {
				return p
			}
		}
	}
	if _, err := os.Stat("web/index.html"); err == nil {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "web")
	}
	return "web"
}

func replayW64(v int) int { return (v + 63) / 64 }

var (
	replayPath string
	replayW    = 800
	replayH    = 600
	replayDqt  = 6
)

func main() {
	selftest := flag.Bool("selftest", false, "load the UI, verify it initialises, then exit")
	// replaytest drives the real Go -> webview -> decoder path with a captured frame,
	// so a rendering problem can be reproduced without a BMC login.
	mode := flag.String("mode", "auto", "auto | webview | browser")
	flag.StringVar(&replayPath, "replaytest", "", "push this frame .bin through the real webview decoder and report stats")
	flag.IntVar(&replayW, "w", 800, "replaytest: width")
	flag.IntVar(&replayH, "h", 600, "replaytest: height")
	flag.IntVar(&replayDqt, "dqt", 6, "replaytest: quantization table index")
	flag.Parse()

	url, err := serveAssets(assetsDir())
	if err != nil {
		log.Fatalf("静态资源服务启动失败: %v", err)
	}

	// Decide the UI host. `auto` prefers the system webview and falls back to an
	// installed Chromium browser driven in app mode (see browser.go).
	useBrowser := *mode == "browser"
	if *mode == "auto" || *mode == "webview" {
		if err := tryWebview(); err != nil {
			if *mode == "webview" {
				fmt.Fprintf(os.Stderr, "系统 webview 不可用: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "系统 webview 不可用（%v），改用已安装的浏览器\n", err)
			useBrowser = true
		}
	}

	if useBrowser {
		name, err := launchBrowser(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Printf("已在 %s 中打开：%s\n", name, url)
		fmt.Println("（关闭此窗口即退出；终端保持打开即可）")
		select {} // stay alive while the external browser drives the session
	}

	if replayPath != "" {
		raw, err := os.ReadFile(replayPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取帧文件失败:", err)
			os.Exit(1)
		}
		fmt.Printf("[replaytest] 送入 %d 字节，%dx%d，dqt=%d\n", len(raw), replayW, replayH, replayDqt)
		go func() {
			<-readyCh
			fmt.Println("[replaytest] 渲染层就绪，开始送帧")
			jsCall("__kvmFrame", map[string]any{
				"frameNo": 1, "width": replayW, "height": replayH,
				"blockX": replayW64(replayW), "blockY": replayW64(replayH),
				"diff": 0, "dqt": replayDqt, "iframe": 1,
				"stream": base64.StdEncoding.EncodeToString(raw),
			})
			fmt.Println("[replaytest] 已发送，等待解码…")
			time.Sleep(2500 * time.Millisecond)
			wv.Dispatch(func() {
				fmt.Println("[replaytest] 读取 __lastStats")
				wv.Eval("goReplayResult(JSON.stringify(window.__lastStats || {}))")
			})
			select {}
		}()
	}

	if *selftest {
		go func() {
			select {
			case <-readyCh:
				fmt.Println("[selftest] 通过")
				os.Exit(0)
			case <-time.After(15 * time.Second):
				fmt.Println("[selftest] 失败: 渲染层 15 秒内未就绪")
				os.Exit(1)
			}
		}()
	}

	wv.Navigate(url)
	wv.Run()
}

// tryWebview builds the window and wires every JS binding. It reports an error
// (rather than panicking) when the platform has no usable webview, so `auto` can
// fall back to the browser path.
func tryWebview() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	wv = webview.New(false)
	wv.SetTitle("iBMC 远程控制台")
	wv.SetSize(1180, 820, webview.HintNone)

	wv.Bind("goSessionsList", func() string { return mustJSON(theStore.List()) })
	wv.Bind("goSessionsSave", saveJSON)
	wv.Bind("goSessionsRemove", func(id string) string {
		theStore.Remove(id)
		pushSessions()
		return mustJSON(map[string]any{"ok": true, "list": theStore.List()})
	})
	wv.Bind("goConnectAsync", connectAsync)
	// Declare the transport explicitly. Sniffing for a binding name breaks silently
	// whenever a binding is renamed (it did: goConnect -> goConnectAsync).
	wv.Init("window.__kvmTransport = 'webview';")
	wv.Bind("goDisconnect", func() { withSession(func(s *kvm.Session) { s.Close() }) })
	wv.Bind("goKey", func(report []int) {
		if len(report) != 8 {
			return
		}
		var r [8]byte
		for i, v := range report {
			r[i] = byte(v)
		}
		withSession(func(s *kvm.Session) { s.SendKeyboard(r) })
	})
	wv.Bind("goMouse", func(x, y, buttons, wheel int) {
		withSession(func(s *kvm.Session) { s.SendMouseAbs(x, y, buttons, wheel) })
	})
	wv.Bind("goCtrlAltDel", func() { withSession(func(s *kvm.Session) { s.CtrlAltDel() }) })
	wv.Bind("goSetDqt", func(v, typ int) { withSession(func(s *kvm.Session) { s.SetDqt(v, typ) }) })
	wv.Bind("goRequestIFrame", func() { withSession(func(s *kvm.Session) { s.RequestIFrame() }) })
	wv.Bind("goMedia", func(action, path string) string {
		return mustJSON(mediaAction(action, path))
	})
	wv.Bind("goPower", func(cmd int) string {
		var err error
		withSession(func(s *kvm.Session) { err = s.SendPower(byte(cmd)) })
		if err != nil {
			return mustJSON(map[string]any{"ok": false, "error": err.Error()})
		}
		return mustJSON(map[string]any{"ok": true})
	})
	wv.Bind("goStorageInfo", func() string {
		return mustJSON(map[string]any{
			"keyringAvailable": theStore.KeyringAvailable(),
			"file":             theStore.File(),
		})
	})
	wv.Bind("goLog", func(m string) {
		// surface renderer-side problems on stdout too; without this a failing
		// bridge/app module is invisible from the terminal
		fmt.Println("[renderer]", m)
		emitLog(m)
	})
	wv.Bind("goReplayResult", func(statsJSON string) {
		fmt.Println("[replaytest] 解码统计:", statsJSON)
		var st struct {
			Consumed int `json:"consumed"`
			Expected int `json:"expected"`
			Blocks   int `json:"blocks"`
			JPEG     int `json:"jpeg"`
			JPEGErr  int `json:"jpegErrors"`
			Copy     int `json:"copy"`
			Invalid  int `json:"invalid"`
		}
		if err := json.Unmarshal([]byte(statsJSON), &st); err != nil {
			fmt.Println("[replaytest] 无法解析统计:", err)
			os.Exit(1)
		}
		ok := st.Consumed == st.Expected && st.JPEGErr == 0 && st.Blocks == replayW64(replayW)*replayW64(replayH)
		fmt.Printf("[replaytest] 块流 %d/%d  块 %d  JPEG %d(失败 %d)  复制 %d  无效 %d\n",
			st.Consumed, st.Expected, st.Blocks, st.JPEG, st.JPEGErr, st.Copy, st.Invalid)
		if ok {
			fmt.Println("[replaytest] ✅ 通过（真实帧经 Go → webview → 解码器）")
			os.Exit(0)
		}
		fmt.Println("[replaytest] ❌ 失败")
		os.Exit(1)
	})
	wv.Bind("goReady", func() {
		readyOnce.Do(func() {
			fmt.Println("[selftest] 渲染层就绪: true")
			close(readyCh)
		})
	})
	// The external-browser transport has no JS bindings; expose a no-op so the
	// bridge can detect "no bindings" and switch to HTTP.
	wv.Bind("goOpenBrowser", func(url string) string {
		name, err := launchBrowser(url)
		if err != nil {
			return mustJSON(map[string]any{"ok": false, "error": err.Error()})
		}
		return mustJSON(map[string]any{"ok": true, "browser": name})
	})
	return nil
}

// ---------- virtual media ----------

var (
	mediaMu   sync.Mutex
	mediaSess *vmm.Session
	mediaHost string // BMC host of the current KVM session (Status carries no host)
)

// mediaAction drives the VMM (virtual media) channel: mount an ISO or floppy image,
// detach, or query state. The VMM channel is separate from the KVM channel, so the
// first mount also performs the KVM-side negotiation that yields its code key + port.
func mediaAction(action, path string) map[string]any {
	mediaMu.Lock()
	defer mediaMu.Unlock()

	switch action {
	case "status":
		if mediaSess == nil {
			return map[string]any{"ok": true, "mounted": false}
		}
		return map[string]any{"ok": true, "mounted": true, "state": mediaSess.State().String()}

	case "detach":
		if mediaSess == nil {
			return map[string]any{"ok": true, "mounted": false}
		}
		if err := mediaSess.Close(); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		mediaSess = nil
		emitLog("已卸载虚拟介质")
		return map[string]any{"ok": true, "mounted": false}

	case "iso", "floppy":
		if path == "" {
			return map[string]any{"ok": false, "error": "未选择镜像文件"}
		}
		if mediaSess == nil {
			mu.Lock()
			ks := session
			mu.Unlock()
			if ks == nil {
				return map[string]any{"ok": false, "error": "请先连接服务器"}
			}
			// negotiate the VMM code key + port over the KVM channel
			boot, err := vmm.Negotiate(ks, ks.KvmKey(), true, 3*time.Second)
			if err != nil {
				return map[string]any{"ok": false, "error": "VMM 协商失败：" + err.Error()}
			}
			opts := boot.Options(mediaHost, ks.Status(), false)
			opts.Log = emitLog
			mediaSess = vmm.New(opts)
		}
		var err error
		if action == "iso" {
			err = mediaSess.MountISO(path)
		} else {
			err = mediaSess.MountFloppy(path, true)
		}
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		if action == "iso" {
			emitLog("已挂载 ISO：" + filepath.Base(path))
		} else {
			emitLog("已挂载软盘镜像（只读）：" + filepath.Base(path))
		}
		return map[string]any{"ok": true, "mounted": true, "state": mediaSess.State().String()}

	default:
		return map[string]any{"ok": false, "error": "未知操作 " + action}
	}
}
