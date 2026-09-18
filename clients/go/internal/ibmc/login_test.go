package ibmc

// Login tests. The BMC itself is replaced by a stubbed HTTPS server that
// reproduces the parts of the flow the client depends on: the cookie warmup (the
// BMC answers 403 without it), the DirectKVM/AddSession login POST, and
// kvm.php serving either the JNLP or a page pointing at it.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const testJNLP = `<?xml version="1.0" encoding="utf-8"?>
<jnlp spec="1.0+" codebase="https://10.0.0.5:443/" href="vconsole.jnlp">
  <information><title>iBMC KVM</title></information>
  <resources><jar href="vconsole.jar" /></resources>
  <applet-desc name="KVM" main-class="com.kvm.KVMApplet" width="1" height="1">
    <param name="port" value="2198" />
    <param name="vmmPort" value="8208" />
    <param name="verifyValue" value="1000000001" />
    <param name="verifyValueExt" value="00000000" />
    <param name="decrykey" value="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" />
    <param name="compress" value="1" />
  </applet-desc>
</jnlp>`

func TestParseJnlpParams(t *testing.T) {
	params := ParseJnlpParams(strings.ReplaceAll(testJNLP, `00112233445566778899aabbccddeeff`,
		"00112233445566778899aabbccddeeff"))
	want := map[string]string{
		"port":           "2198",
		"vmmPort":        "8208",
		"verifyValue":    "1000000001",
		"verifyValueExt": "00000000",
		"decrykey":       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"compress":       "1",
	}
	for k, v := range want {
		if params[k] != v {
			t.Errorf("params[%q] = %q，期望 %q", k, params[k], v)
		}
	}
	if len(params) != len(want) {
		t.Errorf("参数个数 = %d，期望 %d（%v）", len(params), len(want), params)
	}

	userKey, userIV, err := SessionKeys(params)
	if err != nil {
		t.Fatal(err)
	}
	if len(userKey) != 16 || len(userIV) != 16 {
		t.Errorf("decrykey 拆分 = %d/%d 字节，期望 16/16", len(userKey), len(userIV))
	}
	if _, _, err := SessionKeys(map[string]string{"decrykey": "00112233445566778899aabbccddeeff"}); err == nil {
		t.Error("decrykey 长度不对时应报错")
	}
}

func TestFindJnlpURL(t *testing.T) {
	const base = "https://192.168.1.100:443"
	cases := []struct {
		text string
		want string
	}{
		{`<a href="/bmc/pages/remote/vconsole.jnlp">go</a>`, base + "/bmc/pages/remote/vconsole.jnlp"},
		{`window.open("/bmc/x.jnlp","_self")`, base + "/bmc/x.jnlp"},
		{`location.href = "https://other.host:443/a.jnlp"`, "https://other.host:443/a.jnlp"},
		{`<script src="//cdn.host/vconsole.jnlp"></script>`, "https://cdn.host/vconsole.jnlp"},
		// NB: the JS pattern list matches any href/src, not just *.jnlp, so a
		// non-JNLP link is returned too and simply fails the follow-up fetch.
		{`<img src="pic.png">`, base + "/pic.png"},
		{`plain text with no links at all`, ""},
	}
	for _, tc := range cases {
		got, found := FindJnlpURL(tc.text, base)
		if tc.want == "" {
			if found {
				t.Errorf("FindJnlpURL(%q) = %q，期望找不到", tc.text, got)
			}
			continue
		}
		if !found || got != tc.want {
			t.Errorf("FindJnlpURL(%q) = %q/%v，期望 %q", tc.text, got, found, tc.want)
		}
	}
}

func TestDescribeAuthCode(t *testing.T) {
	cases := map[int]string{
		130: "用户名或密码错误",
		131: "账号已被锁定",
		136: "用户无访问权限",
		137: "用户名或密码已过期",
		144: "登录用户数已达上限",
		999: "登录失败（返回码 999）",
	}
	for code, want := range cases {
		if got := DescribeAuthCode(code); got != want {
			t.Errorf("DescribeAuthCode(%d) = %q，期望 %q", code, got, want)
		}
	}
}

// loginStub is the fake BMC: it enforces the cookie warmup exactly like the
// firmware does (403 without the pre-session cookie) and records what it saw.
type loginStub struct {
	t *testing.T

	warmupOK      bool // /login.html was fetched before the POST
	loginCalls    int
	addSessionReq bool
	lastForm      string
	lastCT        string
	lastAccept    string

	directKVM any    // JSON value returned for DirectKVM (nil = use AuthUser)
	authUser  any    // JSON value returned for AuthUser
	jnlpBody  string // body served by kvm.php ("" = 404-ish HTML page)
	jnlpPath  string // path that serves the JNLP
}

func (s *loginStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login.html":
		http.SetCookie(w, &http.Cookie{Name: "pre", Value: "1", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	case "/bmc/php/processparameter.php":
		s.loginCalls++
		if _, err := r.Cookie("pre"); err != nil {
			// the real BMC answers 403 when the warmup GET never happened
			w.WriteHeader(http.StatusForbidden)
			return
		}
		s.warmupOK = true
		s.lastCT = r.Header.Get("Content-Type")
		s.lastAccept = r.Header.Get("Accept")
		if body, err := io.ReadAll(r.Body); err == nil {
			s.lastForm = string(body)
		}
		if strings.Contains(s.lastForm, "func=AddSession") {
			s.addSessionReq = true
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "abc", Path: "/"})
			_, _ = w.Write([]byte(`{"AddSession":[0,"abcdef"]}`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "abc", Path: "/"})
		if s.directKVM != nil {
			_, _ = w.Write([]byte(`{"DirectKVM":` + toJSON(s.directKVM) + `}`))
			return
		}
		_, _ = w.Write([]byte(`{"AuthUser":` + toJSON(s.authUser) + `}`))
	case "/bmc/pages/remote/kvm.php":
		if _, err := r.Cookie("SID"); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if s.jnlpPath == "" || r.URL.Path != s.jnlpPath {
			// kvm.php serves a page that points at the JNLP
			_, _ = w.Write([]byte(`<html><body><a href="/bmc/pages/remote/tmp.jnlp">console</a></body></html>`))
			return
		}
		_, _ = w.Write([]byte(s.jnlpBody))
	case "/bmc/pages/remote/tmp.jnlp":
		_, _ = w.Write([]byte(s.jnlpBody))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func toJSON(v any) string {
	blob, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(blob)
}

func startStub(t *testing.T, stub *loginStub) (string, int, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(stub)
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	return host, port, client
}

func TestLoginDirectKVM(t *testing.T) {
	stub := &loginStub{t: t, directKVM: []any{0}, jnlpPath: "/bmc/pages/remote/kvm.php", jnlpBody: testJNLP}
	host, port, client := startStub(t, stub)

	res, err := Login(LoginOptions{
		Host: host, Port: port, Username: "root", Password: "p@ss", HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("Login 失败：%v", err)
	}
	if !stub.warmupOK {
		t.Error("登录前必须先 GET /login.html 取 cookie，否则 BMC 会回 403")
	}
	if stub.lastForm != "check_pwd=p%40ss&logtype=0&user_name=root&func=DirectKVM&IsKvmApp=0" {
		t.Errorf("表单 = %q", stub.lastForm)
	}
	if stub.lastCT != "application/x-www-form-urlencoded; charset=UTF-8" {
		t.Errorf("Content-Type = %q", stub.lastCT)
	}
	if !strings.Contains(stub.lastAccept, "application/json") {
		t.Errorf("Accept = %q", stub.lastAccept)
	}
	if !strings.Contains(res.JNLP, "<jnlp") {
		t.Errorf("JNLP = %q", res.JNLP)
	}
	if res.Params["port"] != "2198" || res.Params["verifyValue"] != "1000000001" {
		t.Errorf("JNLP 参数 = %v", res.Params)
	}
	if res.Host != "10.0.0.5" {
		t.Errorf("host = %q，期望取自 codebase 的 10.0.0.5", res.Host)
	}
	if res.JNLPURL == "" || !strings.Contains(res.JNLPURL, "kvm.php") {
		t.Errorf("jnlpUrl = %q", res.JNLPURL)
	}
	if res.CookieHeader == "" {
		t.Error("CookieHeader 为空，cookie 罐没生效")
	}
}

// TestLoginViaJnlpLink covers kvm.php returning a page that points at the JNLP
// instead of the JNLP itself.
func TestLoginViaJnlpLink(t *testing.T) {
	// the firmware answers with the array form ([0]); a bare 0 is falsy in JS
	stub := &loginStub{t: t, directKVM: []any{0}, jnlpBody: testJNLP}
	host, port, client := startStub(t, stub)

	res, err := Login(LoginOptions{Host: host, Port: port, Username: "root", Password: "pw", HTTPClient: client})
	if err != nil {
		t.Fatalf("Login 失败：%v", err)
	}
	if !strings.Contains(res.JNLPURL, "tmp.jnlp") {
		t.Errorf("应从页面里找到 JNLP 链接，实际 jnlpUrl = %q", res.JNLPURL)
	}
}

// TestLoginAddSessionFallback covers the firmware that answers AuthUser instead
// of DirectKVM.
func TestLoginAddSessionFallback(t *testing.T) {
	stub := &loginStub{t: t, authUser: []any{0}, jnlpPath: "/bmc/pages/remote/kvm.php", jnlpBody: testJNLP}
	host, port, client := startStub(t, stub)

	if _, err := Login(LoginOptions{Host: host, Port: port, Username: "root", Password: "pw", HTTPClient: client}); err != nil {
		t.Fatalf("Login 失败：%v", err)
	}
	if !stub.addSessionReq {
		t.Error("AuthUser=0 时应回落到 AddSession 登录")
	}
	if stub.loginCalls != 2 {
		t.Errorf("登录 POST 次数 = %d，期望 2（DirectKVM + AddSession）", stub.loginCalls)
	}
}

func TestLoginAuthCodeError(t *testing.T) {
	stub := &loginStub{t: t, authUser: []any{130}, jnlpBody: testJNLP}
	host, port, client := startStub(t, stub)

	_, err := Login(LoginOptions{Host: host, Port: port, Username: "nouser", Password: "pw", HTTPClient: client})
	if err == nil {
		t.Fatal("登录返回码非 0 时必须报错")
	}
	if !strings.Contains(err.Error(), "用户名或密码错误") {
		t.Errorf("错误 = %q，期望「用户名或密码错误」", err.Error())
	}
}

func TestLoginNoJnlpActionableError(t *testing.T) {
	stub := &loginStub{t: t, directKVM: []any{0}, jnlpBody: ""}
	host, port, client := startStub(t, stub)

	_, err := Login(LoginOptions{Host: host, Port: port, Username: "root", Password: "pw", HTTPClient: client})
	if err == nil {
		t.Fatal("拿不到 JNLP 时必须报错")
	}
	for _, want := range []string{"未能从 kvm.php 取得 JNLP", "用 JNLP 文件连接", "每个 JNLP 只能用一次"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误 = %q，应包含 %q", err.Error(), want)
		}
	}
}

func TestLoginForbiddenWithoutCookieWarmup(t *testing.T) {
	// A stub whose /login.html is unreachable: the POST then answers 403, which
	// is exactly why the warmup is mandatory.
	stub := &loginStub{t: t, directKVM: []any{0}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.html" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		stub.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	_, err = Login(LoginOptions{Host: host, Port: port, Username: "root", Password: "pw", HTTPClient: client})
	if err == nil {
		t.Fatal("cookie 预热失败后登录应被 BMC 拒绝")
	}
	if !strings.Contains(err.Error(), "登录失败") {
		t.Errorf("错误 = %q，期望登录失败", err.Error())
	}
}
