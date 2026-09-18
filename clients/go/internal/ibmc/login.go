// Package ibmc implements the iBMC web login and JNLP retrieval.
//
// Flow reverse-engineered from the served frontend (/bmc/resources/js/login.js):
//
//	POST /bmc/php/processparameter.php
//	     { check_pwd, logtype, user_name, func, IsKvmApp }
//	func = "AddSession"  -> normal web login
//	func = "DirectKVM"   -> granted a KVM session directly; the web UI then opens
//	                        /bmc/pages/remote/kvm.php?kvmway=0  (this firmware
//	                        serves the JNLP for both kvmway values)
//
// The session cookie from that POST is what authorises kvm.php, so we keep a
// cookie jar.
package ibmc

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// LoginOptions configures Login.
type LoginOptions struct {
	Host     string
	Port     int // HTTPS port, default 443
	Username string
	Password string
	// Log receives progress messages (may be nil).
	Log func(string)
	// HTTPClient overrides the transport (tests, or a caller that wants its own
	// policy). When nil a client with a cookie jar and the self-signed-cert
	// policy below is used.
	HTTPClient *http.Client
}

// LoginResult is the outcome of a successful login.
type LoginResult struct {
	// JNLP is the raw JNLP XML.
	JNLP string
	// Params are the JNLP <param> entries (port, verifyValue, verifyValueExt,
	// decrykey, ...). Feed them to kvm.New.
	Params map[string]string
	// JNLPURL is the URL the JNLP was actually served from.
	JNLPURL string
	// Host is the BMC host taken from the JNLP codebase (falls back to the
	// requested host).
	Host string
	// CookieHeader is the cookie state after the flow (diagnostics).
	CookieHeader string
	// Raw is the parsed login JSON response (diagnostics; may be nil).
	Raw map[string]any
}

var (
	reJnlp        = regexp.MustCompile(`(?i)<jnlp[\s>]`)
	reJnlpURL     = regexp.MustCompile(`(?i)["']([^"']*\.jnlp[^"']*)["']`)
	reHrefSrc     = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"']+)["']`)
	reWindowOpen  = regexp.MustCompile(`(?i)window\.open\(\s*["']([^"']+)["']`)
	reURLAssign   = regexp.MustCompile(`(?i)(?:url|location\.href)\s*[=:]\s*["']([^"']+)["']`)
	reParam       = regexp.MustCompile(`(?i)<param\s+name="([^"]+)"\s+value="([^"]*)"\s*/?>`)
	reCodebase    = regexp.MustCompile(`(?i)codebase="https?://([^"/]+)`)
	reHTMLConsole = regexp.MustCompile(`(?i)html5|noVNC|novnc|websocket`)
	reHTTP        = regexp.MustCompile(`(?i)^https?:`)
)

const requestTimeout = 30 * time.Second

// Login logs in and obtains a JNLP session descriptor.
func Login(opts LoginOptions) (*LoginResult, error) {
	port := opts.Port
	if port == 0 {
		port = 443
	}
	say := func(string) {}
	if opts.Log != nil {
		say = opts.Log
	}
	base := fmt.Sprintf("https://%s:%d", opts.Host, port)

	hc := opts.HTTPClient
	if hc == nil {
		hc = newHTTPClient()
	}
	if hc.Timeout == 0 {
		hc.Timeout = requestTimeout
	}
	c := &bmcClient{http: hc, base: base}

	// Warm up / pick up any pre-session cookie. The BMC answers 403 to the login
	// POST (and to kvm.php) unless this GET came first, so it is not optional.
	if _, _, err := c.do("GET", "/login.html", nil, nil); err != nil {
		say(fmt.Sprintf("预取 /login.html 失败（继续尝试）：%v", err))
	}

	form := encodeForm([][2]string{
		{"check_pwd", opts.Password},
		{"logtype", "0"},
		{"user_name", opts.Username},
		{"func", "DirectKVM"},
		{"IsKvmApp", "0"},
	})

	say("登录中（DirectKVM）…")
	resp, body, err := c.do("POST", "/bmc/php/processparameter.php", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		"Accept":       "application/json, text/javascript, */*; q=0.01",
	}, form)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		doc = nil // not json
	}

	directOK := false
	var authErr error
	switch {
	case doc != nil && jsTruthy(doc["DirectKVM"]):
		ret, ok := asJSONInt(doc["DirectKVM"])
		if ok && ret == 0 {
			directOK = true
		} else {
			say(fmt.Sprintf("DirectKVM 返回码 %v", doc["DirectKVM"]))
		}
	case doc != nil && jsTruthy(doc["AuthUser"]):
		ret, _ := asJSONInt(doc["AuthUser"])
		if ret == 0 {
			say("DirectKVM 不被支持，改用 AddSession 普通登录…")
			form2 := encodeForm([][2]string{
				{"check_pwd", opts.Password},
				{"logtype", "0"},
				{"user_name", opts.Username},
				{"func", "AddSession"},
				{"IsKvmApp", "0"},
			})
			_, body2, err := c.do("POST", "/bmc/php/processparameter.php", map[string]string{
				"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
				"Accept":       "application/json, text/javascript, */*; q=0.01",
			}, form2)
			if err != nil {
				return nil, err
			}
			var doc2 map[string]any
			if err := json.Unmarshal(body2, &doc2); err == nil {
				doc = doc2
			}
			if sess, ok := doc["AddSession"].([]any); ok && len(sess) >= 2 {
				code, _ := asJSONInt(sess[0])
				if code == 0 && jsTruthy(sess[1]) {
					directOK = true
				}
			}
		} else {
			authErr = errors.New(DescribeAuthCode(ret))
		}
	default:
		if resp.StatusCode == 200 && doc == nil {
			return nil, errors.New("登录响应无法解析（可能地址或端口不对）")
		}
	}

	if authErr != nil {
		return nil, authErr
	}
	if !directOK {
		return nil, errors.New("登录失败：未取得 KVM 会话")
	}

	// Fetch the console entry point; it either returns the JNLP or a page pointing at it.
	// The frontend builds this URL as: kvmway = "jre" (default) | requestStr["openway"];
	//   way = (kvmway == "html5") ? "?kvmway=1" : "?kvmway=0"
	//   window.open("/bmc/pages/remote/kvm.php" + way, "_self")
	// On this firmware kvmway=1 also returns the JNLP (verified 2026-09-18): there is
	// no HTML5 console, the html5 branch in the frontend is dead code.
	stamp := time.Now().UnixMilli()
	candidates := []string{
		"/bmc/pages/remote/kvm.php?kvmway=0",
		fmt.Sprintf("/bmc/pages/remote/kvm.php?kvmway=0&random_str=%d", stamp),
		"/bmc/pages/remote/kvm.php",
	}
	var jnlpText, jnlpURL string
	for _, path := range candidates {
		// mimic the real top-level navigation so referer-based checks don't reject us
		r, text, err := c.do("GET", path, map[string]string{
			"Accept":  "*/*",
			"Referer": base + "/login.html",
		}, nil)
		if err != nil {
			say(fmt.Sprintf("GET %s → 失败：%v", path, err))
			continue
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "?"
		}
		cd := r.Header.Get("Content-Disposition")
		say(fmt.Sprintf("GET %s → %d, %dB, content-type=%s%s", path, r.StatusCode, len(text), ct,
			cond(cd != "", fmt.Sprintf(", disposition=%s", cd), "")))
		if reJnlp.Match(text) {
			jnlpText, jnlpURL = string(text), base+path
			break
		}
		if u, found := FindJnlpURL(string(text), base); found && u != base+path {
			r2, txt2, err := c.do("GET", requestTarget(base, u), map[string]string{"Accept": "*/*"}, nil)
			if err == nil && reJnlp.Match(txt2) {
				jnlpText, jnlpURL = string(txt2), u
				break
			}
			status := 0
			if r2 != nil {
				status = r2.StatusCode
			}
			say(fmt.Sprintf("  指向的 %s 不是 JNLP（%d）", u, status))
		}
		// Not a JNLP: show a snippet so the reason is visible instead of just "failed".
		snippet := collapseWhitespace(string(text))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		say(fmt.Sprintf("  不是 JNLP，响应开头：%s", orEmpty(snippet, "(空)")))
		if reHTMLConsole.Match(text) {
			say("  ⚠️ 该页面提到了 html5/websocket —— 可能另有 HTML5 控制台")
		}
	}
	if jnlpText == "" {
		return nil, errors.New(
			"未能从 kvm.php 取得 JNLP。\n" +
				"请点「用 JNLP 文件连接…」，选一个从 Web UI 下载的 .jnlp 文件绕过这一步。\n" +
				"（每个 JNLP 只能用一次，所以每次都要重新下载。）")
	}

	params := ParseJnlpParams(jnlpText)
	result := &LoginResult{
		JNLP:    jnlpText,
		Params:  params,
		JNLPURL: jnlpURL,
		Host:    opts.Host,
		Raw:     doc,
	}
	if m := reCodebase.FindStringSubmatch(jnlpText); m != nil {
		result.Host = strings.Split(m[1], ":")[0]
	}
	if jar := hc.Jar; jar != nil {
		if u, err := url.Parse(base); err == nil {
			var parts []string
			for _, ck := range jar.Cookies(u) {
				parts = append(parts, ck.Name+"="+ck.Value)
			}
			result.CookieHeader = strings.Join(parts, "; ")
		}
	}
	return result, nil
}

// bmcClient is the tiny request layer: base URL + cookie-jar-carrying client.
type bmcClient struct {
	http *http.Client
	base string
}

func (c *bmcClient) do(method, path string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp, nil, err
	}
	return resp, data, nil
}

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil) // nil PublicSuffixList: single-host flow, no x/net needed
	return &http.Client{
		Timeout: requestTimeout,
		Jar:     jar,
		Transport: &http.Transport{
			// The BMC ships a self-signed certificate; there is no CA to pin
			// against. This mirrors what the vendor's own Java applet / browser
			// flow accepts. The session itself is protected by the JNLP
			// handshake, not by the HTTPS certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// FindJnlpURL extracts the JNLP URL from whatever kvm.php returned (JNLP itself,
// HTML, or a redirect target). base is scheme://host[:port].
func FindJnlpURL(text, base string) (string, bool) {
	patterns := []*regexp.Regexp{reJnlpURL, reHrefSrc, reWindowOpen, reURLAssign}
	for _, re := range patterns {
		m := re.FindStringSubmatch(text)
		if m == nil || m[1] == "" {
			continue
		}
		u := m[1]
		switch {
		case strings.HasPrefix(u, "//"):
			u = "https:" + u
		case strings.HasPrefix(u, "/"):
			u = base + u
		case !reHTTP.MatchString(u):
			u = base + "/" + strings.TrimPrefix(strings.TrimPrefix(u, "./"), "/")
		}
		return u, true
	}
	return "", false
}

// requestTarget turns a URL found on a page into something to GET from the BMC
// itself: the same-host path when possible, otherwise the absolute URL.
func requestTarget(base, u string) string {
	if strings.HasPrefix(u, base) {
		rest := strings.TrimPrefix(u, base)
		if rest == "" {
			return "/"
		}
		return rest
	}
	if strings.HasPrefix(u, "/") {
		return u
	}
	return u
}

// ParseJnlpParams extracts the <param name=... value=...> map from a JNLP.
func ParseJnlpParams(xml string) map[string]string {
	params := map[string]string{}
	for _, m := range reParam.FindAllStringSubmatch(xml, -1) {
		params[m[1]] = m[2]
	}
	return params
}

// SessionKeys splits the JNLP decrykey parameter into the AES key/IV material:
// user_key = decrykey[0:16], user_iv = decrykey[16:32].
func SessionKeys(params map[string]string) (userKey, userIV []byte, err error) {
	decry, err := hex.DecodeString(params["decrykey"])
	if err != nil || len(decry) != 32 {
		return nil, nil, errors.New("decrykey 长度不是 32 字节")
	}
	return decry[0:16], decry[16:32], nil
}

// DescribeAuthCode maps a login return code to a user-facing message.
func DescribeAuthCode(code int) string {
	// 130 was observed live for a nonexistent user (verified 2026-09-18); the rest
	// are the codes the vendor's login.js maps explicitly.
	switch code {
	case 130:
		return "用户名或密码错误"
	case 131:
		return "账号已被锁定"
	case 136:
		return "用户无访问权限"
	case 137:
		return "用户名或密码已过期"
	case 144:
		return "登录用户数已达上限"
	}
	return fmt.Sprintf("登录失败（返回码 %d）", code)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// encodeForm serialises pairs in the given order (JS URLSearchParams order
// matters to nobody but makes the traffic byte-identical to the reference).
func encodeForm(pairs [][2]string) []byte {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p[1]))
	}
	return []byte(b.String())
}

// asJSONInt pulls an int out of a decoded JSON value, unwrapping the array form
// the BMC uses ([0] / [0, "session"]). ok is false when the value is not
// numeric.
func asJSONInt(v any) (int, bool) {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			return 0, false
		}
		return asJSONInt(t[0])
	case float64:
		return int(t), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			f, err := t.Float64()
			if err != nil {
				return 0, false
			}
			return int(f), true
		}
		return int(n), true
	}
	return 0, false
}

// jsTruthy mirrors JavaScript truthiness for the handful of JSON shapes the
// login response can take (this is what decides which branch the reference
// takes, e.g. {"DirectKVM": 0} is falsy while {"DirectKVM": [0]} is not).
func jsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case json.Number:
		f, err := t.Float64()
		return err != nil || f != 0
	case string:
		return t != ""
	case []any:
		return true // an empty array is truthy in JS
	case map[string]any:
		return true
	}
	return true
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func cond(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

func orEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
