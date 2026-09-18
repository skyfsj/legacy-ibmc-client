package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Browser fallback for machines without a usable system webview.
//
// macOS always ships WKWebView, so this path is not normally reached there.
// The realistic cases are Windows without the WebView2 runtime and Linux without
// WebKitGTK. Rather than bundling an engine (which is exactly what Electron does and
// what we are avoiding), we drive an already-installed Chromium-family browser in
// app mode and talk to our own loopback server over /api/call + SSE.
//
// We deliberately do NOT install a runtime automatically. Silently downloading and
// installing a browser/runtime is a heavyweight, privilege-touching action the user
// should opt into; when nothing is found we print the official installer instead.

type browser struct {
	name string
	app  string // macOS .app bundle name
	path string // executable path on other platforms
}

func candidates() []browser {
	switch runtime.GOOS {
	case "darwin":
		return []browser{
			{name: "Google Chrome", app: "Google Chrome"},
			{name: "Microsoft Edge", app: "Microsoft Edge"},
			{name: "Brave Browser", app: "Brave Browser"},
			{name: "Chromium", app: "Chromium"},
			{name: "Vivaldi", app: "Vivaldi"},
			{name: "Arc", app: "Arc"},
		}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		var out []browser
		for _, b := range []struct{ name, rel string }{
			{"Microsoft Edge", `Microsoft\Edge\Application\msedge.exe`},
			{"Google Chrome", `Google\Chrome\Application\chrome.exe`},
			{"Brave Browser", `BraveSoftware\Brave-Browser\Application\brave.exe`},
		} {
			for _, root := range []string{pf, pf86, os.Getenv("LOCALAPPDATA")} {
				if root == "" {
					continue
				}
				p := filepath.Join(root, b.rel)
				if _, err := os.Stat(p); err == nil {
					out = append(out, browser{name: b.name, path: p})
				}
			}
		}
		return out
	default: // linux, bsd
		var out []browser
		for _, name := range []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"microsoft-edge", "brave-browser", "vivaldi",
		} {
			if p, err := exec.LookPath(name); err == nil {
				out = append(out, browser{name: name, path: p})
			}
		}
		return out
	}
}

// findBrowser returns the first Chromium-family browser that exists on this machine.
func findBrowser() (browser, bool) {
	for _, b := range candidates() {
		switch runtime.GOOS {
		case "darwin":
			if _, err := os.Stat("/Applications/" + b.app + ".app"); err == nil {
				return b, true
			}
			if home, err := os.UserHomeDir(); err == nil {
				if _, err := os.Stat(filepath.Join(home, "Applications", b.app+".app")); err == nil {
					return b, true
				}
			}
		default:
			if b.path != "" {
				if _, err := os.Stat(b.path); err == nil {
					return b, true
				}
			}
		}
	}
	return browser{}, false
}

// launchBrowser opens the given URL in app mode (no tabs/address bar) if we find a
// suitable browser. Falls back to the system default opener, which still works but
// shows browser chrome.
func launchBrowser(url string) (string, error) {
	if url == "" {
		return "", errors.New("内部错误：未提供 URL")
	}
	if b, ok := findBrowser(); ok {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			// `open -na` reuses/creates an instance with our flags
			cmd = exec.Command("open", "-na", b.app, "--args",
				"--app="+url, "--new-window", "--user-data-dir="+appDataSubdir("browser"))
		default:
			cmd = exec.Command(b.path, "--app="+url, "--new-window",
				"--user-data-dir="+appDataSubdir("browser"))
		}
		if err := cmd.Start(); err != nil {
			return "", fmt.Errorf("启动 %s 失败: %w", b.name, err)
		}
		return b.name, nil
	}

	// Nothing chromium-based found.
	switch runtime.GOOS {
	case "darwin":
		if err := exec.Command("open", url).Start(); err == nil {
			return "系统默认浏览器", nil
		}
	case "windows":
		if err := exec.Command("cmd", "/c", "start", "", url).Start(); err == nil {
			return "系统默认浏览器", nil
		}
	default:
		if err := exec.Command("xdg-open", url).Start(); err == nil {
			return "系统默认浏览器", nil
		}
	}

	return "", errors.New(
		"未找到可用的浏览器。\n" +
			"请任选其一：\n" +
			"  • 安装 Chrome / Edge / Chromium 后重试（会以 app 模式打开，无地址栏）\n" +
			"  • Windows：安装 Microsoft Edge WebView2 运行时（约 2MB 的官方引导程序），\n" +
			"    之后即可用内置 webview 模式运行，无需浏览器\n" +
			"  • Linux：安装 libwebkit2gtk-4.1-0 后即可用内置 webview 模式运行")
}

// appDataSubdir keeps the fallback browser's profile out of the user's normal
// browser profile, so our window does not inherit their tabs/extensions.
func appDataSubdir(sub string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	p := filepath.Join(base, "huawei-ibmc-kvm-client", sub)
	os.MkdirAll(p, 0o700)
	return p
}
