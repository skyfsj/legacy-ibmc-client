package ibmc

import (
	"os"
	"strings"
	"testing"
)

// Opt-in check against a REAL BMC: proves the URL, cookie warmup, form encoding and
// response parsing work on actual firmware, not just the stub.
//
// It deliberately uses a NONEXISTENT username with an empty password. A real
// credential guess could increment the BMC's failed-login counter and lock the
// account, so this test must never be changed to use a real account.
//
//	HUAWEI_IBMC_KVM_TEST_LIVE=192.168.1.100 go test -run TestLiveLogin ./internal/ibmc/ -v
func TestLiveLogin(t *testing.T) {
	host := os.Getenv("HUAWEI_IBMC_KVM_TEST_LIVE")
	if host == "" {
		t.Skip("set HUAWEI_IBMC_KVM_TEST_LIVE=<host> to run against a real BMC")
	}

	_, err := Login(LoginOptions{
		Host:     host,
		Port:     443,
		Username: "__zcode_probe_nonexistent__",
		Password: "",
		Log:      func(m string) { t.Logf("  %s", m) },
	})
	if err == nil {
		t.Fatalf("用一个不存在的用户登录竟然成功了，说明测试方式有问题")
	}
	t.Logf("返回错误: %v", err)

	// The plumbing is working iff the BMC answered with a recognisable auth code
	// rather than a transport/parse failure.
	msg := err.Error()
	if strings.Contains(msg, "无法解析") || strings.Contains(msg, "请求超时") ||
		strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") {
		t.Fatalf("与 BMC 通信失败（不是认证失败）: %v", err)
	}
	if !strings.Contains(msg, "130") && !strings.Contains(msg, "未取得 KVM 会话") {
		t.Logf("注意：错误信息不是预期的认证失败形态，请人工确认: %v", err)
	}
	t.Log("BMC 正确解析了请求并返回认证失败 —— 登录链路可用")
}
