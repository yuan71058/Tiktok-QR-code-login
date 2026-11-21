package main

// ticketguard.go —— bd-ticket-guard-* 请求头
//
// 依据：web/protocol/STATE-MACHINE.md §4 —— `838.b031aa6c.js@593736` 的
// `setConfig({certType:"header", scene:"web_protect", ... providerPathList:[...]})`，
// 其中 **/passport/web/check_qrconnect/ 就在 providerPathList 里**。
// 也就是说这个端点必须带 ticket-guard 头，否则端侧风控直接 4031。
//
// 实测（web/protect/ticketguard-report.json）：真机四个头是
//
//	bd-ticket-guard-version:        2
//	bd-ticket-guard-web-version:    2
//	bd-ticket-guard-web-sign-type:  0
//	bd-ticket-guard-ree-public-key: <base64(0x04||X||Y) 65 字节 P-256 公钥>
//
// 前三个是常量，公钥是**端上本地生成的 P-256 密钥对**（不需要服务端证书），
// 所以纯 Go 标准库就能造：crypto/ecdsa + crypto/elliptic + encoding/base64。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// TicketGuard 一对本地 P-256 密钥 + 对应请求头。
type TicketGuard struct {
	Private *ecdsa.PrivateKey
	Headers map[string]string
}

// NewTicketGuard 生成端侧 P-256 密钥对并拼出四个请求头。
// 真机公钥是 65 字节未压缩点（首字节 0x04），base64 后 88 字符 —— 与实测长度一致。
func NewTicketGuard() (*TicketGuard, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ticket-guard 密钥对: %w", err)
	}
	raw := make([]byte, 65)
	raw[0] = 0x04
	priv.PublicKey.X.FillBytes(raw[1:33])
	priv.PublicKey.Y.FillBytes(raw[33:65])

	return &TicketGuard{
		Private: priv,
		Headers: map[string]string{
			"bd-ticket-guard-version":        "2",
			"bd-ticket-guard-web-version":    "2",
			"bd-ticket-guard-web-sign-type":  "0",
			"bd-ticket-guard-ree-public-key": base64.StdEncoding.EncodeToString(raw),
		},
	}, nil
}

// PublicKeyB64 当前的 ree-public-key 头值（88 字符）。
func (t *TicketGuard) PublicKeyB64() string {
	if t == nil {
		return ""
	}
	return t.Headers["bd-ticket-guard-ree-public-key"]
}

// needsTicketGuard 哪些端点必须带 ticket-guard 头。
//
// 取自 838.b031aa6c.js 的 providerPathList（会产生 bd-ticket-guard-* 签名的端点）。
// 本任务只实跑 check_qrconnect，其余列出以便后续扩展到 sms_login / user_login。
var ticketGuardPaths = map[string]bool{
	PathCheckQRConnect: true,
	// 未实现但同属 providerPathList（打 sms_login / user_login 时需要）：
	// /passport/web/sms_login/  /passport/web/sms_login_only/
	// /passport/web/email/login/  /passport/web/email/code_login/
	// /passport/web/email/quick_login/  /passport/web/web_login/
	// /passport/web/user/login/
}

func needsTicketGuard(path string) bool { return ticketGuardPaths[path] }
