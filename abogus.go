package main

// abogus.go —— a_bogus 可选外挂签名器桥
//
// 实测边界（见 README「已知边界」）：
//   · GET  /passport/web/get_qrcode/     → **不需要** a_bogus，error_code=0
//   · POST /passport/web/check_qrconnect/ → **必须** 带 a_bogus，缺了必 4031
//     （4 组对照实测：form6+a_bogus=0/new，form6 无 a_bogus=4031，
//       json6+a_bogus=3「缺少参数」，json6 无 a_bogus=4031）
//
// a_bogus 是 bdms.js 里 JSVMP 字节码算出来的，纯 Go 复刻等于再造一台解释器，
// 不在本工程范围内。所以这里做成**可选外挂**：给一条外部命令（默认空 = 不启用，
// 保持"纯标准库 + 纯 HTTP"的默认形态），命令从 argv 收 URL 与 form body，
// stdout 吐 a_bogus 原文。Go 侧只用 os/exec，不引入任何三方依赖。

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ABogusSigner 外部 a_bogus 签名器。
type ABogusSigner struct {
	argv    []string
	timeout time.Duration
	ua      string
}

// NewABogusSigner 按命令行字符串建签名器；空串返回 nil（= 不启用）。
//
// 例：NewABogusSigner("node abogus-node.mjs", DefaultUA)
func NewABogusSigner(cmdline, ua string) (*ABogusSigner, error) {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return nil, nil
	}
	argv := strings.Fields(cmdline)
	if len(argv) == 0 {
		return nil, fmt.Errorf("a_bogus 命令为空")
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, fmt.Errorf("找不到 a_bogus 签名命令 %q: %w", argv[0], err)
	}
	return &ABogusSigner{argv: argv, timeout: 60 * time.Second, ua: ua}, nil
}

// Sign 调外部命令算 a_bogus。
//
// 约定：argv[1] = 完整 URL（含 query，不含 a_bogus），argv[2] = form body（无则空串）。
// stdout 只允许输出 a_bogus 的值。
func (s *ABogusSigner) Sign(ctx context.Context, rawURL, formBody string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	args := append(append([]string{}, s.argv[1:]...), rawURL, formBody)
	cmd := exec.CommandContext(cctx, s.argv[0], args...)
	cmd.Env = append(os.Environ(), "DY_UA="+s.ua)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return "", fmt.Errorf("a_bogus 签名命令失败: %w (stderr=%s)", err, msg)
	}
	ab := strings.TrimSpace(stdout.String())
	if ab == "" {
		return "", fmt.Errorf("a_bogus 签名命令没有输出")
	}
	if i := strings.IndexByte(ab, '\n'); i >= 0 {
		ab = strings.TrimSpace(ab[:i])
	}
	return ab, nil
}

// needsABogus 实测只有轮询端点强制要求 a_bogus（出码不需要）。
func needsABogus(path string) bool {
	return path == PathCheckQRConnect
}

// withABogus 把 a_bogus 追加到已签好名的 URL 上。
// a_bogus 不在 sign/qs 窗口内，所以追加发生在 sign/qs/p_no 之后是安全的。
func withABogus(ctx context.Context, s *ABogusSigner, rawURL, formBody string) (string, error) {
	ab, err := s.Sign(ctx, rawURL, formBody)
	if err != nil {
		return rawURL, err
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	// a_bogus 里含 / + = ，必须百分号编码（与真机 query 形态一致）
	return rawURL + sep + "a_bogus=" + url.QueryEscape(ab), nil
}
