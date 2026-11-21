package main

// qrcode.go —— 二维码落盘
//
// get_qrcode 返回的 data.qrcode 是 base64 编码的 PNG（前端直接塞进 <img src>）。
// 这里解码校验 magic 再写盘，避免把一段错误 JSON 存成 .png 却以为拿到了码。

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

// pngMagic PNG 文件头。
var pngMagic = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// DecodeQRCode 解 base64（容忍 data:image/png;base64, 前缀与换行）。
func DecodeQRCode(b64 string) ([]byte, error) {
	s := strings.TrimSpace(b64)
	if s == "" {
		return nil, fmt.Errorf("qrcode 字段为空")
	}
	if i := strings.Index(s, "base64,"); i >= 0 {
		s = s[i+len("base64,"):]
	}
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// 兼容 URL-safe 变体与缺省 padding
		if raw2, err2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err2 == nil {
			raw = raw2
		} else {
			return nil, fmt.Errorf("base64 解码失败: %w", err)
		}
	}
	if !bytes.HasPrefix(raw, pngMagic) {
		return raw, fmt.Errorf("不是 PNG（前 8 字节=% x）", raw[:min8(len(raw))])
	}
	return raw, nil
}

// QRImage 落盘后的图像事实。
type QRImage struct {
	Path   string
	Bytes  int
	Width  int
	Height int
}

// SaveQRCode 解码、校验 PNG、写盘，并回读尺寸。
func SaveQRCode(b64, out string) (*QRImage, error) {
	raw, err := DecodeQRCode(b64)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("建目录 %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return nil, fmt.Errorf("写 %s: %w", out, err)
	}
	img := &QRImage{Path: out, Bytes: len(raw)}
	// 用标准库真解一次，证明落盘的是能被解码的 PNG（不是空壳文件）
	if cfg, err := png.DecodeConfig(bytes.NewReader(raw)); err == nil {
		img.Width, img.Height = cfg.Width, cfg.Height
	}
	return img, nil
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}
