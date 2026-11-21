package main

// dump.go —— 登录成功后的脱敏产物落盘
//
// 纪律：sessionid / sid_guard / msToken 等凭据**不得原文落库**，
// 这里只写名字 + 长度 + 前 4 字符，够证明"拿到了"，不足以复用。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// CookieSummary 一条 cookie 的脱敏摘要。
type CookieSummary struct {
	Name   string `json:"name"`
	Len    int    `json:"len"`
	Prefix string `json:"prefix4"`
	Domain string `json:"domain,omitempty"`
}

// SummarizeCookies 把 jar 里 douyin 域的 cookie 压成脱敏摘要（按名字排序）。
func (c *Client) SummarizeCookies() []CookieSummary {
	out := []CookieSummary{}
	u, err := url.Parse(Host)
	if err != nil {
		return out
	}
	for _, ck := range c.jar.Cookies(u) {
		pre := ck.Value
		if len(pre) > 4 {
			pre = pre[:4]
		}
		out = append(out, CookieSummary{
			Name:   ck.Name,
			Len:    len(ck.Value),
			Prefix: pre,
			Domain: ck.Domain,
		})
	}
	return out
}

// CookieNames 只取名字列表（回报里贴这一串）。
func (c *Client) CookieNames() []string {
	names := []string{}
	for _, s := range c.SummarizeCookies() {
		names = append(names, s.Name)
	}
	return names
}

// DumpArtifacts 写 session-cookies.json（脱敏）与 profile-self.json（昵称打码）。
func (c *Client) DumpArtifacts(p *Profile, dir string) (string, string, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("建目录 %s: %w", dir, err)
	}

	ckPath := filepath.Join(dir, "session-cookies.json")
	ckBody, err := json.MarshalIndent(map[string]any{
		"note":    "cookie 值已脱敏：只保留 name + len + 前 4 字符",
		"host":    Host,
		"has_sid": c.HasCookie("sessionid"),
		"cookies": c.SummarizeCookies(),
	}, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(ckPath, ckBody, 0o644); err != nil {
		return "", "", fmt.Errorf("写 %s: %w", ckPath, err)
	}

	pPath := filepath.Join(dir, "profile-self.json")
	body, err := json.MarshalIndent(map[string]any{
		"note":          "nickname 打码；uid 保留用于验证登录态",
		"status_code":   p.StatusCode,
		"uid":           p.UID,
		"sec_uid_prefix": trunc(p.SecUID),
		"nickname_mask": maskName(p.Nickname),
		"raw_snippet":   trunc(p.Snippet),
	}, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pPath, body, 0o644); err != nil {
		return "", "", fmt.Errorf("写 %s: %w", pPath, err)
	}
	return ckPath, pPath, nil
}

// maskName 昵称打码：留首尾各 1 个字符，中间用 *。
func maskName(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 2:
		return string(r[0]) + "*"
	}
	return string(r[0]) + "***" + string(r[len(r)-1])
}
