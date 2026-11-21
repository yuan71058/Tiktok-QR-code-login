package main

// verify.go —— 登录态探针
//
// 重要：/passport/web/account/info/ 登录后仍会返回 error_code=16，
// 它**不是**登录态探针。真正的判据是 /aweme/v1/web/user/profile/self/ 的
// status_code == 0 且 user.uid 非空。

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// PathProfileSelf 登录态探针。
const PathProfileSelf = "/aweme/v1/web/user/profile/self/"

// Profile 校验结果。
type Profile struct {
	StatusCode int
	UID        string
	Nickname   string
	SecUID     string
	Snippet    string
}

// VerifyUID 用 profile/self 验证登录态。
// 注意 device_platform 在这里是 webapp（无下划线），与 get_qrcode 的 web_app 不同。
func (c *Client) VerifyUID(ctx context.Context) (*Profile, error) {
	q := url.Values{}
	q.Set("aid", AID)
	q.Set("device_platform", DevicePlatformWebapp)
	q.Set("channel", "channel_pc_web")
	q.Set("pc_client_type", "1")
	q.Set("version_code", "170400")
	q.Set("version_name", "17.4.0")
	q.Set("cookie_enabled", "true")
	q.Set("platform", "PC")
	q.Set("downlink", "10")

	raw := Host + PathProfileSelf + "?" + q.Encode()
	resp, err := c.DoPlain(ctx, "GET", raw, "", map[string]string{
		"Referer": Host + "/",
	})
	if err != nil {
		return nil, err
	}

	p := &Profile{Snippet: resp.Snippet(320)}
	if resp.JSON == nil {
		return p, fmt.Errorf("profile/self 返回非 JSON：%s", resp.Snippet(200))
	}
	p.StatusCode = toInt(resp.JSON["status_code"])

	user, _ := resp.JSON["user"].(map[string]any)
	if user != nil {
		p.UID = toStr(user["uid"])
		p.Nickname = toStr(user["nickname"])
		p.SecUID = toStr(user["sec_uid"])
	}
	if p.StatusCode != 0 || p.UID == "" {
		return p, fmt.Errorf("未登录：status_code=%d uid=%q", p.StatusCode, p.UID)
	}
	return p, nil
}

// Describe 一行摘要，供回报引用。
func (p *Profile) Describe() string {
	return fmt.Sprintf("status_code=%d uid=%s nickname=%s sec_uid=%s",
		p.StatusCode, p.UID, strings.TrimSpace(p.Nickname), trunc(p.SecUID))
}
