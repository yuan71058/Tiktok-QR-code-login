package main

// login.go —— 二维码登录主流程
//
//	① GET  /                                     拿 __ac_nonce / ttwid（失败忽略）
//	② GET  mssdk.bytedance.com/web/r/token       拿 msToken（404 不阻塞）
//	③ POST /passport/user_info/get_sec_ts/       服务器时间（失败忽略）
//	④ POST /ttwid/check/                         注册 ttwid（失败忽略）
//	⑤ GET  /passport/general/login_guiding_strategy/  拿 passport_csrf_token
//	⑥ GET  /passport/web/get_qrcode/             出码
//	⑦ 保存 PNG
//	⑧ POST /passport/web/check_qrconnect/        轮询（每次重算签名，p_ts 会变）
//	⑨ confirmed → redirect_url → sessionid/sid_tt
//	⑩ verify.go 用 profile/self 探登录态

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 端点 path（query 另拼）。
const (
	PathGetQRCode      = "/passport/web/get_qrcode/"
	PathCheckQRConnect = "/passport/web/check_qrconnect/"
	PathLoginGuiding   = "/passport/general/login_guiding_strategy/"
	PathSecTS          = "/passport/user_info/get_sec_ts/"
	PathTtwidCheck     = "/ttwid/check/"
	PathMsToken        = "https://mssdk.bytedance.com/web/r/token"
)

// QR 出码结果。
type QR struct {
	Token          string
	QrcodeB64      string
	IsFrontier     string
	FrontierParams map[string]any
	Path           string
	Bytes          int
	Width          int
	Height         int
	ErrCode        int
	Snippet        string
}

// GetQRCode 出码。成功判据：data.error_code == 0 且 qrcode 非空。
func (c *Client) GetQRCode(ctx context.Context, out string) (*QR, error) {
	extra := map[string]string{
		"device_platform":        DevicePlatformWebApp,
		"next":                   Host,
		"need_short_url":         "true",
		"need_logo":              "false",
		"is_new_login":           "1",
		"is_from_iesaccountsaas": "1",
		"p_ui":                   PUI,
	}
	sq := BuildSignedQuery(PathGetQRCode, extra, nil, time.Now())
	resp, err := c.Do(ctx, "GET", PathGetQRCode, sq, nil)
	if err != nil {
		return nil, err
	}

	qr := &QR{ErrCode: resp.ErrCode, Snippet: resp.Snippet(320)}
	if resp.Data != nil {
		qr.Token = toStr(resp.Data["token"])
		qr.QrcodeB64 = toStr(resp.Data["qrcode"])
		qr.IsFrontier = toBoolStr(resp.Data["is_frontier"])
		if fp, ok := resp.Data["frontier_params"].(map[string]any); ok {
			qr.FrontierParams = fp
		}
	}
	if resp.ErrCode != 0 {
		return qr, fmt.Errorf("get_qrcode 失败 error_code=%d message=%q body=%s",
			resp.ErrCode, resp.Message, resp.Snippet(320))
	}
	if qr.QrcodeB64 == "" {
		return qr, fmt.Errorf("get_qrcode 返回 error_code=0 但没有 qrcode 字段，body=%s", resp.Snippet(320))
	}

	img, err := SaveQRCode(qr.QrcodeB64, out)
	if err != nil {
		return qr, fmt.Errorf("保存二维码: %w", err)
	}
	qr.Path, qr.Bytes, qr.Width, qr.Height = img.Path, img.Bytes, img.Width, img.Height
	return qr, nil
}

// PollResult 一轮轮询的结果。
type PollResult struct {
	Status      string // new / scanned / confirmed / refused / expired / unknown
	Raw         string
	ErrCode     int
	RedirectURL string
	Snippet     string
}

// terminal 是否终止轮询。
func (p PollResult) terminal() bool {
	switch p.Status {
	case "confirmed", "refused", "expired":
		return true
	}
	return false
}

// CheckQRConnect 轮询一次。formData 六键必须参与 sign，且顺序无关（内部排序）。
func (c *Client) CheckQRConnect(ctx context.Context, qr *QR) (*PollResult, error) {
	return c.CheckQRConnectExtra(ctx, qr, DefaultCheckExtra())
}

// DefaultCheckExtra check_qrconnect 的端点专有 query 参数。
func DefaultCheckExtra() map[string]string {
	return map[string]string{
		"device_platform":        DevicePlatformWebApp,
		"is_from_iesaccountsaas": "1",
		"p_ui":                   PUI,
		"p_ca":                   PCA,
		"p_ca_real":              PCACReal,
	}
}

// CheckQRConnectExtra 用给定 extra 轮询一次（探针做变体实验用）。
func (c *Client) CheckQRConnectExtra(ctx context.Context, qr *QR, extra map[string]string) (*PollResult, error) {
	isFrontier := qr.IsFrontier
	if isFrontier == "" {
		isFrontier = "true"
	}
	form := map[string]string{
		"need_logo":      "false",
		"is_frontier":    isFrontier,
		"token":          qr.Token,
		"is_new_login":   "1",
		"next":           Host,
		"need_short_url": "true",
	}
	// ★ 每轮都重算：p_ts 变了，sign / p_no 都要跟着变
	sq := BuildSignedQuery(PathCheckQRConnect, extra, form, time.Now())
	resp, err := c.Do(ctx, "POST", PathCheckQRConnect, sq, form)
	if err != nil {
		return nil, err
	}

	out := &PollResult{Raw: "", ErrCode: resp.ErrCode, Snippet: resp.Snippet(300)}
	if resp.Data != nil {
		out.Raw = toStr(resp.Data["status"])
		out.RedirectURL = toStr(resp.Data["redirect_url"])
		if out.Raw == "" {
			out.Raw = toStr(resp.Data["status_code"])
		}
	}
	out.Status = normalizeStatus(out.Raw)
	return out, nil
}

// CheckQRConnectJSON 用 JSON body 复刻父库 node 客户端的错误形态（探针对照用）。
//
// 实测：JSON body → error_code=3「缺少参数」；form-urlencoded 六键才是真机形态。
func (c *Client) CheckQRConnectJSON(ctx context.Context, qr *QR) (*PollResult, error) {
	isFrontier := qr.IsFrontier == "true" || qr.IsFrontier == ""
	form := map[string]string{
		"need_logo":      "false",
		"is_frontier":    toBoolStr(isFrontier),
		"token":          qr.Token,
		"is_new_login":   "1",
		"next":           Host,
		"need_short_url": "true",
	}
	sq := BuildSignedQuery(PathCheckQRConnect, DefaultCheckExtra(), form, time.Now())
	body, err := json.Marshal(map[string]any{
		"need_logo":      false,
		"is_frontier":    isFrontier,
		"token":          qr.Token,
		"is_new_login":   "1",
		"next":           Host,
		"need_short_url": "true",
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.DoRaw(ctx, "POST", PathCheckQRConnect, sq, body, "application/json")
	if err != nil {
		return nil, err
	}
	out := &PollResult{ErrCode: resp.ErrCode, Snippet: resp.Snippet(300)}
	if resp.Data != nil {
		out.Raw = toStr(resp.Data["status"])
	}
	out.Status = normalizeStatus(out.Raw)
	return out, nil
}

// normalizeStatus 把服务端可能给的 "1"/"new"/"scanned" 等统一。
func normalizeStatus(raw string) string {
	switch raw {
	case "1", "new":
		return "new"
	case "2", "scanned", "scan":
		return "scanned"
	case "3", "confirmed", "confirm", "success":
		return "confirmed"
	case "4", "refused", "refuse", "cancel", "canceled", "cancelled":
		return "refused"
	case "5", "expired", "timeout":
		return "expired"
	case "":
		return "unknown"
	}
	return "unknown:" + raw
}

// WaitLogin 轮询直到终态 / 超时 / ctx 结束。
func (c *Client) WaitLogin(ctx context.Context, qr *QR, interval, timeout time.Duration, log func(string, ...any)) (*PollResult, error) {
	deadline := time.Now().Add(timeout)
	round := 0
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("轮询超时（%s）", timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		round++
		res, err := c.CheckQRConnect(ctx, qr)
		if err != nil {
			return nil, err
		}
		log("  [%02d] status=%s err=%d%s", round, res.Status, res.ErrCode, rawSuffix(res.Raw, res.Status))
		if res.Status == "unknown" || strings.HasPrefix(res.Status, "unknown:") {
			log("       body=%s", res.Snippet)
		}
		if res.terminal() {
			return res, nil
		}
	}
}

func rawSuffix(raw, norm string) string {
	if raw == "" || raw == norm {
		return ""
	}
	return fmt.Sprintf(" (raw=%q)", raw)
}

// HarvestSession confirmed 后把 sessionid / sid_tt 落到 jar。
func (c *Client) HarvestSession(ctx context.Context, res *PollResult, log func(string, ...any)) (string, error) {
	if res != nil && res.RedirectURL != "" {
		_, err := c.DoPlain(ctx, "GET", res.RedirectURL, "", nil)
		if err != nil {
			log("  redirect_url 跟随失败（忽略）：%v", err)
		} else {
			log("  跟随 redirect_url: %s", res.RedirectURL)
		}
	}
	// 兜底：无论有没有 redirect_url，都回主站刷一次 cookie
	if !c.HasCookie("sessionid") {
		if _, err := c.DoPlain(ctx, "GET", Host+"/", "", nil); err != nil {
			log("  GET / 刷新 cookie 失败（忽略）：%v", err)
		}
	}
	sid := c.Cookie("sessionid")
	if sid == "" {
		return "", fmt.Errorf("cookie jar 里没有 sessionid")
	}
	log("  cookies: sessionid(%s) sid_tt(%s)", trunc(sid), trunc(c.Cookie("sid_tt")))
	return sid, nil
}

// ensureTTWID 领 ttwid 并种到 douyin 域。
//
// GET https://www.douyin.com/ 只给 __ac_nonce，不给 ttwid；
// ttwid 由 https://ttwid.bytedance.com/ttwid/union/register/ 发放（Domain=.douyin.com），
// Go 的 cookie jar 不吃跨域 Domain，所以要把值手工搬过来。
func (c *Client) ensureTTWID(ctx context.Context, log func(string, ...any)) {
	if c.HasCookie("ttwid") {
		log("  ④ ttwid 已在 jar 里：%s", trunc(c.Cookie("ttwid")))
		return
	}
	const regURL = "https://ttwid.bytedance.com/ttwid/union/register/"
	const regBody = `{"region":"cn","aid":1768,"needFid":false,"service":"www.ixigua.com",` +
		`"migrate_info":{"ticket":"","source":"node"},"cbUrlProtocol":"https","union":true}`
	r, err := c.DoPlain(ctx, "POST", regURL, regBody, map[string]string{
		"Content-Type": "application/json",
		"Referer":      Host + "/",
	})
	if err != nil {
		log("  ④ ttwid 注册失败（忽略）：%v", err)
		return
	}
	tw := r.SetCookieValue("ttwid")
	if tw == "" {
		// 兜底：老式 /ttwid/check/
		r2, err2 := c.DoPlain(ctx, "POST", Host+PathTtwidCheck,
			`{"status_code":0,"req_content":"check"}`,
			map[string]string{"Referer": Host + "/"})
		if err2 == nil {
			tw = r2.SetCookieValue("ttwid")
		}
	}
	c.SetCookieForDouyin("ttwid", tw)
	log("  ④ ttwid → HTTP %d %s", r.Status, trunc(c.Cookie("ttwid")))
}

// Bootstrap 跑引导请求，失败一律忽略（出码不依赖它们成功）。
func (c *Client) Bootstrap(ctx context.Context, log func(string, ...any)) {
	// ① 主站，拿 __ac_nonce / ttwid
	if r, err := c.DoPlain(ctx, "GET", Host+"/", "", nil); err != nil {
		log("  ① GET / 失败（忽略）：%v", err)
	} else {
		log("  ① GET / → HTTP %d, __ac_nonce=%s ttwid=%s",
			r.Status, trunc(c.Cookie("__ac_nonce")), trunc(c.Cookie("ttwid")))
	}

	// ② msToken（404 不阻塞）
	if r, err := c.DoPlain(ctx, "GET", PathMsToken+"?ms_appid="+AID, "", map[string]string{
		"Referer": Host + "/",
	}); err != nil {
		log("  ② msToken 失败（忽略）：%v", err)
	} else {
		mt := ""
		if r.Data != nil {
			mt = toStr(r.Data["token"])
		}
		if mt == "" {
			mt = c.Cookie("msToken")
		}
		log("  ② msToken → HTTP %d %s", r.Status, trunc(mt))
	}

	// ③ get_sec_ts（服务器时间，失败忽略）
	secTS := BuildSignedQuery(PathSecTS, map[string]string{
		"device_platform": DevicePlatformWebApp,
	}, nil, time.Now())
	if r, err := c.Do(ctx, "POST", PathSecTS, secTS, nil); err != nil {
		log("  ③ get_sec_ts 失败（忽略）：%v", err)
	} else {
		log("  ③ get_sec_ts → error_code=%d", r.ErrCode)
	}

	// ④ ttwid：必须从 ttwid.bytedance.com/ttwid/union/register/ 领，再搬到 douyin 域。
	//    缺 ttwid 是 check_qrconnect 掉 4031 的主要原因之一（get_qrcode 反而不查）。
	c.ensureTTWID(ctx, log)

	// ⑤ login_guiding_strategy：拿 passport_csrf_token
	g := BuildSignedQuery(PathLoginGuiding, map[string]string{
		"device_platform": DevicePlatformWebApp,
	}, nil, time.Now())
	if r, err := c.Do(ctx, "GET", PathLoginGuiding, g, nil); err != nil {
		log("  ⑤ login_guiding_strategy 失败（忽略）：%v", err)
	} else {
		log("  ⑤ login_guiding_strategy → error_code=%d csrf(%s)",
			r.ErrCode, trunc(c.RefreshCSRF()))
	}
	c.RefreshCSRF()
}
