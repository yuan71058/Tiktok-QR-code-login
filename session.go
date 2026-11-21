package main

// session.go —— cookie jar、固定 UA、统一的请求/解包
//
// 关键点：UA 参与签名。同一个会话里所有请求必须用**同一个** UA，
// 否则 sign 与 UA 不一致，服务端可能直接判风控。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultUA 与 Chrome 119 (Windows) 一致；-ua 可覆盖，但整个会话内固定。
const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

// Host 抖音 web 主站。
const Host = "https://www.douyin.com"

// Client 一次登录会话。
type Client struct {
	http  *http.Client
	ua    string
	jar   http.CookieJar
	reqs  int // 已发出的请求数（硬上限 60）
	limit int

	mu   sync.Mutex
	csrf string // passport_csrf_token 缓存（header 用）

	// tg 是本会话的 ticket-guard 密钥与四个请求头。
	tg *TicketGuard

	// abogus 是可选的外挂 a_bogus 签名器；nil = 不启用（纯 Go 形态）。
	abogus *ABogusSigner

	// refOverride 只给 4031 探针用：改 Referer 观察风控是否变化。
	refOverride string
}

// NewClient 建会话：带 cookie jar、固定 UA、总请求上限。
func NewClient(ua string) (*Client, error) {
	if strings.TrimSpace(ua) == "" {
		ua = DefaultUA
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar: %w", err)
	}
	tg, err := NewTicketGuard()
	if err != nil {
		return nil, err
	}
	return &Client{
		http: &http.Client{
			Jar:     jar,
			Timeout: 20 * time.Second,
		},
		ua:    ua,
		jar:   jar,
		limit: 60,
		tg:    tg,
	}, nil
}

// Resp 统一响应：原始 body + HTTP 状态 + 解析后的 JSON。
type Resp struct {
	Status  int
	Header  http.Header
	Body    []byte
	JSON    map[string]any
	Data    map[string]any
	ErrCode int
	Message string
}

// Do 发一次请求。返回 error 仅代表传输层失败；业务错误码看 Resp.ErrCode。
//
// POST 默认 body 是 form-urlencoded（真机形态；JSON body 会被判「缺少参数」）。
func (c *Client) Do(ctx context.Context, method, path string, sq SignedQuery, form map[string]string) (*Resp, error) {
	var body []byte
	ct := ""
	if method == http.MethodPost {
		body = []byte(BuildForm(form))
		ct = "application/x-www-form-urlencoded"
	}
	return c.DoRaw(ctx, method, path, sq, body, ct)
}

// DoRaw 发一次请求，body 与 Content-Type 由调用方给（探针复刻 JSON body 用）。
func (c *Client) DoRaw(ctx context.Context, method, path string, sq SignedQuery, body []byte, contentType string) (*Resp, error) {
	if c.reqs >= c.limit {
		return nil, fmt.Errorf("请求数已达上限 %d，停止", c.limit)
	}

	full := Host + path
	if enc := sq.Encode(); enc != "" {
		full += "?" + enc
	}

	// a_bogus：只有启用了外挂签名器、且是强制要求它的端点（check_qrconnect）才加。
	if c.abogus != nil && needsABogus(path) {
		signed, err := withABogus(ctx, c.abogus, full, string(body))
		if err != nil {
			return nil, fmt.Errorf("%s a_bogus: %w", path, err)
		}
		full = signed
	}

	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, full, rdr)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	c.applyHeaders(req, sq, method == http.MethodPost)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// ticket-guard 四件套：只挂在 providerPathList 里的端点（如 check_qrconnect）。
	if needsTicketGuard(path) && c.tg != nil {
		for k, v := range c.tg.Headers {
			req.Header.Set(k, v)
		}
	}

	c.reqs++
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	out := &Resp{Status: res.StatusCode, Header: res.Header, Body: raw}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err == nil {
		out.JSON = parsed
		if d, ok := parsed["data"].(map[string]any); ok {
			out.Data = d
			if v, ok := d["error_code"]; ok {
				out.ErrCode = toInt(v)
			}
		}
		// 少数端点把 error_code / message 放在顶层
		if out.ErrCode == 0 {
			if v, ok := parsed["error_code"]; ok {
				out.ErrCode = toInt(v)
			}
		}
		if m, ok := parsed["message"].(string); ok {
			out.Message = m
		}
	}
	return out, nil
}

// applyHeaders 固定头：UA 与签名 UA 必须一致。
//
// 真机抓包（requests.jsonl#4757，POST check_qrconnect）里 passport SDK 还带了：
//
//	x-tt-passport-csrf-token: <passport_csrf_token cookie>   ← POST 必带，缺了掉 4031
//	x-tt-passport-trace-id:   <query 里的 biz_trace_id>
//	x-secsdk-csrf-token:      DOWNGRADE
//	web-sdk-version:          1
//
// 只补签名与 URL 参数是不够的：4031 是端上风控，CSRF 头是它的一部分。
func (c *Client) applyHeaders(req *http.Request, sq SignedQuery, isPost bool) {
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json, text/javascript")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Referer", c.referer())
	req.Header.Set("Origin", Host)
	req.Header.Set("web-sdk-version", "1")
	req.Header.Set("x-tt-passport-aid-sign", sq.AIDSign)

	if tid := sq.Values["biz_trace_id"]; tid != "" {
		req.Header.Set("x-tt-passport-trace-id", tid)
	}
	c.mu.Lock()
	csrf := c.csrf
	c.mu.Unlock()
	if csrf == "" {
		csrf = c.Cookie("passport_csrf_token")
	}
	if csrf != "" {
		req.Header.Set("x-tt-passport-csrf-token", csrf)
	}
	req.Header.Set("x-secsdk-csrf-token", "DOWNGRADE")

	if isPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

// DoPlain 发一个不签名的请求（用于 ① 拿 __ac_nonce 之类的引导请求）。
func (c *Client) DoPlain(ctx context.Context, method, rawURL string, body string, headers map[string]string) (*Resp, error) {
	if c.reqs >= c.limit {
		return nil, fmt.Errorf("请求数已达上限 %d，停止", c.limit)
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	c.reqs++
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	out := &Resp{Status: res.StatusCode, Header: res.Header, Body: raw}
	var parsed map[string]any
	if json.Unmarshal(raw, &parsed) == nil {
		out.JSON = parsed
		if d, ok := parsed["data"].(map[string]any); ok {
			out.Data = d
			if v, ok := d["error_code"]; ok {
				out.ErrCode = toInt(v)
			}
		}
	}
	return out, nil
}

// Cookie 读 jar 里某个 cookie 的值。
func (c *Client) Cookie(name string) string {
	u, err := url.Parse(Host)
	if err != nil {
		return ""
	}
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// HasCookie 判断 jar 里是否已出现某 cookie。
func (c *Client) HasCookie(name string) bool { return c.Cookie(name) != "" }

// RefreshCSRF 把 jar 里的 passport_csrf_token 同步进内存缓存，供请求头使用。
func (c *Client) RefreshCSRF() string {
	if v := c.Cookie("passport_csrf_token"); v != "" {
		c.mu.Lock()
		c.csrf = v
		c.mu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.csrf
}

// SetCookieHeader 记录服务端在响应里可能给的 Set-Cookie（jar 通常已自动处理，
// 这里补一手非标准域名的 cookie）。
func (c *Client) SetCookieHeader(rawCookies []string) {
	u, err := url.Parse(Host)
	if err != nil {
		return
	}
	for _, line := range rawCookies {
		parts := strings.SplitN(strings.TrimSpace(line), ";", 2)
		kv := strings.SplitN(parts[0], "=", 2)
		if len(kv) != 2 {
			continue
		}
		c.jar.SetCookies(u, []*http.Cookie{{Name: strings.TrimSpace(kv[0]), Value: kv[1], Path: "/"}})
	}
}

// RequestCount 已发出的请求数。
func (c *Client) Requests() int { return c.reqs }

// UseABogus 挂上 a_bogus 外挂签名器（nil 表示不启用）。
func (c *Client) UseABogus(s *ABogusSigner) { c.abogus = s }

// Referer 当前会话的 Referer（探针用）。
func (c *Client) Referer() string { return c.referer() }
func (c *Client) referer() string {
	if c.refOverride != "" {
		return c.refOverride
	}
	return Host + "/"
}

// SetCookieValue 从响应头里取某个 Set-Cookie 的裸值（不做 URL 解码，
// 浏览器存的就是 %7C 这种原样字符串）。
func (r *Resp) SetCookieValue(name string) string {
	if r.Header == nil {
		return ""
	}
	for _, line := range r.Header.Values("Set-Cookie") {
		seg := strings.SplitN(line, ";", 2)[0]
		kv := strings.SplitN(seg, "=", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == name {
			return kv[1]
		}
	}
	return ""
}

// SetCookieForDouyin 手工把 cookie 种到 www.douyin.com 域。
// ttwid 由 ttwid.bytedance.com 跨域发放，浏览器靠下发 Domain=.douyin.com；
// Go 的 cookie jar 不吃跨域的 Set-Cookie，所以这里搬一次。
func (c *Client) SetCookieForDouyin(name, value string) {
	if name == "" || value == "" {
		return
	}
	u, err := url.Parse(Host)
	if err != nil {
		return
	}
	c.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

// Snippet 响应片段（截断到 n 字节），用于回报里贴证据。
func (r *Resp) Snippet(n int) string {
	if n <= 0 || n > len(r.Body) {
		n = len(r.Body)
	}
	s := string(r.Body[:n])
	s = strings.ReplaceAll(s, "\n", " ")
	if len(r.Body) > n {
		s += "..."
	}
	return s
}

func toInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	}
	return 0
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	}
	return ""
}

func toBoolStr(v any) string {
	if b, ok := v.(bool); ok {
		return fmt.Sprintf("%v", b)
	}
	return toStr(v)
}
