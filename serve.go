package main

// serve.go —— -serve 模式：本地实时二维码页（解决"码只有 ~55s 寿命 vs 传递耗时"）
//
//	GET /         内联 HTML，图片每 1.5s 自刷新 + status 大字（meta refresh 3s 兜底）
//	GET /qr.png   当前有效 token 的 PNG（no-store）
//	GET /state    内存状态 JSON（给父会话/脚本查）
//
// 设计要点：
//   - 当前 token 一旦 expired/refused（或 unknown 连续 2 轮）立即重新出码；
//   - 为了不出现"无有效码空窗"，下一个 Client 的引导在后台预跑（prep channel）；
//   - 每张码用独立 Client：单 Client 有 60 次请求上限，长期跑必须换新；
//   - 成功后 profile/self 通过 → 写 login-result.json（uid 保留，昵称打码，cookie 只留 name+len+前4）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// pollEvent 一轮轮询的时间线记录。
type pollEvent struct {
	At      time.Time `json:"at"`
	AtMS    int64     `json:"at_ms"`
	Round   int       `json:"round"`
	Status  string    `json:"status"`
	ErrCode int       `json:"error_code"`
	Raw     string    `json:"raw,omitempty"`
}

// liveState / 与 /state 共享的内存态。
type liveState struct {
	mu sync.RWMutex

	qrPNG    []byte
	token    string
	status   string
	errCode  int
	issuedAt time.Time
	expireAt time.Time
	qrCount  int
	polls    []pollEvent

	profile     *Profile
	cookieNames []string
	success     bool
	lastErr     string
	note        string
}

func (s *liveState) setQR(qr *QR, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.qrPNG = mustDecodeQR(qr.QrcodeB64)
	s.token = qr.Token
	s.status = "new"
	s.errCode = qr.ErrCode
	s.issuedAt = time.Now()
	// 实测纯 HTTP 路径下 expire_time ≈ 55~60s；这里按 60s 估计剩余秒数（仅展示用）
	s.expireAt = s.issuedAt.Add(60 * time.Second)
	s.qrCount = count
	s.polls = nil
}

func (s *liveState) addPoll(round int, res *PollResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.polls = append(s.polls, pollEvent{
		At: time.Now(), AtMS: time.Now().UnixMilli(),
		Round: round, Status: res.Status, ErrCode: res.ErrCode, Raw: res.Raw,
	})
	s.status = res.Status
	s.errCode = res.ErrCode
}

func (s *liveState) setStatus(st string, errCode int, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
	s.errCode = errCode
	if note != "" {
		s.note = note
	}
}

func (s *liveState) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err.Error()
}

func (s *liveState) done(p *Profile, cli *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profile = p
	s.cookieNames = cli.CookieNames()
	s.success = true
	s.status = "confirmed"
}

func (s *liveState) snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	remain := int(time.Until(s.expireAt).Seconds())
	if remain < 0 {
		remain = 0
	}
	out := map[string]any{
		"status":         s.status,
		"error_code":     s.errCode,
		"token_prefix":   trunc(s.token),
		"token_len":      len(s.token),
		"qr_count":       s.qrCount,
		"png_bytes":      len(s.qrPNG),
		"issued_at":      s.issuedAt.Format(time.RFC3339Nano),
		"issued_at_ms":   s.issuedAt.UnixMilli(),
		"expire_at":      s.expireAt.Format(time.RFC3339Nano),
		"expire_at_ms":   s.expireAt.UnixMilli(),
		"remain_seconds": remain,
		"success":        s.success,
		"polls":          s.polls,
		"last_error":     s.lastErr,
		"note":           s.note,
	}
	if s.profile != nil {
		out["uid"] = s.profile.UID
		out["status_code"] = s.profile.StatusCode
		out["nickname_mask"] = maskName(s.profile.Nickname)
	}
	if len(s.cookieNames) > 0 {
		out["cookie_names"] = s.cookieNames
	}
	return out
}

func mustDecodeQR(b64 string) []byte {
	raw, err := DecodeQRCode(b64)
	if err != nil {
		return nil
	}
	return raw
}

// newLiveClient 建 Client 并跑引导（ttwid / csrf），返回可直接出码的会话。
func newLiveClient(ctx context.Context, ua, abogusCmd string, logf func(string, ...any)) (*Client, error) {
	cli, err := NewClient(ua)
	if err != nil {
		return nil, err
	}
	signer, err := NewABogusSigner(abogusCmd, cli.ua)
	if err != nil {
		return nil, err
	}
	cli.UseABogus(signer)
	cli.Bootstrap(ctx, logf)
	return cli, nil
}

// liveLoop 常青二维码循环：出码 → 轮询 → 过期立刻换新码。
func liveLoop(ctx context.Context, st *liveState, ua, abogusCmd, dumpDir string, interval, timeout time.Duration) {
	logf := func(format string, args ...any) {
		fmt.Printf("[live] "+format+"\n", args...)
	}
	deadline := time.Now().Add(timeout)
	prep := make(chan *Client, 2)

	// 后台预热一个 Client，减少换码空窗
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			c, err := newLiveClient(ctx, ua, abogusCmd, func(string, ...any) {})
			if err != nil {
				logf("预热 Client 失败（重试）：%v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			select {
			case prep <- c:
			case <-ctx.Done():
				return
			}
		}
	}()

	qrCount := 0
	for time.Now().Before(deadline) && ctx.Err() == nil {
		var cli *Client
		select {
		case cli = <-prep:
		case <-time.After(30 * time.Second):
			logf("等待预热 Client 超时，现场建一个")
			c, err := newLiveClient(ctx, ua, abogusCmd, logf)
			if err != nil {
				st.setErr(err)
				time.Sleep(2 * time.Second)
				continue
			}
			cli = c
		}

		qr, err := cli.GetQRCode(ctx, filepath.Join(dumpDir, "qr-live.png"))
		if err != nil {
			st.setErr(err)
			logf("出码失败，2s 后重试：%v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		qrCount++
		st.setQR(qr, qrCount)
		logf("#%d 出码 token=%s len=%d png=%dB", qrCount, trunc(qr.Token), len(qr.Token), qr.Bytes)

		// 轮询直到过期/被拒/确认
		round, unknowns := 0, 0
		for ctx.Err() == nil && time.Now().Before(deadline) {
			time.Sleep(interval)
			round++
			res, err := cli.CheckQRConnect(ctx, qr)
			if err != nil {
				unknowns++
				st.setErr(err)
				logf("#%d [%02d] 传输错误：%v", qrCount, round, err)
				if unknowns >= 2 {
					break
				}
				continue
			}
			st.addPoll(round, res)
			logf("#%d [%02d] status=%s err=%d", qrCount, round, res.Status, res.ErrCode)

			switch {
			case res.Status == "confirmed":
				if onConfirmed(ctx, st, cli, res, dumpDir, logf) {
					return
				}
				logf("confirmed 但取 session 失败，继续轮询")
			case res.Status == "scanned":
				unknowns = 0
			case res.Status == "expired" || strings.HasPrefix(res.Status, "refused"):
				logf("#%d 码失效（%s），立刻换码", qrCount, res.Status)
				round = -1
			case strings.HasPrefix(res.Status, "unknown"):
				unknowns++
				logf("#%d [%02d] unknown（%s），不换码继续轮询", qrCount, round, res.Snippet)
			}
			if round == -1 || unknowns >= 2 {
				break
			}
		}
		if st.isSuccess() {
			return
		}
		// 保持"任意时刻有有效码"：立刻进入下一轮出码
	}
	st.setStatus("stopped", 0, "到达 timeout 或 ctx 结束")
}

// onConfirmed confirmed 之后的取 session + 验证；成功返回 true。
func onConfirmed(ctx context.Context, st *liveState, cli *Client, res *PollResult, dumpDir string, logf func(string, ...any)) bool {
	_, herr := cli.HarvestSession(ctx, res, logf)
	if herr != nil {
		st.setErr(herr)
		logf("HarvestSession 失败：%v", herr)
	}
	p, verr := cli.VerifyUID(ctx)
	if verr != nil {
		st.setErr(verr)
		if p != nil {
			logf("VerifyUID 失败：%v（%s）", verr, p.Describe())
		} else {
			logf("VerifyUID 失败：%v", verr)
		}
		return false
	}
	logf("✓ 登录成功 %s", p.Describe())
	st.done(p, cli)

	if _, _, derr := cli.DumpArtifacts(p, dumpDir); derr != nil {
		logf("DumpArtifacts 失败：%v", derr)
	}
	if err := writeLoginResult(st, cli, p, dumpDir); err != nil {
		logf("写 login-result.json 失败：%v", err)
	} else {
		logf("login-result.json 已写 → %s", filepath.Join(dumpDir, "login-result.json"))
	}
	return true
}

func (s *liveState) isSuccess() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.success
}

// writeLoginResult 写取证用的 login-result.json（脱敏）。
func writeLoginResult(st *liveState, cli *Client, p *Profile, dir string) error {
	snap := st.snapshot()
	body, err := json.MarshalIndent(map[string]any{
		"note":        "cookie 值脱敏（name+len+前4）；nickname 打码；uid 保留",
		"status_code": p.StatusCode,
		"uid":         p.UID,
		"nickname_mask": maskName(p.Nickname),
		"sec_uid_prefix": trunc(p.SecUID),
		"cookie_names": cli.CookieNames(),
		"cookies":      cli.SummarizeCookies(),
		"state":        snap,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "login-result.json"), body, 0o644)
}

// servePage 内联 HTML：图片 1.5s 自刷新，状态 1s 一拉，meta refresh 3s 兜底。
const servePage = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>抖音扫码登录 · 纯 HTTP</title>
<style>
  body{margin:0;background:#fff;color:#111;font:16px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif;
       display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:14px}
  h1{font-size:20px;font-weight:600;margin:0}
  #q{width:400px;height:400px;image-rendering:pixelated}
  #status{font-size:30px;font-weight:700;letter-spacing:.5px}
  #meta{font-size:14px;color:#555}
  #done{font-size:22px;font-weight:700;color:#0a7d32;display:none}
  code{background:#f3f3f3;padding:1px 5px;border-radius:4px}
</style></head>
<body>
<h1>抖音扫码登录 · 纯 HTTP（Go）</h1>
<img id="q" alt="二维码" src="/qr.png?t=__T__">
<div id="status">加载中…</div>
<div id="meta"></div>
<div id="done"></div>
<script>
function tick(){
  document.getElementById('q').src = '/qr.png?t=' + Date.now();
}
setInterval(tick, 1500);
async function st(){
  try{
    const r = await fetch('/state', {cache:'no-store'});
    const s = await r.json();
    const map = {new:'等待扫码', scanned:'已扫到，请在手机上确认', confirmed:'已确认',
                 expired:'码已过期，正在换新码', refused:'已拒绝，正在换新码', starting:'启动中', stopped:'已停止'};
    document.getElementById('status').textContent = map[s.status] || s.status;
    document.getElementById('meta').innerHTML =
      'token=<code>' + (s.token_prefix||'') + '</code> len=' + (s.token_len||0) +
      ' · 剩余 ' + (s.remain_seconds||0) + 's · 第 ' + (s.qr_count||0) + ' 张码' +
      ' · err=' + s.error_code;
    if (s.success) {
      const d = document.getElementById('done');
      d.style.display = 'block';
      d.textContent = '登录成功 uid=' + s.uid + ' 昵称=' + (s.nickname_mask||'');
      document.getElementById('status').textContent = '已登录';
      document.getElementById('q').style.display = 'none';
    }
  }catch(e){}
}
setInterval(st, 1000);
st();
</script>
</body></html>`

// runServe 起 HTTP 服务（标准库 net/http，无第三方依赖）。
func runServe(ctx context.Context, addr, ua, abogusCmd, dumpDir string, interval, timeout time.Duration) error {
	st := &liveState{status: "starting"}
	go liveLoop(ctx, st, ua, abogusCmd, dumpDir, interval, timeout)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		page := strings.ReplaceAll(servePage, "__T__", fmt.Sprintf("%d", time.Now().UnixMilli()))
		_, _ = w.Write([]byte(page))
	})
	mux.HandleFunc("/qr.png", func(w http.ResponseWriter, r *http.Request) {
		st.mu.RLock()
		png := st.qrPNG
		st.mu.RUnlock()
		if len(png) == 0 {
			http.Error(w, "还没出码", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(png)))
		_, _ = w.Write(png)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st.snapshot())
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	fmt.Printf("[serve] 实时页：http://%s/  （/qr.png · /state）\n", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
