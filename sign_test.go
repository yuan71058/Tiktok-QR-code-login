package main

// sign_test.go —— 四套签名的真值断言
//
// 黄金样本来自实测抓包：
//
//	samples/douyin-web-login/web/verify/samples-normalized.json → requests.jsonl#4757
//	（POST /passport/web/check_qrconnect/，测试夹具见 testdata/golden_check_qrconnect.json）
//
// 四条断言：
//  1. aid-sign 真值（含 HKDF 参数序）
//  2. sign 真值（query 前 10 键 + formData 六键）
//  3. qs 与真机逐字节相等（unxor5 后比对键名列表）
//  4. p_no 真值

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type goldenSample struct {
	SampleID string            `json:"sample_id"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    map[string]string `json:"query"`
	FormData map[string]string `json:"formData"`
	Expect   struct {
		Sign    string `json:"sign"`
		QS      string `json:"qs"`
		PNo     string `json:"p_no"`
		AIDSign string `json:"aid_sign"`
	} `json:"expect"`
	TS     int64  `json:"ts"`
	TSNoon string `json:"ts_noon"`
}

func loadGolden(t *testing.T) goldenSample {
	t.Helper()
	path := filepath.Join("testdata", "golden_check_qrconnect.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不了夹具 %s: %v", path, err)
	}
	var g goldenSample
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("夹具不是合法 JSON: %v", err)
	}
	if g.Expect.Sign == "" || g.Expect.QS == "" || g.Expect.PNo == "" || g.Expect.AIDSign == "" {
		t.Fatalf("夹具缺期望值: %+v", g.Expect)
	}
	return g
}

// 断言 1：x-tt-passport-aid-sign 真值（HKDF: ikm=appKey, salt=ts）。
func TestAIDSignGolden(t *testing.T) {
	g := loadGolden(t)
	const want = "ad5805b9e6dacbd1a39bb44582d4e63b41ba67e18625ae5bb59f0214d5f16bec"

	if got := AIDSignMessage(g.Path, g.TSNoon); got != "aid=6383&path=/passport/web/check_qrconnect/&ts=1795176000" {
		t.Fatalf("aid-sign 原文不对: %s", got)
	}
	got := AIDSign(AppKey, g.Path, g.TSNoon)
	if got != want {
		t.Fatalf("aid-sign 真值不符\n got=%s\nwant=%s", got, want)
	}
	// 交叉校验：夹具里同一条请求的真实 aid_sign 也是这个值
	if g.Expect.AIDSign != want {
		t.Fatalf("夹具 aid_sign 与常量不一致: %s", g.Expect.AIDSign)
	}
	// HKDF 参数序反了（salt=ikm, ikm=ts）必须得到不同结果，防止再次写反
	if bad := hkdfReversed(g.Path, g.TSNoon); bad == want {
		t.Fatal("HKDF 参数序反了居然得到同一结果，说明实现没区分 ikm/salt")
	}
}

// hkdfReversed 故意把 ikm/salt 写反，用于反证参数顺序敏感。
func hkdfReversed(path, ts string) string {
	key := hkdfSHA256([]byte(ts), []byte(AppKey), nil, 32)
	return hmacHex(key, AIDSignMessage(path, ts))
}

// 断言 2：sign 真值（query 前 10 键 + formData 六键 + app_key）。
func TestSignGolden(t *testing.T) {
	g := loadGolden(t)

	content := SignContent(g.Query, g.FormData)
	// 拼串结构自检：query 段 + "&" + form 段 + "&app_key=..."
	if !strings.HasSuffix(content, "&app_key="+AppKey) {
		t.Fatalf("sign 原文结尾不对: ...%s", content[maxInt(0, len(content)-60):])
	}
	if !strings.Contains(content, "is_frontier=") || !strings.Contains(content, "token=") {
		t.Fatalf("sign 原文没把 formData 拼进去: %s", content)
	}

	got := Sign(g.Query, g.FormData)
	if got != g.Expect.Sign {
		t.Fatalf("sign 真值不符\n got=%s\nwant=%s\ncontent=%s", got, g.Expect.Sign, content)
	}

	// 幂等性：连算两次必须一致（map 迭代顺序不能影响结果）
	if again := Sign(g.Query, g.FormData); again != got {
		t.Fatalf("sign 不稳定: %s != %s", again, got)
	}
}

// 断言 3：qs 与真机逐字节相等（unxor5 后比对键名列表）。
func TestQSGolden(t *testing.T) {
	g := loadGolden(t)

	got := QS(g.Query)
	if got != g.Expect.QS {
		t.Fatalf("qs 真值不符\n got=%s\nwant=%s", got, g.Expect.QS)
	}

	// 逐字节：解 xor5 后的键名列表必须与真机一致
	wantKeys := strings.Split(unxor5(g.Expect.QS), ",")
	gotKeys := strings.Split(unxor5(got), ",")
	if len(wantKeys) != signWindow {
		t.Fatalf("真机 qs 键数=%d，期望 %d", len(wantKeys), signWindow)
	}
	if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("qs 键名列表不一致\n got=%v\nwant=%v", gotKeys, wantKeys)
	}
	// 首键必须是 aid 排序后的第一个：account_app_language
	if gotKeys[0] != "account_app_language" {
		t.Fatalf("qs 首键=%q，期望 account_app_language", gotKeys[0])
	}
	// xor5 自反：再 xor 回去能还原明文
	if unxor5(got) != strings.Join(gotKeys, ",") {
		t.Fatal("xor5 不是自反的")
	}
}

// 断言 4：p_no 真值（六个键、p_ca 不兜底）。
func TestPNoGolden(t *testing.T) {
	g := loadGolden(t)

	content := PNoContent(g.Query)
	const wantContent = "p_bd=1.0.1.19-fix.01&p_ca=4.0.26&p_ts=1795179999691" +
		"&p_ver=1.1.4-beta.5&p_zt=3.3.35&passport_jssdk_version=3.4.21"
	if content != wantContent {
		t.Fatalf("p_no 原文不符\n got=%s\nwant=%s", content, wantContent)
	}

	got := PNo(g.Query)
	const want = "a29c7fd6ddf8531745e74a51b4c3b353370864f73365b4c2e7dab0ee1809496a"
	if got != want {
		t.Fatalf("p_no 真值不符\n got=%s\nwant=%s", got, want)
	}
	if got != g.Expect.PNo {
		t.Fatalf("p_no 与夹具不一致: 夹具=%s", g.Expect.PNo)
	}

	// p_ts 变则 p_no 必须变（轮询每轮重算的依据）
	q2 := cloneMap(g.Query)
	q2["p_ts"] = "1795180004812"
	if PNo(q2) == got {
		t.Fatal("p_ts 变了 p_no 却没变")
	}
}

// aid-sign 的 ts 必须是「当天 UTC 12:00 秒」，不是当前秒。
func TestAIDSignTSIsUTCMidday(t *testing.T) {
	g := loadGolden(t)
	// 夹具 ts=1795179999717 ms，落在 UTC 12:00 后约 66 分钟，仍是同一天
	now := time.UnixMilli(g.TS)
	if got := AIDSignTS(now); got != g.TSNoon {
		t.Fatalf("aid-sign ts 不符: got=%s want=%s", got, g.TSNoon)
	}
	// 跨日要换日：同一 UTC 日的 00:00:01 与 23:59:59 必须同值
	u := time.UnixMilli(g.TS).UTC()
	dayStart := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 1, 0, time.UTC)
	dayEnd := time.Date(u.Year(), u.Month(), u.Day(), 23, 59, 59, 0, time.UTC)
	if AIDSignTS(dayStart) != AIDSignTS(dayEnd) {
		t.Fatal("同一天 UTC 内 aid-sign ts 应该相同")
	}
}

// path 归一化：/passport 开头原样，否则拼 /passport/sso。
func TestAIDSignPath(t *testing.T) {
	if AIDSignPath("/passport/web/check_qrconnect/") != "/passport/web/check_qrconnect/" {
		t.Fatal("/passport 开头不该被改写")
	}
	if AIDSignPath("/aweme/v1/web/user/profile/self/") != "/passport/sso/aweme/v1/web/user/profile/self/" {
		t.Fatal("非 /passport 开头应拼 /passport/sso")
	}
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
