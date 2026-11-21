package main

// params.go —— 公共参数基座 + query 组装
//
// 抖音 web passport 的 query 是「固定基座 + 端点专有参数 + 四套签名」拼起来的。
// 任何一个键少带都可能直接掉进 4031 风控（HTTP 仍然 200）。

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// 版本常量：与实测样本一致，改了要重新验签。
const (
	PassportJSSDKVersion = "3.4.21"
	PassportJSSDKType    = "normal"
	PJSV                 = "3.4.21"
	PJST                 = "pro"
	PZT                  = "3.3.35"
	PVer                 = "1.1.4-beta.5"
	PVerReal             = "0"
	PBD                  = "1.0.1.19-fix.01"
	PCA                  = "4.0.26"
	PCACReal             = "1.0.0.1023"
	RequestHost          = "https://www.douyin.com"
	PUI                  = "2.4.23"

	// DevicePlatformWebApp 是 get_qrcode 用的（下划线）；
	// account/info 等端点要用 "webapp"（无下划线），见 verify.go。
	DevicePlatformWebApp = "web_app"
	DevicePlatformWebapp = "webapp"
)

// BaseParams 返回公共参数基座（值均为「解码后」形态，编码交给 url.Values）。
func BaseParams() map[string]string {
	return map[string]string{
		"aid":                    AID,
		"language":               "zh",
		"account_app_language":   "zh-CN",
		"account_sdk_source":     "web",
		"passport_jssdk_version": PassportJSSDKVersion,
		"passport_jssdk_type":    PassportJSSDKType,
		"p_js_v":                 PJSV,
		"p_js_t":                 PJST,
		"p_zt":                   PZT,
		"p_ver":                  PVer,
		"p_ver_real":             PVerReal,
		"p_bd":                   PBD,
		"p_ca":                   PCA,
		"p_ca_real":              PCACReal,
		"request_host":           RequestHost,
		"biz_trace_id":           genBizTraceID(),
		"is_from_ttaccountsdk":   "1", // ★ 4031 的唯一开关，缺了/为 0 直接拒
		"device_platform":        DevicePlatformWebApp,
	}
}

// genBizTraceID 8 位小写 hex。
func genBizTraceID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// SignedQuery 一次请求要用的完整 query（含签名），附带 aid-sign 头需要的值。
type SignedQuery struct {
	Values map[string]string
	// Path 是 aid-sign 归一化后的 path（/passport 开头原样，否则 /passport/sso 前缀）。
	Path string
	// TS 与 query 里的 ts 是同一个值：当天 UTC 12:00 的秒级时间戳。
	TS string
	// AIDSign 是 x-tt-passport-aid-sign 头的值。
	AIDSign string
}

// BuildSignedQuery 组装 query 并算出 sign / qs / p_no / ts / aid-sign。
//
// extra 是端点专有参数；formData 是 POST 请求体（参与 sign，不进 query）。
// now 用于 p_ts（13 位毫秒）与 aid-sign 的 ts（当天 UTC 12:00 秒）。
func BuildSignedQuery(path string, extra, formData map[string]string, now time.Time) SignedQuery {
	q := BaseParams()
	for k, v := range extra {
		q[k] = v
	}

	// p_ts 必须与请求同一时刻；p_ca 缺失时回退 "0"（回退在调用方，不在 PNo 内）。
	q["p_ts"] = strconv.FormatInt(now.UnixMilli(), 10)
	pcA := q["p_ca"]
	if pcA == "" {
		pcA = "0"
		q["p_ca"] = pcA
	}
	q["p_no"] = PNo(q)

	ts := AIDSignTS(now)
	q["ts"] = ts

	q["sign"] = Sign(q, formData)
	q["qs"] = QS(q)

	return SignedQuery{
		Values:  q,
		Path:    AIDSignPath(path),
		TS:      ts,
		AIDSign: AIDSign(AppKey, path, ts),
	}
}

// Encode 把 query 编成 URL 查询串（键按字典序，值做百分号编码）。
func (s SignedQuery) Encode() string {
	v := make(url.Values, len(s.Values))
	for k, val := range s.Values {
		v.Set(k, val)
	}
	return v.Encode()
}

// BuildForm 同样把 formData 编成请求体。
func BuildForm(formData map[string]string) string {
	v := make(url.Values, len(formData))
	for k, val := range formData {
		v.Set(k, val)
	}
	return v.Encode()
}

// stringify 供日志输出，避免打全整条 query。
func (s SignedQuery) stringify() string {
	return fmt.Sprintf("path=%s ts=%s p_no=%s sign=%s qs=%s",
		s.Path, s.TS, trunc(s.Values["p_no"]), trunc(s.Values["sign"]), trunc(s.Values["qs"]))
}
