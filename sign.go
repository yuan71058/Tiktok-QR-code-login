package main

// sign.go —— passport 四套签名的 Go 复刻
//
//	1) sign   query 参数，64 hex  (sha256)
//	2) qs     query 参数，xor5 hex
//	3) p_no   query 参数，64 hex  (sha256)
//	4) x-tt-passport-aid-sign  请求头，64 hex (HKDF-SHA256 + HMAC-SHA256)
//
// 所有结论来自 samples/douyin-web-login/web/verify 的实测样本，
// 真值断言见 sign_test.go。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// AppKey 是 passport 前端打包进 JS 的公开 app_key。
	AppKey = "163e7ce78d58971a41f5b969996d85c2"
	// AID 抖音 web 的 aid。
	AID = "6383"

	// signWindow sign / qs 只看按字典序排序后的前 10 个键。
	signWindow = 10
)

// excludedFromSign 参与 URL 但不参与 sign/qs 计算的键（窗口之外的才不影响结果）。
var excludedFromSign = map[string]struct{}{
	"sign":    {},
	"qs":      {},
	"a_bogus": {},
	"msToken": {},
}

// 注意：p_no 与 ts 必须留在窗口输入里 —— 它们虽然落在前 10 之外，
// 但剔除名单多一个或少一个都可能改变排序后的第 10 个键，别乱加。

// signSource 剔除 sign/qs/a_bogus/msToken，得到参与签名的 query 集合。
func signSource(query map[string]string) map[string]string {
	out := make(map[string]string, len(query))
	for k, v := range query {
		if _, skip := excludedFromSign[k]; skip {
			continue
		}
		out[k] = v
	}
	return out
}

// sortedJoin 复刻前端 l(o, cut)：
//
//	keys = Object.keys(o).sort(); if (cut >= 0) keys.splice(cut);
//	str  = keys.map(k => `${k}=${o[k]}`).join('&')
//
// cut < 0 表示不截断。
func sortedJoin(o map[string]string, cut int) (keys []string, str string) {
	keys = make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if cut >= 0 && len(keys) > cut {
		keys = keys[:cut]
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(o[k])
	}
	return keys, b.String()
}

// Sign 复刻 sign：
//
//	content = l(query,10).str + "&" + l(formData).str + "&app_key=" + appKey
//	sign    = sha256_hex(content)
func Sign(query, formData map[string]string) string {
	_, q := sortedJoin(signSource(query), signWindow)
	_, f := sortedJoin(formData, -1)
	return sha256Hex(q + "&" + f + "&app_key=" + AppKey)
}

// SignContent 暴露拼串结果，仅供测试与排障使用。
func SignContent(query, formData map[string]string) string {
	_, q := sortedJoin(signSource(query), signWindow)
	_, f := sortedJoin(formData, -1)
	return q + "&" + f + "&app_key=" + AppKey
}

// QS 复刻 qs：与 sign 共用同一组键名（前 10 个），按键名逗号拼接后 xor5。
func QS(query map[string]string) string {
	keys, _ := sortedJoin(signSource(query), signWindow)
	return xor5Hex(strings.Join(keys, ","))
}

// xor5Hex 对 UTF-8 每个字节 XOR 0x05，再逐字节转 2 位小写 hex。
func xor5Hex(s string) string {
	raw := []byte(s)
	var b strings.Builder
	b.Grow(len(raw) * 2)
	for _, c := range raw {
		const digits = "0123456789abcdef"
		x := c ^ 0x05
		b.WriteByte(digits[x>>4])
		b.WriteByte(digits[x&0x0f])
	}
	return b.String()
}

// unxor5 反解 qs，供单测逐字节比对键名列表。
func unxor5(s string) string {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	for i := range raw {
		raw[i] ^= 0x05
	}
	return string(raw)
}

// PNo 复刻 p_no：
//
//	参与键：passport_jssdk_version / p_bd / p_ca / p_ts / p_ver / p_zt
//	p_ca 的空值回退在调用方（缺省按 "0"），函数内不做兜底。
func PNo(params map[string]string) string {
	in := map[string]string{
		"passport_jssdk_version": params["passport_jssdk_version"],
		"p_bd":                   params["p_bd"],
		"p_ca":                   params["p_ca"],
		"p_ts":                   params["p_ts"],
		"p_ver":                  params["p_ver"],
		"p_zt":                   params["p_zt"],
	}
	_, str := sortedJoin(in, -1)
	return sha256Hex(str)
}

// PNoContent 暴露 p_no 的拼串结果，仅供测试。
func PNoContent(params map[string]string) string {
	in := map[string]string{
		"passport_jssdk_version": params["passport_jssdk_version"],
		"p_bd":                   params["p_bd"],
		"p_ca":                   params["p_ca"],
		"p_ts":                   params["p_ts"],
		"p_ver":                  params["p_ver"],
		"p_zt":                   params["p_zt"],
	}
	_, str := sortedJoin(in, -1)
	return str
}

// AIDSignPath 复刻 path 归一化：/passport 开头原样，否则拼 /passport/sso。
func AIDSignPath(path string) string {
	if strings.HasPrefix(path, "/passport") {
		return path
	}
	return "/passport/sso" + path
}

// AIDSignTS 当天 UTC 12:00 的秒级时间戳。
func AIDSignTS(now time.Time) string {
	u := now.UTC()
	noon := time.Date(u.Year(), u.Month(), u.Day(), 12, 0, 0, 0, time.UTC)
	return strconv.FormatInt(noon.Unix(), 10)
}

// AIDSign 复刻 x-tt-passport-aid-sign。
//
//	key = HKDF_SHA256(ikm=appKey, salt=ts, info=nil, L=32)   // ★ 标准 RFC5869 序
//	sig = hex(HMAC_SHA256(key, "aid=6383&path="+path+"&ts="+ts))
func AIDSign(appKey, path, ts string) string {
	key := hkdfSHA256([]byte(appKey), []byte(ts), nil, 32)
	return hmacHex(key, AIDSignMessage(path, ts))
}

// AIDSignMessage 暴露 HMAC 原文，仅供测试。
func AIDSignMessage(path, ts string) string {
	return "aid=" + AID + "&path=" + AIDSignPath(path) + "&ts=" + ts
}

// hkdfSHA256 RFC5869 展开（extract + expand），只支持 SHA-256。
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(prev)
		exp.Write(info)
		exp.Write([]byte{counter})
		prev = exp.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hmacHex = hex(HMAC_SHA256(key, msg))，aid-sign 的最后一层。
func hmacHex(key []byte, msg string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// trunc 打印凭据类值时统一截断：前 4 字符 + 长度。
func trunc(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= 4 {
		return s + "...(len=" + strconv.Itoa(len(s)) + ")"
	}
	return s[:4] + "...(len=" + strconv.Itoa(len(s)) + ")"
}
