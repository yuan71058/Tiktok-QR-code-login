package main

// probe_test.go —— check_qrconnect 4031 归因的可复现对照实验（默认跳过）
//
//	$env:DY_PROBE=1; go test ./... -run TestProbe4031 -v -count=1
//
// 前置：可用的 a_bogus 外挂签名命令（默认 node abogus-node.mjs + 已还原的 sign.mjs）。
//
// 结论（本文件就是证据）：
//   A 不带 a_bogus                     → error_code=4031「网站存在安全风险」
//   B 带 a_bogus（form 六键）          → error_code=0  status="new"
//   C 带 a_bogus 但 body 用 JSON       → error_code=3 「缺少参数」
//
// 也就是说：check_qrconnect 的门禁是 a_bogus + form-urlencoded 六键，
// 而 get_qrcode 只要 is_from_ttaccountsdk=1 就能过（不需要 a_bogus）。

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestProbe4031(t *testing.T) {
	if os.Getenv("DY_PROBE") == "" {
		t.Skip("设 DY_PROBE=1 才跑（需要网络 + node 签名器）")
	}
	abogusCmd := os.Getenv("DY_ABOGUS_CMD")
	if abogusCmd == "" {
		abogusCmd = "node abogus-node.mjs"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	newCli := func(withABogus bool) *Client {
		cli, err := NewClient(DefaultUA)
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		if withABogus {
			s, err := NewABogusSigner(abogusCmd, cli.ua)
			if err != nil {
				t.Fatalf("a_bogus 签名器: %v", err)
			}
			cli.UseABogus(s)
		}
		cli.Bootstrap(ctx, func(string, ...any) {})
		return cli
	}

	type result struct {
		Variant string `json:"variant"`
		ErrCode int    `json:"error_code"`
		Status  string `json:"status"`
		Body    string `json:"body"`
	}
	var rows []result

	// A / B：同一套 form 六键，只差 a_bogus
	formQR := func(t *testing.T, cli *Client) *QR {
		qr, err := cli.GetQRCode(ctx, "probe-qr.png")
		if err != nil {
			t.Fatalf("出码失败: %v", err)
		}
		return qr
	}

	// A：无 a_bogus
	{
		cli := newCli(false)
		qr := formQR(t, cli)
		res, err := cli.CheckQRConnect(ctx, qr)
		if err != nil {
			t.Fatalf("A 请求失败: %v", err)
		}
		rows = append(rows, result{"A 无 a_bogus", res.ErrCode, res.Raw, res.Snippet})
	}

	// B：带 a_bogus
	{
		cli := newCli(true)
		qr := formQR(t, cli)
		res, err := cli.CheckQRConnect(ctx, qr)
		if err != nil {
			t.Fatalf("B 请求失败: %v", err)
		}
		rows = append(rows, result{"B 带 a_bogus + form6", res.ErrCode, res.Raw, res.Snippet})
	}

	// C：带 a_bogus 但 body 用 JSON（复刻父库 node 客户端的错误形态）
	{
		cli := newCli(true)
		qr := formQR(t, cli)
		res, err := cli.CheckQRConnectJSON(ctx, qr)
		if err != nil {
			t.Fatalf("C 请求失败: %v", err)
		}
		rows = append(rows, result{"C 带 a_bogus + json6", res.ErrCode, res.Raw, res.Snippet})
	}

	blob, _ := json.MarshalIndent(rows, "", " ")
	t.Logf("对照结果:\n%s", string(blob))

	if rows[0].ErrCode != 4031 {
		t.Errorf("A 期望 4031，实际 %d", rows[0].ErrCode)
	}
	if rows[1].ErrCode != 0 || rows[1].Status != "new" {
		t.Errorf("B 期望 error_code=0/status=new，实际 %d/%q", rows[1].ErrCode, rows[1].Status)
	}
	if rows[2].ErrCode != 3 {
		t.Errorf("C 期望 error_code=3（缺少参数），实际 %d", rows[2].ErrCode)
	}
}
