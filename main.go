package main

// main.go —— CLI 入口
//
//	go run . -out qr.png -ua "<UA>" -timeout 180s -interval 2s
//
// 纯 HTTP，无浏览器、无 JS 运行时：只需要 sign / qs / p_no / aid-sign 四套签名。

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

func main() {
	out := flag.String("out", "qr.png", "二维码 PNG 输出路径")
	ua := flag.String("ua", DefaultUA, "User-Agent（必须与签名 UA 一致，全程固定）")
	timeout := flag.Duration("timeout", 180*time.Second, "轮询总超时")
	interval := flag.Duration("interval", 2*time.Second, "轮询间隔（≥2s）")
	skipPoll := flag.Bool("skip-poll", false, "只出码并试一轮轮询，不进长轮询（CI 自检用）")
	abogus := flag.String("abogus", "", "可选：a_bogus 外挂签名命令，例如 \"node abogus-node.mjs\"；留空=纯 Go（轮询会 4031）")
	dumpDir := flag.String("dumpdir", ".", "登录成功后写 session-cookies.json / profile-self.json（脱敏）的目录")
	serve := flag.String("serve", "", "实时二维码页监听地址，例如 127.0.0.1:8899；留空=CLI 出码模式")
	flag.Parse()

	if *interval < time.Second {
		fmt.Fprintf(os.Stderr, "-interval 太小（%s），最少 1s；建议 2s\n", *interval)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *serve != "" {
		if err := runServe(ctx, *serve, *ua, *abogus, *dumpDir, *interval, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "\n✗ serve: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(ctx, *out, *ua, *timeout, *interval, *skipPoll, *abogus, *dumpDir); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out, ua string, timeout, interval time.Duration, skipPoll bool, abogusCmd, dumpDir string) error {
	logf := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	}

	cli, err := NewClient(ua)
	if err != nil {
		return err
	}
	signer, err := NewABogusSigner(abogusCmd, cli.ua)
	if err != nil {
		return err
	}
	cli.UseABogus(signer)

	logf("douyin-login-go · 纯 HTTP 二维码登录")
	logf("  UA=%s", cli.ua)
	logf("  out=%s interval=%s timeout=%s", out, interval, timeout)
	logf("  ticket-guard ree-public-key=%s", trunc(cli.tg.PublicKeyB64()))
	if signer == nil {
		logf("  a_bogus=未启用（出码不需要；轮询 check_qrconnect 必带，缺了会 4031）")
	} else {
		logf("  a_bogus=外挂签名器 %v", signer.argv)
	}
	logf("")

	logf("① 引导")
	cli.Bootstrap(ctx, logf)

	logf("② 出码")
	qr, err := cli.GetQRCode(ctx, out)
	if err != nil {
		if qr != nil {
			logf("  error_code=%d", qr.ErrCode)
			logf("  body=%s", qr.Snippet)
		}
		return err
	}
	logf("  ✓ error_code=%d token=%s len=%d", qr.ErrCode, qr.Token, len(qr.Token))
	logf("  二维码 PNG: %s (%d bytes, %dx%d, is_frontier=%s, 头=%x)",
		qr.Path, qr.Bytes, qr.Width, qr.Height, qr.IsFrontier, pngMagic)
	logf("  → 用抖音 App 扫码确认（本程序不会替你扫码）")
	logf("")

	logf("③ 轮询 check_qrconnect（每轮重算 sign/qs/p_no/aid-sign）")
	if skipPoll {
		res, err := cli.CheckQRConnect(ctx, qr)
		if err != nil {
			return err
		}
		logf("  单轮 status=%s raw=%q", res.Status, res.Raw)
		logf("")
		logf("已发出的请求数：%d", cli.Requests())
		return nil
	}

	res, err := cli.WaitLogin(ctx, qr, interval, timeout, logf)
	if err != nil {
		logf("")
		logf("轮询结束：%v（请求数=%d）", err, cli.Requests())
		return nil // 超时不算失败：出码与轮询通路已验证
	}

	logf("")
	switch res.Status {
	case "confirmed":
		logf("④ 已确认，收 session")
		if _, err := cli.HarvestSession(ctx, res, logf); err != nil {
			logf("  ✗ %v", err)
			return err
		}
		logf("")
		logf("⑤ 验证登录态（profile/self）")
		p, err := cli.VerifyUID(ctx)
		if err != nil {
			if p != nil {
				logf("  %s", p.Describe())
			}
			return err
		}
		logf("  ✓ %s", p.Describe())
		logf("")
		logf("⑥ 落盘脱敏产物（cookie 只留 name+len+前4）")
		ck, pf, derr := cli.DumpArtifacts(p, dumpDir)
		if derr != nil {
			logf("  ✗ dump: %v", derr)
		} else {
			logf("  session-cookies.json → %s（%d 个 cookie: %v）", ck, len(cli.CookieNames()), cli.CookieNames())
			logf("  profile-self.json   → %s", pf)
		}
	default:
		logf("④ 扫码未完成：status=%s（raw=%q）", res.Status, res.Raw)
	}
	logf("")
	logf("已发出的请求数：%d", cli.Requests())
	return nil
}
