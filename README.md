# douyin-login-go

> **用途声明**：本项目仅用于**协议研究**与**自有账号登录**（在你自己账号上跑一遍二维码登录流程、
> 观察并记录公开端点的参数与签名算法）。它不提供任何绕过风控的能力，也不提供批量注册、
> 批量登录、撞库、养号或多账号自动化能力。请只用自己的账号，并遵守目标站点的服务条款。

抖音网页版**二维码登录**客户端：纯 HTTP，零浏览器、零 JS 运行时。
Go 标准库实现，`go build ./...` 无任何三方依赖。

```
douyin-login-go/
  go.mod            module douyinlogin（go 1.21+，纯标准库）
  main.go           CLI 入口
  session.go        cookie jar + 固定 UA + 请求/解包
  sign.go           sign / qs / p_no / aid-sign 四套签名
  params.go         公共参数基座 + query 组装
  qrcode.go         二维码 base64 → PNG 落盘 + 尺寸校验
  login.go          get_qrcode → check_qrconnect 轮询 → 取 sessionid
  verify.go         /aweme/v1/web/user/profile/self/ 验 uid
  ticketguard.go    bd-ticket-guard-* 四件套（P-256 本地生成）
  abogus.go         a_bogus 可选外挂签名器桥（默认不启用）
  abogus-node.mjs   a_bogus 外挂签名器（node，可选组件）
  sign_test.go      四套签名真值断言 + 锚点
  probe_test.go     4031 归因可复现对照实验（DY_PROBE=1 才跑）
  testdata/golden_check_qrconnect.json  实测抓包黄金样本
```

## 用法

```bash
# 只出码（纯 Go，无需任何外部组件）
go run . -out qr.png -timeout 180s -interval 2s

# 出码 + 轮询（轮询端点强制要 a_bogus，见「已知边界」）
go run . -out qr.png -abogus "node abogus-node.mjs" -timeout 180s -interval 2s

# 自检：只出码并试一轮轮询
go run . -skip-poll

# 单测（四套签名真值）
go test ./... -v

# 4031 归因对照实验（需要网络 + node 签名器）
$env:DY_PROBE=1; go test ./... -run TestProbe4031 -v
```

CLI 参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-out` | `qr.png` | 二维码 PNG 输出路径 |
| `-ua` | Chrome 119 | UA，**全流程固定**；改它必须整条链路一起改 |
| `-timeout` | `180s` | 轮询总超时 |
| `-interval` | `2s` | 轮询间隔（硬下限 1s，实测 ≥2s 不被限流） |
| `-skip-poll` | `false` | 只出码 + 单轮轮询，长轮询跳过 |
| `-abogus` | 空 | a_bogus 外挂签名命令；留空 = 纯 Go 形态 |

## 依赖

| 组件 | 版本 / 形态 | 说明 |
|---|---|---|
| Go | **1.21+** | 纯标准库，无三方 module，`go build ./...` 直接编译 |
| Node.js | ≥ 18（可选） | 仅在用 `-abogus` 时需要，用来跑 `abogus-node.mjs` |
| `abogus-node.mjs` | 随仓库分发 | 把外挂签名器包成 CLI，契约见文件头注释 |
| `sign.mjs` | **不随仓库分发** | 其内部依赖 `bdms.js`；路径用 `DY_SIGN_MJS` 指定 |
| `bdms.js` | **不随仓库分发** | 字节码签名运行时，需自行从官方 CDN 获取 |

`bdms.js` 的获取路径形态（`<ver>` 形如 `1.0.1.15`，请以当前线上版本为准）：

```
https://lf-c-flwb.bytetos.com/obj/rc-client-security/web/stable/<ver>/bdms.js
```

拿到后在 `sign.mjs` 侧指定，或直接给 `abogus-node.mjs` 传环境变量：

```bash
# Windows PowerShell
$env:DY_SIGN_MJS = "path/to/sign.mjs"      # 必填：外挂签名器入口
$env:DY_BDMS     = "path/to/bdms.js"       # 可选：sign.mjs 有默认路径
$env:DY_UA       = "<与 -ua 完全一致的 UA>"  # 可选：保证与签名 UA 一致

# 验证外挂链路（不给 -abogus 就是纯 Go 形态，出码不受影响）
go run . -out qr.png -abogus "node abogus-node.mjs" -timeout 180s -interval 2s
```

为什么不下发 `bdms.js`：它是站点侧压缩/混淆过的字节码运行时，属于对方资产，
随仓库分发既不合规也会立刻过期；本仓库只保留调用契约（argv/stdout），
运行时不进版本库。

## 凭据处理

本仓库**不含任何真实 cookie / token / 账号资料**。所有运行产物都在 `.gitignore` 里排除，
只留在本地，不进版本库、不进 commit：

| 产物 | 内容 | 状态 |
|---|---|---|
| `login-result.json` | cookie 名 + 长度 + 前 4 字符、uid | 已 ignore |
| `state-final.json` | token 前缀、uid | 已 ignore |
| `profile-self-full.json` | 账号资料全字段 | 已 ignore |
| `session-cookies.json` / `profile-self.json` | 完整 cookie / 资料 | 已 ignore |
| `run-serve.log` 等 `*.log` | 运行日志 | 已 ignore |
| `qr-live.png` / `qr*.png` | 真实登录二维码截图 | 已 ignore |
| `_trash-*/` | 清理回收站（含历史会话文件） | 已 ignore |
| `bin/` `*.exe` `data/` | 构建产物与本地产物目录 | 已 ignore |

提交前自检（期望 **0 命中**，命中即说明有凭据被 staged）：

```bash
git grep --cached -nE "sessionid=|sid_guard=|sid_tt=|uid_tt=|msToken=|passport_csrf_token=|x_tt_token="
```

判读：`exit 1` = 无命中（期望结果），`exit 0` = 有命中必须处理。

工程侧也做了约束：所有凭据打印一律截断成「前 4 字符 + 长度」（`sign.go:trunc`），
`testdata/golden_check_qrconnect.json` 里的 `fp` / `msToken` / `check token` 已替换成
`REDACTED_*` 占位符。`qs` / `p_no` / `aid_sign` 保留真机真值；`sign` 因输入含已脱敏字段
（`msToken` / `fp` / `token` / `a_bogus`），改为对脱敏输入的派生值，仅用于防回归，
**不可作为 `sign` 算法的对照真值**。

## 协议说明

### 0. 通用

- Host：`https://www.douyin.com`。所有请求的 `User-Agent` 必须与签名所用 UA 一致。
- 统一响应包络：`{"data":{...,"error_code":N,...},"message":"success|error"}`。
  成功判据是 `data.error_code == 0`，**不是 HTTP 状态码**（4031 也返回 HTTP 200）。
- **必带 `is_from_ttaccountsdk=1`**：这是 `get_qrcode` 的 4031 唯一开关，缺了或置 0 直接
  `error_code=4031`（已在 `confirm.json` 的 C1/C2 变体里实测复现）。
- `device_platform`：`get_qrcode` 用 `web_app`（下划线），`account/info` 一类用 `webapp`。
- 公共参数基座见 `params.go:BaseParams()`。

### 1. `sign`（query，64 hex）

```
window = 剔除 sign/qs/a_bogus/msToken 后的 query，按字典序取前 10
content = join(window → "k=v", "&") + "&" + join(formData 全量排序, "&") + "&app_key=" + APP_KEY
sign    = sha256_hex(content)
```

- 拼接前值按 **URL 解码** 后的形态参与；数组/对象用 `JSON.stringify`。
- `APP_KEY = 163e7ce78d58971a41f5b969996d85c2`。
- **POST 端点必须把 formData 拼进去**（`check_qrconnect` 的六键）。

### 2. `qs`（query，hex）

```
qs = xor5_hex( join(window 的键名, ",") )      # 与 sign 共用同一组键名
```

`xor5_hex`：对 UTF-8 每个字节 XOR `0x05`，逐字节转 2 位小写 hex。

### 3. `p_no`（query，64 hex）

```
o = { passport_jssdk_version, p_bd, p_ca, p_ts, p_ver, p_zt }
p_no = sha256_hex( join(sorted(o) → "k=v", "&") )
```

- `p_ts` = 13 位毫秒，必须与实际请求同一时刻；**每轮轮询都要重算**。
- `p_ca` 空值回退成 `"0"` 在调用方（`PNo` 内不做兜底）。
- `get_qrcode` / `challenge` / `check_qrconnect` 上 `p_ca=4.0.26`。

### 4. `x-tt-passport-aid-sign`（请求头，64 hex）

```go
ts  := 当天 UTC 12:00 的秒级时间戳        // time.Date(y,m,d,12,0,0,0,time.UTC).Unix()
key := HKDF_SHA256(ikm=appKey, salt=ts, info=nil, L=32)   // 标准 RFC5869 序
sig := hex(HMAC_SHA256(key, "aid=6383&path="+path+"&ts="+ts))
```

- `path` 归一化：`/passport` 开头原样，否则拼 `/passport/sso` 前缀。
- 同时把 `ts` 注入 query。
- **参数序写反是经典坑**：`ikm=appKey`、`salt=ts`。`sign_test.go` 里有一条反证断言
  （把 ikm/salt 调换后结果必须不同）。

### 5. `a_bogus`

`bdms.js`（JSVMP 字节码）算的，纯 Go 复刻等于再造一台解释器，本工程**不实现**。
实测边界（见下）：

- `get_qrcode`：**不需要**，`error_code=0` 照常出码；
- `check_qrconnect`：**必须**，缺了必 4031。

所以 `abogus.go` 做成可选外挂：`-abogus "<cmd>"` 里 `<cmd>` 收到
`argv[1]=URL`、`argv[2]=form body`，stdout 吐 a_bogus 原文，Go 侧只 `os/exec`。
仓库自带 `abogus-node.mjs` 包一层已还原的 `sign.mjs`。

### 6. `bd-ticket-guard-*` 请求头

`838.b031aa6c.js@593736` 的 `providerPathList` 里包含 `/passport/web/check_qrconnect/`
（同批还有 `sms_login` / `user_login` / `web_login` 等），端点必须带：

```
bd-ticket-guard-version:        2
bd-ticket-guard-web-version:    2
bd-ticket-guard-web-sign-type:  0
bd-ticket-guard-ree-public-key: base64(0x04||X||Y)   # 65 字节未压缩 P-256 点，88 字符
```

前三个是常量，公钥是**端上本地生成的 P-256 密钥对**（不需要服务端证书），
`crypto/ecdsa` + `crypto/elliptic` 即可，见 `ticketguard.go`。

### 7. 流程

```
① GET  https://www.douyin.com/                          拿 __ac_nonce（建议）
② GET  mssdk.bytedance.com/web/r/token?ms_appid=6383    拿 msToken（404 不阻塞）
③ POST /passport/user_info/get_sec_ts/                  服务器时间（失败忽略）
④ POST ttwid.bytedance.com/ttwid/union/register/        领 ttwid 并搬到 douyin 域
⑤ GET  /passport/general/login_guiding_strategy/        拿 passport_csrf_token
⑥ GET  /passport/web/get_qrcode/?<全套参数>              出码
⑦ 保存 PNG
⑧ POST /passport/web/check_qrconnect/                    轮询（每轮重算四套签名）
⑨ confirmed → redirect_url → sessionid / sid_tt
⑩ GET  /aweme/v1/web/user/profile/self/                  验 uid
```

`get_qrcode` 专有参数：`next=https://www.douyin.com & need_short_url=true & need_logo=false
& is_new_login=1 & is_from_iesaccountsaas=1 & p_ui=2.4.23`。

`check_qrconnect` body（**form-urlencoded 六键**，JSON 会掉 `error_code=3 缺少参数`）：

```
need_logo=false & is_frontier=<出码响应的 is_frontier> & token=<出码响应的 token>
& is_new_login=1 & next=https://www.douyin.com & need_short_url=true
```

状态机：`"1"/"new"` → `"2"/"scanned"` → `"3"/"confirmed"`；
`"4"/"5"/"refused"/"expired"` 终止。

### 8. 登录态探针

`/passport/web/account/info/` 登录后仍返回 `error_code=16`，**它不是登录态探针**。
用 `/aweme/v1/web/user/profile/self/?aid=6383&device_platform=webapp&channel=channel_pc_web`，
判据 `status_code == 0` 且 `user.uid` 非空。

## 已知边界

1. **`check_qrconnect` 必须带 a_bogus**。这是本工程唯一的非纯 Go 环节：
   不加 → `error_code=4031`；加了 → `error_code=0 / status:"new"`。
   三条对照由 `probe_test.go` 固化，可复现：

   | 变体 | error_code | status |
   |---|---|---|
   | A 无 a_bogus | 4031 | — |
   | B 有 a_bogus + form 六键 | **0** | **new** |
   | C 有 a_bogus + JSON body | 3（缺少参数） | — |

2. **msToken 拿不到**：`mssdk.bytedance.com/web/r/token` 的 body 是 bmssdk 加密载荷，
   直接 GET 返回 404。实测不带 msToken 也能出码与轮询，故不实现。
3. **`challenge` / `ticket_guard` / `dtrait` 未实现**：出码与确认都不依赖它们。
   若要打受保护端点（`/passport/web/sms_login/`、`user_login`、`web_login`、
   `email/login` 等），需要补：
   - `POST /passport/ticket_guard/get_client_cert/` → `data.server_cert`（ECIES 服务端证书，
     `protect/ecies.mjs` 有离线实现），之后请求带上 `bd-ticket-guard-*` + 响应侧
     `bd-ticket-guard-sec-ts`；
   - `POST /passport/web/challenge/` → `data.passportiv`，
     body `{sign: AES-CBC(btoa(JSON(payload))), sk}`；
   - `x-tt-session-dtrait`（`uc-secure-dtrait-core` 签名）。
4. **不替你扫码**：出码 + 轮询到 `new` 是本工程的验收面；`confirmed` 之后的
   `redirect_url` → `sessionid` 逻辑已实现但需要真人扫码才能触发。
5. **频率约束**：轮询 ≥2s，全会话硬上限 60 次请求（`Client.limit`），超了直接报错不硬跑。
6. **凭据打印一律截断**：`msToken` / `passport_csrf_token` / `sessionid` 只打
   前 4 字符 + 长度（`sign.go:trunc`）。

## 实测记录

```
go version go1.26.4 windows/amd64
go vet ./...   → 0
go build ./... → 0
go test ./...  → ok douyinlogin（四套签名真值断言全 PASS）

go run . -out qr.png -abogus "node abogus-node.mjs" -timeout 18s -interval 4s
  ✓ get_qrcode error_code=0 token=<35ch>
  二维码 PNG: qr.png（795 bytes, 400x400, PNG magic 89 50 4e 47）
  [01]..[05] status=new err=0
```
