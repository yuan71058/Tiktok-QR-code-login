/**
 * abogus-node.mjs —— Go 客户端用的 a_bogus 外挂签名器（可选组件）
 *
 * 契约（与 abogus.go 对齐）：
 *   argv[1] = 完整 URL（含 query，不含 a_bogus）
 *   argv[2] = form body（GET 时为空串）
 *   stdout  = a_bogus 的值（一行，不加任何装饰）
 *
 * 它只是把已还原好的 bdms.js 签名器（sign.mjs）包一层 CLI。
 * sign.mjs 与 bdms.js 均不随本仓库分发，需自行准备（见 README「依赖」）。
 * 环境变量：
 *   DY_SIGN_MJS  sign.mjs 路径（强烈建议显式指定；默认取当前工作目录下的 ./sign.mjs）
 *   DY_BDMS      bdms.js 路径（可选，sign.mjs 内有默认解析）
 *   DY_UA        UA（Go 侧传进来，保证与签名 UA 一致）
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SIGN_MJS = process.env.DY_SIGN_MJS || './sign.mjs';

const [urlArg, bodyArg] = process.argv.slice(2);
if (!urlArg) {
  console.error('用法: node abogus-node.mjs <url> [formBody]');
  process.exit(2);
}

const mod = await import(pathToFileURL(path.resolve(SIGN_MJS)).href);

const opts = {};
if (process.env.DY_BDMS) opts.bdmsPath = process.env.DY_BDMS;
if (process.env.DY_UA) opts.ua = process.env.DY_UA;

const signer = await mod.createSigner(opts);
const ab = await signer.sign({
  url: urlArg,
  body: bodyArg && bodyArg.length ? bodyArg : null,
  ua: process.env.DY_UA || undefined,
});

process.stdout.write(ab);
// bdms 的 vm 沙箱里挂着 setInterval/定时上报句柄，不显式退出进程会一直活着。
process.exit(0);
