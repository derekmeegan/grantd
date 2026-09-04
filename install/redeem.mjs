#!/usr/bin/env node
//
// Redeem a grantd capability URL. Node only, no dependencies, no binaries.
//
// This exists for agent sandboxes that have a JavaScript runtime and nothing
// else. It implements the same protocol as install/redeem.sh and produces the
// same canonical bytes. Node's own crypto module covers every primitive the
// protocol needs: ed25519, SHA-256, HMAC-SHA256, and base64url.
//
// It writes an OpenSSH private key and a certificate, then prints the ssh
// command. Opening the session needs an SSH client, which this script does not
// provide. See the note it prints at the end.
//
// Usage:
//   node redeem.mjs [URL] [--out DIR] [--identity FILE] [--json] [--no-probe]
//
// Every flag has an environment variable, because node cannot pass arguments
// to a piped module. A sandbox that refuses to save a downloaded script can
// still run it:
//
//   curl -s .../redeem.mjs | GRANTD_CAPABILITY=... GRANTD_OUT=./grant \
//     node --input-type=module
//
//   GRANTD_CAPABILITY  the capability URL, also readable from stdin as "-"
//   GRANTD_OUT         directory for the key and certificate
//   GRANTD_IDENTITY    agent identity file
//   GRANTD_JSON        set to any value for JSON output
//   GRANTD_NO_PROBE    set to 1 to skip the reachability check
//
// Other users on the same machine can read command line arguments, so prefer
// the variables on a shared machine.

import { createHmac, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as edSign, verify as edVerify } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { connect as tcpConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { pathToFileURL } from "node:url";

const PROTOCOL_VERSION = 1;
const SECRET_BYTES = 32;
const NONCE_BYTES = 16;

// ------------------------------------------------------------------ encodings

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64u = (s) => Buffer.from(s, "base64url");

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
// lp prefixes a byte string with its 32 bit big endian length.
const lp = (b) => Buffer.concat([u32(b.length), Buffer.from(b)]);

// Canonical Binary Encoding, docs/whitepaper.md §5.1:
//   CBE(context, fields) = LP(utf8(context)) || u32be(count)
//                          || for each: LP(utf8(name)) || tag || LP(value)
const TAG_STRING = 0x01, TAG_U64 = 0x02, TAG_BYTES = 0x03;

const fString = (name, v) => Buffer.concat([lp(Buffer.from(name, "utf8")), Buffer.from([TAG_STRING]), lp(Buffer.from(v, "utf8"))]);
const fU64 = (name, v) => Buffer.concat([lp(Buffer.from(name, "utf8")), Buffer.from([TAG_U64]), lp(u64(v))]);
const fBytes = (name, v) => Buffer.concat([lp(Buffer.from(name, "utf8")), Buffer.from([TAG_BYTES]), lp(v)]);

function cbe(context, fields) {
  return Buffer.concat([lp(Buffer.from(context, "utf8")), u32(fields.length), ...fields]);
}

// ---------------------------------------------------------------------- keys
//
// Node exports ed25519 keys as DER. The raw 32 byte public key is the tail of
// an SPKI export, and the raw 32 byte seed is the tail of a PKCS8 export.

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const rawPublicKey = (keyObject) => keyObject.export({ type: "spki", format: "der" }).subarray(-32);
const rawSeed = (keyObject) => keyObject.export({ type: "pkcs8", format: "der" }).subarray(-32);
const publicKeyFromRaw = (raw) =>
  createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });

const signRaw = (privateKey, msg) => edSign(null, msg, privateKey);
const verifyRaw = (rawPub, msg, sig) => {
  if (rawPub.length !== 32 || sig.length !== 64) return false;
  try { return edVerify(null, msg, publicKeyFromRaw(rawPub), sig); } catch { return false; }
};

// ------------------------------------------------------------- identifiers
//
// id = prefix || base32(sha256(raw public key)[0:20]), RFC 4648 lowercase.

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

function base32(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

const sha256 = (b) => createHash("sha256").update(b).digest();
const idOf = (prefix, rawPub) => prefix + "_" + base32(sha256(rawPub).subarray(0, 20));

// ---------------------------------------------------------------- ssh format
//
// SSH wire values are length prefixed byte strings. A public key blob is the
// key type followed by the key itself.

const sshString = (b) => lp(Buffer.from(b));

function sshReader(buf) {
  let off = 0;
  return {
    string() {
      const n = buf.readUInt32BE(off); off += 4;
      const out = buf.subarray(off, off + n); off += n;
      return out;
    },
    u64() { const v = buf.readBigUInt64BE(off); off += 8; return v; },
    u32() { const v = buf.readUInt32BE(off); off += 4; return v; },
    get offset() { return off; },
    get remaining() { return buf.length - off; },
  };
}

const sshEd25519Blob = (rawPub) => Buffer.concat([sshString("ssh-ed25519"), sshString(rawPub)]);
const authorizedKeyLine = (rawPub) => "ssh-ed25519 " + sshEd25519Blob(rawPub).toString("base64");
const sshFingerprint = (blob) => "SHA256:" + sha256(blob).toString("base64").replace(/=+$/, "");

// openSshPrivateKey writes the "openssh-key-v1" container that ssh(1) reads.
// The key is not encrypted, so the cipher and KDF are both "none".
function openSshPrivateKey(rawSeed32, rawPub, comment = "") {
  const pubBlob = sshEd25519Blob(rawPub);
  const check = randomBytes(4);
  let priv = Buffer.concat([
    check, check,
    sshString("ssh-ed25519"), sshString(rawPub),
    sshString(Buffer.concat([rawSeed32, rawPub])),
    sshString(comment),
  ]);
  // Pad to the cipher block size with the bytes 1, 2, 3 and so on.
  const pad = [];
  for (let i = 1; (priv.length + pad.length) % 8 !== 0; i++) pad.push(i);
  priv = Buffer.concat([priv, Buffer.from(pad)]);

  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "binary"),
    sshString("none"), sshString("none"), sshString(""),
    u32(1), sshString(pubBlob), sshString(priv),
  ]);
  const b64 = body.toString("base64").replace(/(.{70})/g, "$1\n");
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

// parseCertificate reads an ssh-ed25519 user certificate and verifies the CA
// signature over it. docs/whitepaper.md §8 lists the fields grantd sets.
function parseCertificate(line) {
  const parts = line.trim().split(" ");
  if (parts.length !== 2 || parts[0] !== "ssh-ed25519-cert-v01@openssh.com") {
    throw new Error("the response does not carry an ssh-ed25519 certificate");
  }
  const blob = Buffer.from(parts[1], "base64");
  const r = sshReader(blob);
  const cert = {};
  if (r.string().toString() !== "ssh-ed25519-cert-v01@openssh.com") throw new Error("certificate type mismatch");
  r.string();                       // nonce
  cert.key = r.string();            // the certified public key
  cert.serial = r.u64();
  cert.type = r.u32();              // 1 is a user certificate
  cert.keyId = r.string().toString();
  const principalBlob = r.string();
  cert.validAfter = r.u64();
  cert.validBefore = r.u64();
  r.string();                       // critical options
  cert.extensions = r.string();
  r.string();                       // reserved
  const signatureKeyBlob = r.string();
  const signedLength = r.offset;    // everything before the signature is signed
  const signatureBlob = r.string();

  cert.principals = [];
  const pr = sshReader(principalBlob);
  while (pr.remaining > 0) cert.principals.push(pr.string().toString());

  const kr = sshReader(signatureKeyBlob);
  if (kr.string().toString() !== "ssh-ed25519") throw new Error("certificate CA is not ssh-ed25519");
  cert.caKey = kr.string();
  cert.caBlob = signatureKeyBlob;

  const sr = sshReader(signatureBlob);
  if (sr.string().toString() !== "ssh-ed25519") throw new Error("certificate signature is not ssh-ed25519");
  const signature = sr.string();

  if (!verifyRaw(cert.caKey, blob.subarray(0, signedLength), signature)) {
    throw new Error("the certificate signature does not verify under its own CA key");
  }
  return cert;
}

// ---------------------------------------------------------------------- http

// Node's fetch ignores HTTPS_PROXY, and many agent sandboxes reach the
// network only through a proxy. Requests therefore go through node:http and
// node:https, over a CONNECT tunnel when a proxy is configured.
//
// A proxy refusal must never be reported as if the service rejected the
// caller. ProxyError keeps the two apart.
class ProxyError extends Error {}

// openTunnel asks the proxy for a byte pipe to host:port.
function openTunnel(proxy, host, port, timeout) {
  return new Promise((resolve, reject) => {
    const s = tcpConnect({ host: proxy.host, port: proxy.port, timeout });
    const via = `proxy ${proxy.host}:${proxy.port}`;
    let head = "";
    const fail = (m) => { s.destroy(); reject(new ProxyError(m)); };
    s.on("connect", () => {
      const auth = proxy.auth ? `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString("base64")}\r\n` : "";
      s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
    });
    s.on("data", function onHead(d) {
      head += d.toString("latin1");
      if (!head.includes("\r\n\r\n")) return;
      s.removeListener("data", onHead);
      const status = head.split("\r\n")[0].trim();
      if (!/ 2\d\d /.test(status + " ")) {
        return fail(`${via} refused a tunnel to ${host}:${port}: "${status}". This is the sandbox's network policy, not a grantd response.`);
      }
      s.setTimeout(0);
      resolve(s);
    });
    s.on("timeout", () => fail(`${via} did not answer`));
    s.on("error", (e) => fail(`${via}: ${e.message}`));
  });
}

async function api(method, urlStr, body) {
  const url = new URL(urlStr);
  const secure = url.protocol === "https:";
  const port = Number(url.port) || (secure ? 443 : 80);
  const proxy = proxyFor(url.hostname);
  const payload = body ? JSON.stringify(body) : null;

  let socket = null;
  if (proxy) socket = await openTunnel(proxy, url.hostname, port, 15_000);

  const { request } = await import(secure ? "node:https" : "node:http");
  const { connect: tlsConnect } = await import("node:tls");

  const { status, text } = await new Promise((resolve, reject) => {
    const options = {
      method,
      headers: payload
        ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
        : {},
    };
    // With a tunnel the socket already exists, so TLS runs on top of it.
    if (socket) {
      options.createConnection = () =>
        secure ? tlsConnect({ socket, servername: url.hostname }) : socket;
    }
    const req = request(url, options, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, text: data }));
    });
    req.setTimeout(60_000, () => req.destroy(new Error("timed out")));
    req.on("error", (e) => reject(new Error(`could not reach ${urlStr}: ${e.message}`)));
    if (payload) req.write(payload);
    req.end();
  });

  if (status >= 200 && status < 300) return text ? JSON.parse(text) : {};
  let parsed;
  try { parsed = JSON.parse(text); } catch { /* not a protocol error envelope */ }
  if (parsed?.error?.code) throw new Error(`${parsed.error.code}: ${parsed.error.message} (from ${urlStr})`);
  if (status === 429) throw new Error(`rate limited by ${urlStr}. Wait a minute and try again`);
  throw new Error(`HTTP ${status} from ${urlStr}: ${text.slice(0, 200)}`);
}

// -------------------------------------------------------------- validation

const HOST_ID_RE = /^h_[a-z2-7]{32}$/;
const GRANT_ID_RE = /^g_[a-z2-7]{16}$/;
const ORIGIN_RE = /^https?:\/\/[A-Za-z0-9.:-]+$/;
const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const HOSTNAME_RE = /^[A-Za-z0-9._:[\]-]{1,253}$/;

function parseCapabilityURL(raw) {
  const hash = raw.indexOf("#");
  if (hash < 0) throw new Error("the URL has no '#' fragment, so it carries no capability secret");
  const secret = unb64u(raw.slice(hash + 1));
  if (secret.length !== SECRET_BYTES) throw new Error("the capability secret is not 32 bytes");

  const path = raw.slice(0, hash);
  const m = path.match(/^(https?:\/\/[^/]+)\/g\/([^/]+)\/([^/]+)$/);
  if (!m) throw new Error("the URL path must be /g/<host_id>/<grant_id>");
  const [, origin, hostId, grantId] = m;
  if (!ORIGIN_RE.test(origin)) throw new Error("malformed origin in the URL");
  if (!HOST_ID_RE.test(hostId)) throw new Error("malformed host id in the URL");
  if (!GRANT_ID_RE.test(grantId)) throw new Error("malformed grant id in the URL");
  return { origin, hostId, grantId, secret };
}

// verifyHostRecord checks the host's signed registration against the host id
// from the capability URL. The host id is a hash of the host's identity key,
// so this needs no other trust anchor. The coordination service is not trusted
// and cannot produce a record that passes.
function verifyHostRecord(hostId, record) {
  const reg = record?.registration;
  if (!reg) throw new Error("the host record carries no signed registration");
  if (reg.version !== PROTOCOL_VERSION) throw new Error(`host registration has protocol version ${reg.version}`);
  if (reg.host_id !== hostId || record.host_id !== hostId) throw new Error("the host record is for a different host");

  const identity = unb64u(reg.identity_public_key);
  if (idOf("h", identity) !== hostId) throw new Error("the host identity key does not match the host id");

  const canonical = cbe("grantd/v1/host-register", [
    fU64("version", reg.version),
    fString("host_id", reg.host_id),
    fBytes("identity_public_key", identity),
    fString("ssh_ca_public_key", reg.ssh_ca_public_key),
    fString("ssh_host_public_key", reg.ssh_host_public_key),
    fString("hostname", reg.hostname),
    fU64("ssh_port", reg.ssh_port),
    fString("ssh_user", reg.ssh_user),
    fU64("timestamp", reg.timestamp),
    fBytes("nonce", unb64u(reg.nonce)),
  ]);
  if (!verifyRaw(identity, canonical, unb64u(record.signature))) {
    throw new Error("the host registration signature does not verify");
  }

  if (!USER_RE.test(reg.ssh_user) || reg.ssh_user === "root") throw new Error("the host record names a bad user");
  if (!HOSTNAME_RE.test(reg.hostname)) throw new Error("the host record carries a malformed hostname");
  if (!Number.isInteger(reg.ssh_port) || reg.ssh_port < 1 || reg.ssh_port > 65535) {
    throw new Error("the host record carries a bad port");
  }

  const ca = reg.ssh_ca_public_key.split(" ");
  if (ca.length !== 2 || ca[0] !== "ssh-ed25519") throw new Error("the host record carries a malformed SSH CA key");
  const caReader = sshReader(Buffer.from(ca[1], "base64"));
  if (caReader.string().toString() !== "ssh-ed25519") throw new Error("the SSH CA key is not ssh-ed25519");

  // The key sshd will present. The CA key verifies this agent to the host;
  // this verifies the host to this agent. A certificate cannot do that job.
  const hk = typeof reg.ssh_host_public_key === "string" ? reg.ssh_host_public_key.split(" ") : [];
  if (hk.length !== 2 || hk[0] !== "ssh-ed25519") throw new Error("the host record carries no usable SSH host key");
  const hkReader = sshReader(Buffer.from(hk[1], "base64"));
  if (hkReader.string().toString() !== "ssh-ed25519") throw new Error("the SSH host key is not ssh-ed25519");
  if (reg.ssh_host_public_key === reg.ssh_ca_public_key) throw new Error("the host record uses its CA key as its host key");
  return { ...reg, caKey: caReader.string(), hostKeyLine: reg.ssh_host_public_key };
}

// -------------------------------------------------------------- reachability
//
// A grant is single use. Burning one and then finding that this machine cannot
// open a session wastes it, so check the path to the host's SSH port first.
//
// Many agent sandboxes have no raw TCP egress and reach the network only
// through an HTTP CONNECT proxy. CONNECT builds a byte pipe once established,
// and SSH runs over it unchanged, so a proxy that allows the host and port is
// a working path.

function proxyFromEnv() {
  const raw = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.ALL_PROXY || process.env.all_proxy;
  if (!raw) return null;
  try {
    const u = new URL(raw.includes("://") ? raw : `http://${raw}`);
    return { host: u.hostname, port: Number(u.port || 8080), auth: u.username ? `${u.username}:${u.password}` : null };
  } catch { return null; }
}

// NO_PROXY, read the way curl reads it: a comma-separated list of hosts that
// must not go through the proxy. An entry matches its host exactly or as a
// domain suffix (a leading dot is optional), "*" matches everything, and an
// IPv4 CIDR matches an address inside it.
//
// This matters in exactly the sandboxes the proxy support exists for. They
// set HTTPS_PROXY and list loopback and the hosts they allow direct in
// NO_PROXY. Sending those through the proxy anyway fails with an upstream
// error that reads as the service being down, which is how this bug hid:
// curl honours the list, so the shell client worked where this one did not.
function bypassesProxy(host) {
  const raw = process.env.NO_PROXY || process.env.no_proxy;
  if (!raw) return false;
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, "");
  const ip4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  const toNum = (m) => ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
  for (let entry of raw.split(",")) {
    entry = entry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === "*") return true;
    const cidr = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(entry);
    if (cidr) {
      if (!ip4) continue;
      const bits = Number(cidr[2]);
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const net = toNum(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(cidr[1]));
      if ((toNum(ip4) & mask) === (net & mask)) return true;
      continue;
    }
    // "host:port" is allowed in the list; an IPv6 literal is not "host:port".
    if (/^[^:]+:\d+$/.test(entry)) entry = entry.replace(/:\d+$/, "");
    entry = entry.replace(/^\./, "");
    if (h === entry || h.endsWith("." + entry)) return true;
  }
  return false;
}

// The proxy to use for one host, or null to go direct.
function proxyFor(host) {
  return bypassesProxy(host) ? null : proxyFromEnv();
}

// An open socket is not proof of a usable path. Two cases look identical
// until the first bytes arrive:
//
//   A proxy that authorizes the tunnel and then requires TLS inside it
//   answers 200 to CONNECT and silently drops an SSH banner.
//
//   A TCP listener on the port might be any service at all.
//
// sshd sends its identification string unprompted on connect (RFC 4253
// section 4.2), so waiting one round trip for "SSH-" settles both cases and
// costs nothing.
function readBanner(socket, seed, label, done) {
  let buf = seed;
  const decide = () => {
    if (buf.length < 4) return false;
    if (buf.startsWith("SSH-")) {
      done(true, `${label}, ${buf.split("\r\n")[0].trim()}`);
    } else {
      done(false, `${label}, but the far end sent non-SSH bytes: ${JSON.stringify(buf.slice(0, 32))}`, true);
    }
    return true;
  };
  if (decide()) return;
  socket.on("data", (d) => { buf += d.toString("latin1"); decide(); });
}

function probeDirect(host, port, timeout) {
  return new Promise((resolve) => {
    const s = tcpConnect({ host, port, timeout });
    let connected = false;
    const done = (ok, detail) => { s.destroy(); resolve({ ok, detail }); };
    s.on("connect", () => { connected = true; readBanner(s, "", "direct TCP", done); });
    s.on("timeout", () => done(false, connected
      ? `connected to ${host}:${port}, but it sent no SSH banner`
      : `no answer from ${host}:${port} within ${timeout}ms`));
    s.on("error", (e) => done(false, e.message));
    s.on("end", () => done(false, `${host}:${port} closed the connection without an SSH banner`));
  });
}

function probeProxy(proxy, host, port, timeout) {
  return new Promise((resolve) => {
    const s = tcpConnect({ host: proxy.host, port: proxy.port, timeout });
    const via = `proxy ${proxy.host}:${proxy.port}`;
    let head = "", tunnelled = false;
    const done = (ok, detail, carriedNoSSH = false) => { s.destroy(); resolve({ ok, detail, carriedNoSSH }); };
    s.on("connect", () => {
      const auth = proxy.auth ? `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString("base64")}\r\n` : "";
      s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
    });
    s.on("data", function onHead(d) {
      if (tunnelled) return;
      head += d.toString("latin1");
      if (!head.includes("\r\n\r\n")) return;
      const status = head.split("\r\n")[0];
      if (!/ 2\d\d /.test(status + " ")) {
        return done(false, `${via} refused the tunnel: "${status.trim()}"`);
      }
      // The tunnel is open. The server's first bytes can already be here.
      tunnelled = true;
      s.removeListener("data", onHead);
      readBanner(s, head.split("\r\n\r\n").slice(1).join("\r\n\r\n"), `${via} opened a tunnel`, done);
    });
    s.on("timeout", () => tunnelled
      ? done(false, `${via} opened a tunnel to ${host}:${port} but carried no SSH`, true)
      : done(false, `${via} did not answer`));
    s.on("error", (e) => done(false, tunnelled
      ? `${via} reset the tunnel after CONNECT: ${e.code || e.message}`
      : `${via}: ${e.message}`));
    s.on("end", () => tunnelled
      ? done(false, `${via} closed the tunnel without sending any SSH banner`, true)
      : done(false, `${via} closed the connection`));
  });
}

async function probeReachable(host, port, timeout = 8000) {
  const proxy = proxyFor(host);
  const result = proxy ? await probeProxy(proxy, host, port, timeout) : await probeDirect(host, port, timeout);
  return { ...result, viaProxy: Boolean(proxy) };
}

// ----------------------------------------------------------------- identity

function loadIdentity(path) {
  if (existsSync(path)) {
    const key = createPrivateKey(readFileSync(path, "utf8"));
    return { key, raw: rawPublicKey(createPublicKey(key)) };
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // The same PEM shape openssl writes, so redeem.sh and redeem.mjs can share
  // one agent identity.
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return { key: privateKey, raw: rawPublicKey(publicKey), created: true };
}

// solvePow finds a nonce whose SHA-256 digest starts with the required number
// of zero bits. This is the cost that keeps registration from being free.
function solvePow(prefix, bits) {
  const whole = bits >> 3, rest = bits & 7;
  for (let i = 0; ; i++) {
    const d = sha256(Buffer.concat([prefix, Buffer.from(String(i))]));
    let ok = true;
    for (let j = 0; j < whole; j++) if (d[j] !== 0) { ok = false; break; }
    if (ok && rest !== 0 && d[whole] >>> (8 - rest) !== 0) ok = false;
    if (ok) return String(i);
  }
}

async function registerAgent(origin, identity, agentId, log) {
  log(`registering ${agentId}`);
  const challenge = await api("POST", `${origin}/v1/agent-challenges`);
  const nonce = solvePow(unb64u(challenge.pow.prefix), challenge.pow.difficulty_bits);
  const timestamp = Math.floor(Date.now() / 1000);

  const canonical = cbe("grantd/v1/agent-register", [
    fU64("version", PROTOCOL_VERSION),
    fString("agent_id", agentId),
    fBytes("public_key", identity.raw),
    fString("challenge_id", challenge.challenge_id),
    fString("pow_nonce", nonce),
    fU64("timestamp", timestamp),
  ]);
  await api("POST", `${origin}/v1/agents`, {
    registration: {
      version: PROTOCOL_VERSION, agent_id: agentId, public_key: b64u(identity.raw),
      challenge_id: challenge.challenge_id, pow_nonce: nonce, timestamp,
    },
    signature: b64u(signRaw(identity.key, canonical)),
  });
  log("registered");
}

// --------------------------------------------------------------------- main

function parseArgs(argv) {
  const opts = { url: process.env.GRANTD_CAPABILITY || "", out: process.env.GRANTD_OUT || "",
                 json: Boolean(process.env.GRANTD_JSON), noProbe: process.env.GRANTD_NO_PROBE === "1",
                 identity: process.env.GRANTD_IDENTITY || join(homedir(), ".grantd", "agent_identity.pem") };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opts.out = argv[++i];
    else if (a === "--identity") opts.identity = argv[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "--no-probe") opts.noProbe = true;
    // ProxyCommand mode. ssh runs this file again with this flag; it is not
    // a flag a person passes.
    else if (a === "--bridge") opts.bridge = argv[++i];
    else if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-") opts.url = readFileSync(0, "utf8").trim();
    else if (a.startsWith("-")) throw new Error(`unknown flag: ${a}`);
    else opts.url = a;
  }
  return opts;
}


// ------------------------------------------------------------------ bridge
//
// When there is no raw TCP path to the host, the session can go over the
// host's WebSocket bridge on 443 instead. A sandbox that allows HTTPS and
// nothing else allows this, because to its gateway it is HTTPS.
//
// This file is its own ProxyCommand: `node redeem.mjs --bridge wss://h/ssh`
// makes stdin and stdout the SSH transport. Doing it here rather than reusing
// the python shim means the Node path needs nothing that running this script
// did not already require.
//
// The transport moves; nothing else does. ssh still pins the host key by host
// id and still presents the certificate the host's CA issued, so what
// authorises the session is unchanged.

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** A TLS socket to host:port, through an HTTP CONNECT proxy when one is set. */
function bridgeSocket(host, port) {
  return new Promise((resolve, reject) => {
    // Parity with bridge-proxy.py. TLS here protects the transport; what
    // protects the session is the SSH host key ssh pins and the certificate
    // the host's CA issued, and neither depends on this.
    const insecure = process.env.GRANTD_BRIDGE_INSECURE_TLS === "1";
    if (insecure) {
      process.stderr.write(
        "redeem.mjs: WARNING: TLS certificate checking is off " +
        "(GRANTD_BRIDGE_INSECURE_TLS=1). The SSH host key is still pinned, so " +
        "the session is still verified; only the transport is unauthenticated.\n");
    }
    const tlsOpts = insecure ? { rejectUnauthorized: false } : {};
    const proxy = proxyFor(host);
    if (!proxy) {
      const s = tlsConnect({ host, port, servername: host, ...tlsOpts }, () => resolve(s));
      s.on("error", reject);
      return;
    }
    const raw = tcpConnect({ host: proxy.host, port: proxy.port });
    let head = "", tunnelled = false;
    raw.on("error", reject);
    raw.on("connect", () => {
      const auth = proxy.auth
        ? `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString("base64")}\r\n` : "";
      raw.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
    });
    raw.on("data", function onHead(d) {
      if (tunnelled) return;
      head += d.toString("latin1");
      if (!head.includes("\r\n\r\n")) return;
      const status = head.split("\r\n")[0];
      if (!/ 2\d\d /.test(status + " ")) {
        raw.destroy();
        return reject(new Error(`the proxy refused a tunnel to ${host}:${port}: "${status.trim()}"`));
      }
      tunnelled = true;
      raw.removeListener("data", onHead);
      const s = tlsConnect({ socket: raw, servername: host, ...tlsOpts }, () => resolve(s));
      s.on("error", reject);
    });
  });
}

/** Upgrades an open socket. Resolves with any bytes read past the headers. */
function wsHandshake(sock, hostHeader, path) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    sock.write(
      `GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nUpgrade: websocket\r\n` +
      `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\n` +
      `Sec-WebSocket-Version: 13\r\n\r\n`);
    let head = Buffer.alloc(0);
    const onData = (d) => {
      head = Buffer.concat([head, d]);
      const i = head.indexOf("\r\n\r\n");
      if (i === -1) return;
      sock.removeListener("data", onData);
      const lines = head.subarray(0, i).toString("latin1").split("\r\n");
      if (!lines[0].includes("101")) {
        return reject(new Error(`the bridge did not accept the upgrade (${lines[0]})`));
      }
      // Proves the peer is a WebSocket endpoint, not something that answered
      // 101 for reasons of its own.
      const want = createHash("sha1").update(key + WS_GUID).digest("base64");
      const got = lines.slice(1)
        .map((l) => l.split(":"))
        .find((kv) => kv[0].trim().toLowerCase() === "sec-websocket-accept");
      if (!got || got.slice(1).join(":").trim() !== want) {
        return reject(new Error("the bridge's handshake did not verify"));
      }
      resolve(head.subarray(i + 4));
    };
    sock.on("data", onData);
    sock.on("error", reject);
    sock.on("end", () => reject(new Error("the host closed the connection during the WebSocket handshake")));
  });
}

/** A masked frame. A client must mask; a server must not. */
function wsFrame(payload, opcode = 0x2) {
  const n = payload.length;
  let head;
  if (n < 126) {
    head = Buffer.from([0x80 | opcode, 0x80 | n]);
  } else if (n < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode; head[1] = 0xFE; head.writeUInt16BE(n, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode; head[1] = 0xFF; head.writeBigUInt64BE(BigInt(n), 2);
  }
  const mask = randomBytes(4);
  const body = Buffer.allocUnsafe(n);
  for (let i = 0; i < n; i++) body[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([head, mask, body]);
}

/** Reassembles frames. Control frames are answered or ignored here. */
function wsReader(sock, leftover, onMessage, onClose) {
  let buf = leftover;
  const pump = () => {
    for (;;) {
      if (buf.length < 2) return;
      const opcode = buf[0] & 0x0F;
      const masked = buf[1] & 0x80;
      let n = buf[1] & 0x7F, off = 2;
      if (n === 126) { if (buf.length < 4) return; n = buf.readUInt16BE(2); off = 4; }
      else if (n === 127) { if (buf.length < 10) return; n = Number(buf.readBigUInt64BE(2)); off = 10; }
      let mask = null;
      if (masked) { if (buf.length < off + 4) return; mask = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + n) return;
      let payload = buf.subarray(off, off + n);
      if (mask) {
        const un = Buffer.allocUnsafe(n);
        for (let i = 0; i < n; i++) un[i] = payload[i] ^ mask[i % 4];
        payload = un;
      }
      buf = buf.subarray(off + n);
      if (opcode === 0x8) return onClose();
      if (opcode === 0x9) { sock.write(wsFrame(payload, 0xA)); continue; }
      if (opcode === 0xA) continue;
      onMessage(payload);
    }
  };
  pump();
  sock.on("data", (d) => { buf = Buffer.concat([buf, d]); pump(); });
  sock.on("end", onClose);
  sock.on("error", onClose);
}

function parseWssUrl(raw) {
  const u = new URL(raw);
  if (u.protocol !== "wss:") {
    throw new Error(`only wss:// is supported; got "${u.protocol.replace(":", "")}"`);
  }
  return { host: u.hostname, port: Number(u.port || 443), hostHeader: u.host,
           path: (u.pathname || "/") + (u.search || "") };
}

/** Opens the bridge and closes it. Answers one question and spends nothing. */
async function probeBridge(url) {
  try {
    const { host, port, hostHeader, path } = parseWssUrl(url);
    const sock = await bridgeSocket(host, port);
    await wsHandshake(sock, hostHeader, path);
    sock.destroy();
    return true;
  } catch {
    return false;
  }
}

/** ProxyCommand mode: stdin and stdout become the SSH transport. */
async function runBridge(url) {
  const { host, port, hostHeader, path } = parseWssUrl(url);
  const sock = await bridgeSocket(host, port);
  const leftover = await wsHandshake(sock, hostHeader, path);
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    try { sock.destroy(); } catch { /* already gone */ }
    process.exit(0);
  };
  wsReader(sock, leftover, (payload) => process.stdout.write(payload), finish);
  process.stdin.on("data", (d) => sock.write(wsFrame(d)));
  process.stdin.on("end", finish);
  sock.on("close", finish);
}


/**
 * The ProxyCommand ssh will run, as a string.
 *
 * ssh needs a path to this file. When this script was piped into node there
 * is no argv[1] to point at, so a copy is fetched beside the key material —
 * the same origin that served the script running now.
 */
async function bridgeProxyCommand(origin, out, url) {
  let script = process.argv[1] && existsSync(process.argv[1]) ? process.argv[1] : null;
  if (!script) {
    const res = await fetch(`${origin}/redeem.mjs`);
    if (!res.ok) throw new Error(`could not fetch redeem.mjs for the bridge (HTTP ${res.status})`);
    script = join(out, "redeem.mjs");
    writeFileSync(script, await res.text(), { mode: 0o700 });
  }
  return `${process.execPath} ${script} --bridge ${url}`;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.bridge) return await runBridge(opts.bridge);
  const log = (m) => { if (!opts.json) console.error(m); };
  if (opts.help || !opts.url) {
    console.error("usage: node redeem.mjs [URL] [--out DIR] [--identity FILE] [--json] [--no-probe]");
    console.error("       the URL may also come from GRANTD_CAPABILITY, or from stdin with '-'");
    process.exit(2);
  }

  const cap = parseCapabilityURL(opts.url);
  const out = opts.out || mkdtempSync(join(tmpdir(), "grantd-"));
  mkdirSync(out, { recursive: true, mode: 0o700 });
  log(`host:   ${cap.hostId}`);
  log(`grant:  ${cap.grantId}`);
  log(`origin: ${cap.origin}`);

  // The service is not trusted. Take every connection detail from the host's
  // own signed registration, never from the redemption response.
  const host = verifyHostRecord(cap.hostId, await api("GET", `${cap.origin}/v1/hosts/${cap.hostId}`));
  log(`target: ${host.ssh_user}@${host.hostname}:${host.ssh_port} (signed by the host)`);

  // Check the path to the host before spending the grant. The advice has to
  // match the actual cause: telling someone to widen an allowlist when the
  // real problem is a TLS-inspecting proxy sends them after the wrong fix.
  let transport = "direct";
  let bridgeUrl = null;
  if (!opts.noProbe) {
    const probe = await probeReachable(host.hostname, host.ssh_port);
    if (!probe.ok) {
      const target = `${host.hostname}:${host.ssh_port}`;

      // Before giving up: the host may serve the session over a WebSocket on
      // 443. A sandbox that carries no SSH usually does carry that, which is
      // the whole reason the bridge exists.
      log(`direct ssh to ${target} is not available here; looking for a bridge`);
      const candidate = `wss://${host.hostname}/ssh`;
      if (await probeBridge(candidate)) {
        transport = "bridge";
        bridgeUrl = candidate;
        log(`bridge: ${candidate}`);
      }

      let advice;
      if (probe.carriedNoSSH) {
        advice =
`  The proxy authorized the tunnel and then dropped what went through it.
  A proxy that inspects HTTPS cannot carry SSH, and no client can work
  around that. This machine needs raw outbound TCP, or a proxy that
  tunnels bytes without inspecting them.`;
      } else if (probe.viaProxy) {
        advice = `  Ask for ${target} to be allowed through the proxy.`;
      } else {
        advice =
`  No HTTPS_PROXY is set. If this machine reaches the network through a
  proxy, set it and try again.
  If the host listens only on 22, ask its operator to re-run the installer
  with --listen-port 443, which most sandboxes allow.`;
      }
      if (transport !== "bridge") {
        throw new Error(
`this machine cannot reach ${target}, so the session could not be opened.
  ${probe.detail}
The grant was NOT spent. It is still valid until it expires.

${advice}
  If this sandbox allows only HTTP and TLS, ask the host's operator to run
  install/bridge.sh, which serves the session over a WebSocket on 443.
  Set GRANTD_NO_PROBE=1 to redeem anyway.`);
      }
    } else {
      log(`reachable: ${host.hostname}:${host.ssh_port} via ${probe.viaProxy ? "HTTP CONNECT proxy" : "direct TCP"}`);
    }
  }

  const identity = loadIdentity(opts.identity);
  const agentId = idOf("a", identity.raw);
  if (identity.created) log(`generated a new agent identity at ${opts.identity}`);
  log(`agent:  ${agentId}`);

  try {
    await api("GET", `${cap.origin}/v1/agents/${agentId}`);
  } catch {
    await registerAgent(cap.origin, identity, agentId, log);
  }

  // The certificate is issued over this key. The proof below covers the public
  // half, so nobody in the middle can substitute it.
  const ephemeral = generateKeyPairSync("ed25519");
  const sshRawPub = rawPublicKey(ephemeral.publicKey);
  const sshLine = authorizedKeyLine(sshRawPub);

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(NONCE_BYTES);
  const fields = [
    fU64("version", PROTOCOL_VERSION),
    fString("host_id", cap.hostId),
    fString("grant_id", cap.grantId),
    fString("agent_id", agentId),
    fBytes("agent_public_key", identity.raw),
    fString("ssh_public_key", sshLine),
    fU64("timestamp", timestamp),
    fBytes("nonce", nonce),
  ];
  // One statement, two proofs: a signature naming the agent, and a MAC proving
  // possession of the capability. Only the MAC authorizes issuance.
  const agentSignature = signRaw(identity.key, cbe("grantd/v1/redemption-agent-sig", fields));
  const proof = createHmac("sha256", cap.secret).update(cbe("grantd/v1/redemption-proof", fields)).digest();

  const response = await api("POST", `${cap.origin}/v1/hosts/${cap.hostId}/grants/${cap.grantId}/redeem`, {
    payload: {
      version: PROTOCOL_VERSION, host_id: cap.hostId, grant_id: cap.grantId,
      agent_id: agentId, agent_public_key: b64u(identity.raw),
      ssh_public_key: sshLine, timestamp, nonce: b64u(nonce),
    },
    agent_signature: b64u(agentSignature),
    proof: b64u(proof),
  });

  // The response is not signed. Every field must agree with the signed
  // registration, and the certificate must come from the host's own CA.
  if (response.hostname !== host.hostname) throw new Error("the response names a hostname the host did not sign");
  if (response.port !== host.ssh_port) throw new Error("the response names a port the host did not sign");
  if (response.user !== host.ssh_user) throw new Error("the response names a user the host did not sign");

  const cert = parseCertificate(response.certificate);
  if (!cert.caKey.equals(host.caKey)) throw new Error("the certificate was not signed by the host's CA");
  if (!cert.key.equals(sshRawPub)) throw new Error("the certificate is for a different key");
  if (cert.type !== 1) throw new Error("the certificate is not a user certificate");
  if (cert.principals.length !== 1 || cert.principals[0] !== host.ssh_user) {
    throw new Error(`the certificate names principals ${JSON.stringify(cert.principals)}, want [${host.ssh_user}]`);
  }
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (now < cert.validAfter || now >= cert.validBefore) throw new Error("the certificate is not valid right now");

  const keyPath = join(out, "id_ed25519");
  const certPath = join(out, "id_ed25519-cert.pub");
  // Pinned by host id, which HostKeyAlias looks up: the entry does not depend
  // on how the address is spelled or how the connection is carried.
  const knownHostsPath = join(out, "known_hosts");
  writeFileSync(knownHostsPath, `${cap.hostId} ${host.hostKeyLine}\n`, { mode: 0o600 });
  writeFileSync(keyPath, openSshPrivateKey(rawSeed(ephemeral.privateKey), sshRawPub, "grantd ephemeral"), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  writeFileSync(keyPath + ".pub", sshLine + "\n", { mode: 0o644 });
  writeFileSync(certPath, response.certificate + "\n", { mode: 0o644 });

  // ssh is told to run this file as its ProxyCommand only when the direct
  // path is unavailable. Everything else about the invocation is identical.
  const proxyCommand = transport === "bridge"
    ? await bridgeProxyCommand(cap.origin, out, bridgeUrl) : null;
  const proxyLine = proxyCommand ? `\n    -o ProxyCommand='${proxyCommand}' \\` : "";

  if (opts.json) {
    console.log(JSON.stringify({
      ...response, key_file: keyPath, certificate_file: certPath, known_hosts_file: knownHostsPath,
      host_key_alias: cap.hostId,
      transport, ...(transport === "bridge" ? { proxy_command: proxyCommand, bridge_url: bridgeUrl } : {}),
      key_fingerprint: sshFingerprint(sshEd25519Blob(sshRawPub)),
      valid_before_iso: new Date(Number(cert.validBefore) * 1000).toISOString(),
    }, null, 2));
  } else {
    console.log(JSON.stringify(response));
    console.error(`
verified: certificate from the host's CA, for this key, principal ${host.ssh_user},
          expires ${new Date(Number(cert.validBefore) * 1000).toISOString()}

ssh -i '${keyPath}' \\
    -o CertificateFile='${certPath}' \\
    -o IdentitiesOnly=yes \\
    -o UserKnownHostsFile='${knownHostsPath}' \\
    -o StrictHostKeyChecking=yes \\
    -o HostKeyAlias=${cap.hostId} \\
    -o HostKeyAlgorithms=ssh-ed25519 \\${proxyLine}
    -l '${host.ssh_user}' -p ${host.ssh_port} -- '${host.hostname}'

${transport === "bridge"
? `This machine has no raw TCP path to ${host.hostname}:${host.ssh_port}, so the session
goes over the host's WebSocket bridge on 443. TLS terminates on the host, not
on the coordination service, and the host key pinned in ${knownHostsPath}
still gates the session exactly as it would directly. Keep every one of those
options.`
: `The host key is pinned in ${knownHostsPath}, keyed by host id. Keep those
options: without them ssh accepts whatever machine answers the address.`}

This script does not open the session. If there is no ssh binary here, use a
JavaScript SSH client such as ssh2, loading ${keyPath}
as the private key and ${certPath} as its certificate.`);
  }
}

// Run when invoked directly, and when piped into node, where argv[1] is
// absent. Some agent sandboxes refuse to save a downloaded script to disk, so
// a pipe is the only way to execute it:
//
//   curl -s .../redeem.mjs | GRANTD_CAPABILITY=... node --input-type=module
//
// A test that imports this file leaves argv[1] pointing at the test, so main
// does not run there.
const pipedIntoNode = import.meta.url.includes("[eval");
const isEntryPoint = pipedIntoNode || !process.argv[1]
  || import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntryPoint) {
  main().catch((e) => { console.error(`redeem.mjs: ${e.message}`); process.exit(1); });
}

export {
  bypassesProxy,
  proxyFor,
  cbe, fString, fU64, fBytes, b64u, unb64u,
  idOf, base32, sha256, authorizedKeyLine, sshEd25519Blob, sshFingerprint,
  openSshPrivateKey, parseCertificate, parseCapabilityURL, verifyHostRecord,
  probeReachable, signRaw, verifyRaw, rawPublicKey, publicKeyFromRaw, solvePow,
  api, proxyFromEnv, ProxyError,
  parseWssUrl, wsFrame, probeBridge, runBridge,
};
