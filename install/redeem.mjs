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
//   node redeem.mjs [URL] [--out DIR] [--identity FILE] [--json]
//
// The URL can also come from GRANTD_CAPABILITY, or from stdin when URL is "-".
// Other users on the same machine can read command line arguments, so prefer
// those two forms on a shared machine.

import { createHmac, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as edSign, verify as edVerify } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir, homedir } from "node:os";

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

// Canonical Binary Encoding, protocol/v1.md section 1:
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
// signature over it. protocol/v1.md section 9 lists the fields grantd sets.
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

async function api(method, url, body) {
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(60_000),
    });
  } catch (e) {
    throw new Error(`could not reach ${url}: ${e.message}`);
  }
  const text = await res.text();
  if (res.ok) return text ? JSON.parse(text) : {};
  let parsed;
  try { parsed = JSON.parse(text); } catch { /* not a protocol error envelope */ }
  if (parsed?.error?.code) throw new Error(`${parsed.error.code}: ${parsed.error.message} (from ${url})`);
  if (res.status === 429) throw new Error(`rate limited by ${url}. Wait a minute and try again`);
  throw new Error(`HTTP ${res.status} from ${url}: ${text.slice(0, 200)}`);
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
  return { ...reg, caKey: caReader.string() };
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
  const opts = { url: process.env.GRANTD_CAPABILITY || "", out: "", json: false,
                 identity: process.env.GRANTD_IDENTITY || join(homedir(), ".grantd", "agent_identity.pem") };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opts.out = argv[++i];
    else if (a === "--identity") opts.identity = argv[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-") opts.url = readFileSync(0, "utf8").trim();
    else if (a.startsWith("-")) throw new Error(`unknown flag: ${a}`);
    else opts.url = a;
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const log = (m) => { if (!opts.json) console.error(m); };
  if (opts.help || !opts.url) {
    console.error("usage: node redeem.mjs [URL] [--out DIR] [--identity FILE] [--json]");
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
  writeFileSync(keyPath, openSshPrivateKey(rawSeed(ephemeral.privateKey), sshRawPub, "grantd ephemeral"), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  writeFileSync(keyPath + ".pub", sshLine + "\n", { mode: 0o644 });
  writeFileSync(certPath, response.certificate + "\n", { mode: 0o644 });

  if (opts.json) {
    console.log(JSON.stringify({
      ...response, key_file: keyPath, certificate_file: certPath,
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
    -l '${host.ssh_user}' -p ${host.ssh_port} -- '${host.hostname}'

This script does not open the session. If there is no ssh binary here, use a
JavaScript SSH client such as ssh2, loading ${keyPath}
as the private key and ${certPath} as its certificate.`);
  }
}

main().catch((e) => { console.error(`redeem.mjs: ${e.message}`); process.exit(1); });
