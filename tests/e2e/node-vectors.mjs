#!/usr/bin/env node
//
// Check the Node implementation of canonical encoding against the frozen
// vectors in protocol/test-vectors/v1.json.
//
// This is the fourth independent implementation of CBE (Go, TypeScript, sh,
// Node) and it is held to the same standard: reproduce the bytes from the
// spec, not merely interoperate.
//
// Usage: node tests/e2e/node-vectors.mjs [path/to/redeem.mjs] [path/to/v1.json]

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const clientPath = resolve(process.argv[2] || join(repo, "install", "redeem.mjs"));
const vectorPath = resolve(process.argv[3] || join(repo, "protocol", "test-vectors", "v1.json"));

const c = await import(clientPath);
const V = JSON.parse(readFileSync(vectorPath, "utf8"));

let fail = 0;
const ok = (m) => console.log(`  ok ${m}`);
const bad = (m, got, want) => { fail = 1; console.log(`  FAIL ${m}\n     got:  ${got}\n     want: ${want}`); };
const check = (m, got, want) => (got === want ? ok(m) : bad(m, got, want));

const byName = Object.fromEntries(V.vectors.map((v) => [v.name, v]));
const hex = (b) => Buffer.from(b).toString("hex");
const raw = (b64) => c.unb64u(b64);

// Each message's field list, in the order protocol/v1.md declares it. The
// order is part of the encoding, so it is written out rather than derived.
const shape = {
  host_register: (m) => [
    c.fU64("version", m.version), c.fString("host_id", m.host_id),
    c.fBytes("identity_public_key", raw(m.identity_public_key)),
    c.fString("ssh_ca_public_key", m.ssh_ca_public_key),
    c.fString("ssh_host_public_key", m.ssh_host_public_key),
    c.fString("hostname", m.hostname), c.fU64("ssh_port", m.ssh_port),
    c.fString("ssh_user", m.ssh_user), c.fU64("timestamp", m.timestamp),
    c.fBytes("nonce", raw(m.nonce)),
  ],
  host_connect: (m) => [
    c.fU64("version", m.version), c.fString("host_id", m.host_id),
    c.fString("path", m.path), c.fU64("timestamp", m.timestamp),
    c.fBytes("nonce", raw(m.nonce)),
  ],
  grant: (m) => [
    c.fU64("version", m.version), c.fString("host_id", m.host_id),
    c.fString("grant_id", m.grant_id), c.fString("ssh_user", m.ssh_user),
    c.fU64("created_at", m.created_at), c.fU64("expires_at", m.expires_at),
  ],
  redemption: (m) => [
    c.fU64("version", m.version), c.fString("host_id", m.host_id),
    c.fString("grant_id", m.grant_id), c.fString("agent_id", m.agent_id),
    c.fBytes("agent_public_key", raw(m.agent_public_key)),
    c.fString("ssh_public_key", m.ssh_public_key),
    c.fU64("timestamp", m.timestamp), c.fBytes("nonce", raw(m.nonce)),
  ],
  agent_register: (m) => [
    c.fU64("version", m.version), c.fString("agent_id", m.agent_id),
    c.fBytes("public_key", raw(m.public_key)),
    c.fString("challenge_id", m.challenge_id), c.fString("pow_nonce", m.pow_nonce),
    c.fU64("timestamp", m.timestamp),
  ],
};

const shapeFor = {
  "grantd/v1/host-register": shape.host_register,
  "grantd/v1/host-connect": shape.host_connect,
  "grantd/v1/grant": shape.grant,
  "grantd/v1/redemption-agent-sig": shape.redemption,
  "grantd/v1/redemption-proof": shape.redemption,
  "grantd/v1/agent-register": shape.agent_register,
};

console.log("canonical bytes");
for (const v of V.vectors) {
  const fields = shapeFor[v.context](v.message);
  check(v.name, hex(c.cbe(v.context, fields)), v.canonical_hex);
}

console.log("signatures and macs");
for (const v of V.vectors) {
  const bytes = c.cbe(v.context, shapeFor[v.context](v.message));
  if (v.signature_hex) {
    const pub = v.context === "grantd/v1/redemption-agent-sig"
      ? raw(v.message.agent_public_key)
      : v.context === "grantd/v1/agent-register"
        ? raw(v.message.public_key)
        : Buffer.from(V.keys.host_identity_pub_hex, "hex");
    check(`${v.name} signature verifies`, String(c.verifyRaw(pub, bytes, Buffer.from(v.signature_hex, "hex"))), "true");
  }
  if (v.mac_hex) {
    const { createHmac } = await import("node:crypto");
    const mac = createHmac("sha256", Buffer.from(v.mac_key_hex, "hex")).update(bytes).digest();
    check(`${v.name} mac`, hex(mac), v.mac_hex);
  }
}

console.log("identifiers");
check("host_id", c.idOf("h", Buffer.from(V.keys.host_identity_pub_hex, "hex")), V.identifiers.host_id);
check("agent_id", c.idOf("a", Buffer.from(V.keys.agent_identity_pub_hex, "hex")), V.identifiers.agent_id);

console.log("capability url");
const cap = c.parseCapabilityURL(V.capability.capability_url);
check("origin", cap.origin, V.capability.origin);
check("host_id", cap.hostId, V.identifiers.host_id);
check("grant_id", cap.grantId, V.identifiers.grant_id);
check("secret", c.b64u(cap.secret), V.capability.secret_b64url);

console.log("ssh key encoding");
const agentPub = Buffer.from(V.keys.agent_identity_pub_hex, "hex");
check("authorized_keys line round trip",
  c.authorizedKeyLine(agentPub).split(" ")[0], "ssh-ed25519");

process.exit(fail);
