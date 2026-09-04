#!/usr/bin/env node
//
// Check that the Node client actually uses a configured proxy.
//
// This test exists because of a specific bug. Node's fetch ignores
// HTTPS_PROXY, so every API call went direct. On a developer machine with
// clean egress that looks like success, and in a sandbox whose only route out
// is a proxy it fails before the client reaches its own reachability check.
// The whole plain-CONNECT-proxy path was broken and nothing noticed, because
// every environment the code ran in had direct egress.
//
// The assertion is therefore not "the request succeeded". It is "the proxy
// saw the request". A client that bypasses the proxy still succeeds here, and
// still fails the test.
//
// Usage: node tests/e2e/node-proxy.mjs [path/to/redeem.mjs]

import { createServer as createHttpServer } from "node:http";
import { createServer as createTcpServer, connect as tcpConnect } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const clientPath = resolve(process.argv[2] || join(repo, "install", "redeem.mjs"));

let fail = 0;
const ok = (m) => console.log(`  ok ${m}`);
const bad = (m) => { fail = 1; console.log(`  FAIL ${m}`); };
const check = (m, cond) => (cond ? ok(m) : bad(m));

const listen = (server, host = "127.0.0.1") =>
  new Promise((res) => server.listen(0, host, () => res(server.address().port)));

// A service that records what reached it.
const seen = [];
const service = createHttpServer((req, res) => {
  seen.push(`${req.method} ${req.url}`);
  if (req.url === "/error") {
    res.writeHead(404, { "content-type": "application/json" });
    return res.end(JSON.stringify({ error: { code: "HOST_NOT_FOUND", message: "no such host" } }));
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ hello: "world", method: req.method }));
});
const servicePort = await listen(service);

// A CONNECT proxy that counts tunnels and can refuse on demand.
let connects = 0;
let refuse = false;
const proxy = createTcpServer((client) => {
  let head = "";
  const onData = (d) => {
    head += d.toString("latin1");
    if (!head.includes("\r\n\r\n")) return;
    client.removeListener("data", onData);
    const [method, hostport] = head.split("\r\n")[0].split(" ");
    if (method !== "CONNECT") return client.end("HTTP/1.1 405 no\r\n\r\n");
    if (refuse) return client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    connects++;
    const [host, port] = hostport.split(":");
    const upstream = tcpConnect({ host, port: Number(port) }, () => {
      client.write("HTTP/1.1 200 Connection established\r\n\r\n");
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy());
  };
  client.on("data", onData);
  client.on("error", () => {});
});
const proxyPort = await listen(proxy);

process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;
const client = await import(clientPath);
const base = `http://127.0.0.1:${servicePort}`;

// 1. A GET must travel through the proxy, not around it.
connects = 0;
const got = await client.api("GET", `${base}/v1/hosts/h_test`);
check("GET reaches the service", got.hello === "world");
check("GET went through the proxy", connects === 1);

// 2. A POST with a body, same requirement.
connects = 0;
const posted = await client.api("POST", `${base}/v1/agents`, { registration: { version: 1 } });
check("POST reaches the service", posted.method === "POST");
check("POST went through the proxy", connects === 1);
check("the service saw both requests", seen.length >= 2);

// 3. A protocol error from the service is still reported as the service's.
try {
  await client.api("GET", `${base}/error`);
  bad("a 404 should have thrown");
} catch (e) {
  check("service errors keep their protocol code", e.message.includes("HOST_NOT_FOUND"));
  check("service errors are not blamed on the sandbox", !e.message.includes("network policy"));
}

// 4. A refused tunnel is the sandbox's fault and must say so. This is the
//    misattribution that made a blocked sandbox look like a grantd rejection.
refuse = true;
try {
  await client.api("GET", `${base}/v1/hosts/h_test`);
  bad("a refused tunnel should have thrown");
} catch (e) {
  check("a refused tunnel names the proxy", e.message.includes("refused a tunnel"));
  check("a refused tunnel is attributed to the sandbox", e.message.includes("network policy"));
  check("a refused tunnel is not a protocol error", !/HOST_NOT_FOUND|BAD_REQUEST/.test(e.message));
}
refuse = false;

// 5. With no proxy configured the client must still work directly.
delete process.env.HTTPS_PROXY;
connects = 0;
const direct = await client.api("GET", `${base}/v1/hosts/h_test`);
check("works with no proxy configured", direct.hello === "world");
check("no proxy was used when none is set", connects === 0);

// 6. NO_PROXY is honoured, the way curl honours it. A sandbox that sets
//    HTTPS_PROXY also lists loopback and its directly reachable hosts in
//    NO_PROXY; sending those through the proxy anyway fails with an upstream
//    error that looks like the service being down. That is how this bug hid:
//    the shell client uses curl, which reads the list, and worked.
process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;
for (const [list, expectDirect, why] of [
  ["127.0.0.1", true, "an exact address"],
  ["localhost,127.0.0.0/8", true, "a CIDR range"],
  ["example.com", false, "an unrelated entry"],
  ["*", true, "a wildcard"],
]) {
  process.env.NO_PROXY = list;
  connects = 0;
  const r = await client.api("GET", `${base}/v1/hosts/h_test`);
  check(`NO_PROXY=${list}: reaches the service`, r.hello === "world");
  check(`NO_PROXY=${list}: ${expectDirect ? "bypasses" : "still uses"} the proxy (${why})`,
    connects === (expectDirect ? 0 : 1));
}
process.env.NO_PROXY = ".example.com, api.other.net:443 ,::1";
check("suffix with a leading dot matches a subdomain", client.bypassesProxy("api.example.com"));
check("suffix without a leading dot also matches a subdomain", (process.env.NO_PROXY = "example.com", client.bypassesProxy("api.example.com")));
check("suffix does not match a lookalike", !client.bypassesProxy("notexample.com"));
check("an entry with a port matches its host", (process.env.NO_PROXY = "api.other.net:443", client.bypassesProxy("api.other.net")));
check("an IPv6 entry is not mangled as host:port", (process.env.NO_PROXY = "::1", client.bypassesProxy("::1") && !client.bypassesProxy(":")));
check("lowercase no_proxy is read too", (delete process.env.NO_PROXY, process.env.no_proxy = "127.0.0.1", client.bypassesProxy("127.0.0.1")));
delete process.env.no_proxy;
delete process.env.HTTPS_PROXY;

service.close();
proxy.close();
console.log(fail ? "\nFAIL" : "\nall proxy transport checks passed");
process.exit(fail);
