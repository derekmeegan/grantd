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

service.close();
proxy.close();
console.log(fail ? "\nFAIL" : "\nall proxy transport checks passed");
process.exit(fail);
