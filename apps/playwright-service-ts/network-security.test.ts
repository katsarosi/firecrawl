import assert from "node:assert/strict";
import net, { Socket } from "node:net";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  assertPublicAddress,
  browserProxy,
  chromiumSecurityArguments,
  InsecureConnectionError,
  NavigationPolicy,
  parseSafeDestination,
  SecureEgressProxy,
  validateResolvedAddresses,
  type DialPinned,
  type ResolveAll,
} from "./network-security";

const publicAddress = "93.184.216.34";

function fakeUpstream(address: string): Socket {
  const stream = new PassThrough();
  Object.defineProperty(stream, "remoteAddress", { value: address });
  return stream as unknown as Socket;
}

async function connect(proxy: string, authority: string): Promise<string> {
  const endpoint = new URL(proxy);
  return await new Promise((resolve, reject) => {
    const socket = net.connect(Number(endpoint.port), endpoint.hostname, () => {
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
      );
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("proxy response timeout"));
    }, 1000);
    socket.once("data", (data) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(data.toString("ascii").split("\r\n")[0]);
    });
    socket.once("error", reject);
  });
}

test("public-address policy rejects representative IPv4 and IPv6 ranges", () => {
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "192.0.2.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "::",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff00::1",
    "2001:db8::1",
    "::ffff:10.0.0.1",
  ])
    assert.throws(() => assertPublicAddress(address), InsecureConnectionError);
  assert.doesNotThrow(() => assertPublicAddress(publicAddress));
  assert.doesNotThrow(() =>
    assertPublicAddress("2606:2800:220:1:248:1893:25c8:1946"),
  );
  assert.throws(() =>
    validateResolvedAddresses([
      { address: publicAddress, family: 4 },
      { address: "10.0.0.1", family: 4 },
    ]),
  );
  assert.throws(() => validateResolvedAddresses([]));
});

test("URL policy rejects downgrade, credentials, fragments, literals, and explicit ports", () => {
  for (const value of [
    "http://example.com",
    "https://user:pass@example.com",
    "https://example.com/#x",
    "https://example.com:443",
    "https://example.com:444",
    "https://127.0.0.1",
    "https://[::1]",
    "https://localhost",
  ])
    assert.throws(() => parseSafeDestination(value), InsecureConnectionError);
});

test("secure connector pins the validated address and blocks DNS rebinding", async () => {
  let resolution = 0;
  const resolver: ResolveAll = (_host, callback) => {
    resolution++;
    callback(null, [
      { address: resolution === 1 ? publicAddress : "10.0.0.1", family: 4 },
    ]);
  };
  const dialed: string[] = [];
  const dial: DialPinned = (address, _port, callback) => {
    dialed.push(address);
    callback(null, fakeUpstream(address));
  };
  const proxy = new SecureEgressProxy(resolver, dial);
  const endpoint = await proxy.start();
  try {
    assert.equal(
      await connect(endpoint, "example.com:443"),
      "HTTP/1.1 200 Connection Established",
    );
    assert.equal(
      await connect(endpoint, "example.com:443"),
      "HTTP/1.1 403 Forbidden",
    );
    assert.deepEqual(dialed, [publicAddress]);
  } finally {
    await proxy.close();
  }
});

test("secure connector fails closed for mixed DNS, failures, empty answers, unsafe ports, and IP literals", async () => {
  const answers: Array<
    [
      NodeJS.ErrnoException | null,
      Array<{ address: string; family: number }> | undefined,
    ]
  > = [
    [
      null,
      [
        { address: publicAddress, family: 4 },
        { address: "169.254.169.254", family: 4 },
      ],
    ],
    [Object.assign(new Error("dns"), { code: "ENOTFOUND" }), undefined],
    [null, []],
  ];
  for (const [error, addresses] of answers) {
    let dialed = false;
    const proxy = new SecureEgressProxy(
      (_host, callback) => callback(error, addresses),
      (_address, _port, callback) => {
        dialed = true;
        callback(new Error("must not dial"));
      },
    );
    const endpoint = await proxy.start();
    assert.equal(
      await connect(endpoint, "example.com:443"),
      "HTTP/1.1 403 Forbidden",
    );
    assert.equal(dialed, false);
    await proxy.close();
  }
  const proxy = new SecureEgressProxy((_host, callback) =>
    callback(null, [{ address: publicAddress, family: 4 }]),
  );
  const endpoint = await proxy.start();
  assert.equal(
    await connect(endpoint, "example.com:80"),
    "HTTP/1.1 403 Forbidden",
  );
  assert.equal(
    await connect(endpoint, "127.0.0.1:443"),
    "HTTP/1.1 403 Forbidden",
  );
  await proxy.close();
});

function request(
  url: string,
  navigation: boolean,
  redirectedFrom: object | null = null,
) {
  return {
    url: () => url,
    isNavigationRequest: () => navigation,
    redirectedFrom: () => redirectedFrom,
  };
}

test("navigation policy enforces loops and a ten-redirect maximum without resetting", () => {
  const policy = new NavigationPolicy();
  let previous: object | null = null;
  for (let index = 0; index <= 10; index++) {
    const current = request(`https://example.com/${index}`, true, previous);
    policy.observe(current as never);
    previous = current;
  }
  assert.throws(
    () =>
      policy.observe(
        request("https://example.com/11", true, previous) as never,
      ),
    /too_many_redirects/,
  );

  const loop = new NavigationPolicy();
  const first = request("https://example.com/a", true);
  loop.observe(first as never);
  loop.observe(request("https://other.example/b", true, first) as never);
  assert.throws(
    () => loop.observe(request("https://example.com/a", true, first) as never),
    /redirect_loop/,
  );
});

test("all browser requests are URL-validated, including unsafe redirect and subresource URLs", () => {
  const policy = new NavigationPolicy();
  for (const url of [
    "https://127.0.0.1/image.png",
    "http://example.com/script.js",
    "https://user:pass@example.com/redirect",
    "https://example.com:444/redirect",
  ]) {
    assert.throws(
      () => policy.observe(request(url, false) as never),
      InsecureConnectionError,
    );
  }
});

test("Chromium configuration cannot bypass the secure connector", () => {
  const endpoint = "http://127.0.0.1:32123";
  assert.deepEqual(browserProxy(endpoint), { server: endpoint, bypass: "" });
  const args = chromiumSecurityArguments(endpoint);
  assert.ok(args.includes(`--proxy-server=${endpoint}`));
  assert.ok(args.includes("--proxy-bypass-list=<-loopback>"));
  assert.ok(
    args.some((value) =>
      value.startsWith("--host-resolver-rules=MAP * ~NOTFOUND"),
    ),
  );
  assert.ok(args.includes("--disable-quic"));
  assert.ok(
    args.includes("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"),
  );
});
