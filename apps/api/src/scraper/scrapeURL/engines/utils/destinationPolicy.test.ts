import { describe, expect, it } from "vitest";
import { MockAgent } from "undici";
import {
  assertPublicAddress,
  makePinnedLookup,
  parseSafeDestination,
  UnsafeDestinationError,
  validateResolvedAddresses,
  type ResolveAll,
} from "./destinationPolicy";
import { __test, secureFetch } from "./safeFetch";

const publicAnswer = [{ address: "93.184.216.34", family: 4 }];
const publicResolver: ResolveAll = (_hostname, callback) =>
  callback(null, publicAnswer);

describe("Swallow destination policy", () => {
  it.each([
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "224.0.0.1",
    "0.0.0.0",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "::1",
    "fe80::1",
    "fc00::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
  ])("rejects non-public address %s", address => {
    expect(() => assertPublicAddress(address)).toThrow(UnsafeDestinationError);
  });

  it("accepts public addresses and rejects mixed, empty, and malformed answers", () => {
    expect(() => assertPublicAddress("93.184.216.34")).not.toThrow();
    expect(() =>
      assertPublicAddress("2606:2800:220:1:248:1893:25c8:1946"),
    ).not.toThrow();
    expect(() =>
      validateResolvedAddresses([
        ...publicAnswer,
        { address: "10.0.0.1", family: 4 },
      ]),
    ).toThrow();
    expect(() => validateResolvedAddresses([])).toThrow();
    expect(() => assertPublicAddress("not-an-address")).toThrow();
  });

  it.each([
    "http://example.com",
    "https://user:pass@example.com",
    "https://example.com/#fragment",
    "https://example.com:443/",
    "https://example.com:444/",
    "https://127.0.0.1/",
    "https://localhost/",
    "not a url",
  ])("rejects unsafe URL %s", value => {
    expect(() => parseSafeDestination(value)).toThrow(UnsafeDestinationError);
  });

  it("fails closed on DNS failure, empty answers, and rebinding before connection", async () => {
    for (const resolver of [
      ((_host, callback) =>
        callback(
          Object.assign(new Error("dns"), { code: "ENOTFOUND" }),
        )) as ResolveAll,
      ((_host, callback) => callback(null, [])) as ResolveAll,
      ((_host, callback) =>
        callback(null, [{ address: "10.0.0.1", family: 4 }])) as ResolveAll,
    ]) {
      await new Promise<void>(resolve => {
        makePinnedLookup(resolver)("example.com", {}, error => {
          expect(error).toBeTruthy();
          resolve();
        });
      });
    }
  });

  it("does not connect when connection-time DNS rebounds to loopback", async () => {
    const reboundResolver: ResolveAll = (_host, callback) =>
      callback(null, [{ address: "127.0.0.1", family: 4 }]);
    const dispatcher = __test.makeDispatcher(false, false, reboundResolver);
    await expect(
      secureFetch(
        "https://rebound.example/path",
        { dispatcher },
        publicResolver,
      ),
    ).rejects.toBeTruthy();
    await dispatcher.close();
  });
});

describe("Swallow secure redirects", () => {
  it("follows a bounded public cross-origin redirect", async () => {
    const agent = new MockAgent();
    agent.disableNetConnect();
    agent
      .get("https://example.com")
      .intercept({ path: "/start", method: "GET" })
      .reply(302, "", { headers: { location: "https://www.example.org/end" } });
    agent
      .get("https://www.example.org")
      .intercept({ path: "/end", method: "GET" })
      .reply(200, "ok");
    const response = await secureFetch(
      "https://example.com/start",
      { dispatcher: agent },
      publicResolver,
    );
    expect(await response.text()).toBe("ok");
    await agent.close();
  });

  it.each([
    ["http://example.com/end", "unsupported_scheme"],
    ["https://user:pass@example.com/end", "credentials"],
    ["https://example.com:444/end", "explicit_port"],
  ])("rejects redirect destination %s", async (location, code) => {
    const agent = new MockAgent();
    agent.disableNetConnect();
    agent
      .get("https://example.com")
      .intercept({ path: "/start", method: "GET" })
      .reply(302, "", { headers: { location } });
    await expect(
      secureFetch(
        "https://example.com/start",
        { dispatcher: agent },
        publicResolver,
      ),
    ).rejects.toMatchObject({ code });
    await agent.close();
  });

  it("rejects private redirect resolution before dispatch", async () => {
    const agent = new MockAgent();
    agent.disableNetConnect();
    agent
      .get("https://example.com")
      .intercept({ path: "/start", method: "GET" })
      .reply(302, "", { headers: { location: "https://private.example/end" } });
    const resolver: ResolveAll = (host, callback) =>
      callback(
        null,
        host === "private.example"
          ? [{ address: "10.0.0.1", family: 4 }]
          : publicAnswer,
      );
    await expect(
      secureFetch("https://example.com/start", { dispatcher: agent }, resolver),
    ).rejects.toBeInstanceOf(UnsafeDestinationError);
    await agent.close();
  });

  it("rejects loops and more than ten redirects", async () => {
    const loopAgent = new MockAgent();
    loopAgent.disableNetConnect();
    const loopPool = loopAgent.get("https://example.com");
    loopPool
      .intercept({ path: "/a", method: "GET" })
      .reply(302, "", { headers: { location: "/b" } });
    loopPool
      .intercept({ path: "/b", method: "GET" })
      .reply(302, "", { headers: { location: "/a" } });
    await expect(
      secureFetch(
        "https://example.com/a",
        { dispatcher: loopAgent },
        publicResolver,
      ),
    ).rejects.toMatchObject({ code: "redirect_loop" });
    await loopAgent.close();

    const manyAgent = new MockAgent();
    manyAgent.disableNetConnect();
    const pool = manyAgent.get("https://example.com");
    for (let index = 0; index <= 10; index++) {
      pool
        .intercept({ path: `/${index}`, method: "GET" })
        .reply(302, "", { headers: { location: `/${index + 1}` } });
    }
    await expect(
      secureFetch(
        "https://example.com/0",
        { dispatcher: manyAgent },
        publicResolver,
      ),
    ).rejects.toMatchObject({ code: "too_many_redirects" });
    await manyAgent.close();
  });
});
