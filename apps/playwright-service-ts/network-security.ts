import { lookup as dnsLookup } from "node:dns";
import http from "node:http";
import net, { Socket } from "node:net";
import type { Duplex } from "node:stream";
import IPAddr from "ipaddr.js";
import type { Request as PlaywrightRequest } from "playwright";

export const MAX_SAFE_REDIRECTS = 10;
export const chromiumSecurityArguments = (proxyEndpoint: string): string[] => [
  `--proxy-server=${proxyEndpoint}`,
  "--proxy-bypass-list=<-loopback>",
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
  "--disable-quic",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
];
export const browserProxy = (proxyEndpoint: string) => ({
  server: proxyEndpoint,
  bypass: "",
});
export type LookupAddress = { address: string; family: number };
export type ResolveAll = (
  hostname: string,
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses?: LookupAddress[],
  ) => void,
) => void;
export type DialPinned = (
  address: string,
  port: number,
  callback: (error: Error | null, socket?: Socket) => void,
) => void;

export class InsecureConnectionError extends Error {
  constructor(readonly code: string) {
    super(`Connection blocked by destination policy (${code}).`);
    this.name = "InsecureConnectionError";
  }
}

const blockedRanges = new Set([
  "unspecified",
  "broadcast",
  "multicast",
  "linkLocal",
  "loopback",
  "private",
  "carrierGradeNat",
  "uniqueLocal",
  "ipv4Mapped",
  "rfc6145",
  "rfc6052",
  "6to4",
  "teredo",
  "benchmarking",
  "amt",
  "as112",
  "deprecated",
  "orchid",
  "reserved",
]);
const blockedNetworks = [
  IPAddr.parseCIDR("0.0.0.0/8"),
  IPAddr.parseCIDR("192.0.0.0/24"),
  IPAddr.parseCIDR("192.0.2.0/24"),
  IPAddr.parseCIDR("198.18.0.0/15"),
  IPAddr.parseCIDR("198.51.100.0/24"),
  IPAddr.parseCIDR("203.0.113.0/24"),
  IPAddr.parseCIDR("240.0.0.0/4"),
  IPAddr.parseCIDR("2001:db8::/32"),
];

export function assertPublicAddress(value: string): void {
  if (!IPAddr.isValid(value))
    throw new InsecureConnectionError("malformed_address");
  const address = IPAddr.parse(value);
  if (
    address.kind() === "ipv6" &&
    "isIPv4MappedAddress" in address &&
    address.isIPv4MappedAddress()
  ) {
    throw new InsecureConnectionError("mapped_ipv6");
  }
  if (blockedRanges.has(address.range()))
    throw new InsecureConnectionError("non_public_address");
  for (const network of blockedNetworks) {
    if (address.kind() === network[0].kind() && address.match(network)) {
      throw new InsecureConnectionError("non_public_address");
    }
  }
}

function sameAddress(left: string, right: string): boolean {
  try {
    return (
      IPAddr.parse(left).toNormalizedString() ===
      IPAddr.parse(right).toNormalizedString()
    );
  } catch {
    return false;
  }
}

export function validateResolvedAddresses(
  addresses: LookupAddress[],
): LookupAddress {
  if (addresses.length === 0)
    throw new InsecureConnectionError("empty_dns_answer");
  for (const answer of addresses) assertPublicAddress(answer.address);
  return addresses[0];
}

export function parseSafeDestination(value: string | URL): URL {
  const raw = value instanceof URL ? value.href : value;
  const authority = raw.match(/^(?:https:)?\/\/([^/?#]+)/i);
  if (authority?.[1].includes("@")) {
    throw new InsecureConnectionError("credentials");
  }
  if (authority?.[1].includes(":")) {
    throw new InsecureConnectionError("explicit_port");
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new InsecureConnectionError("malformed_url");
  }
  if (parsed.protocol !== "https:")
    throw new InsecureConnectionError("unsupported_scheme");
  if (parsed.username || parsed.password)
    throw new InsecureConnectionError("credentials");
  if (parsed.hash) throw new InsecureConnectionError("fragment");
  if (parsed.port) throw new InsecureConnectionError("explicit_port");
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    IPAddr.isValid(hostname) ||
    !hostname.includes(".") ||
    hostname.length > 253 ||
    hostname
      .split(".")
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    throw new InsecureConnectionError("invalid_hostname");
  }
  parsed.hostname = hostname;
  return parsed;
}

export const systemResolveAll: ResolveAll = (hostname, callback) => {
  dnsLookup(hostname, { all: true, verbatim: true }, (error, addresses) =>
    callback(error, addresses),
  );
};
const systemDial: DialPinned = (address, port, callback) => {
  const socket = net.connect({ host: address, port });
  socket.once("error", (error) => callback(error));
  socket.once("connect", () => callback(null, socket));
};

export class SecureEgressProxy {
  private readonly server: http.Server;
  private readonly clients = new Set<Duplex>();
  private readonly upstreams = new Set<Socket>();
  private endpoint: string | null = null;

  constructor(
    private readonly resolveAll: ResolveAll = systemResolveAll,
    private readonly dial: DialPinned = systemDial,
  ) {
    this.server = http.createServer((_request, response) => {
      response.writeHead(403, { Connection: "close" });
      response.end();
    });
    this.server.on("connect", (request, client, head) => {
      this.clients.add(client);
      client.once("close", () => this.clients.delete(client));
      this.connect(request, client, head);
    });
  }

  async start(): Promise<string> {
    if (this.endpoint) return this.endpoint;
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(0, "127.0.0.1", () => resolve());
    });
    const address = this.server.address();
    if (!address || typeof address === "string")
      throw new Error("Secure proxy did not bind a TCP port.");
    this.endpoint = `http://127.0.0.1:${address.port}`;
    return this.endpoint;
  }

  async close(): Promise<void> {
    for (const client of this.clients) client.destroy();
    for (const upstream of this.upstreams) upstream.destroy();
    await new Promise<void>((resolve, reject) =>
      this.server.close((error) => (error ? reject(error) : resolve())),
    );
    this.endpoint = null;
  }

  private deny(client: Duplex): void {
    if (!client.destroyed)
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
  }

  private connect(
    request: http.IncomingMessage,
    client: Duplex,
    head: Buffer,
  ): void {
    let target: URL;
    try {
      const authority = request.url?.match(/^([A-Za-z0-9.-]+):(\d+)$/);
      if (!authority) throw new InsecureConnectionError("malformed_connect");
      if (authority[2] !== "443")
        throw new InsecureConnectionError("unsafe_port");
      target = parseSafeDestination(`https://${authority[1]}`);
    } catch {
      this.deny(client);
      return;
    }
    this.resolveAll(target.hostname, (resolveError, addresses) => {
      if (resolveError) {
        this.deny(client);
        return;
      }
      let selected: LookupAddress;
      try {
        selected = validateResolvedAddresses(addresses ?? []);
      } catch {
        this.deny(client);
        return;
      }
      this.dial(selected.address, 443, (dialError, upstream) => {
        if (
          dialError ||
          !upstream ||
          !upstream.remoteAddress ||
          !sameAddress(upstream.remoteAddress, selected.address)
        ) {
          upstream?.destroy();
          this.deny(client);
          return;
        }
        try {
          assertPublicAddress(upstream.remoteAddress);
        } catch {
          upstream.destroy();
          this.deny(client);
          return;
        }
        this.upstreams.add(upstream);
        upstream.once("close", () => this.upstreams.delete(upstream));
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length) upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      });
    });
  }
}

export class NavigationPolicy {
  private readonly navigationUrls = new Set<string>();
  private redirects = 0;

  observe(request: PlaywrightRequest): void {
    const parsed = parseSafeDestination(request.url());
    if (!request.isNavigationRequest()) return;
    const key = parsed.href;
    if (this.navigationUrls.has(key))
      throw new InsecureConnectionError("redirect_loop");
    this.navigationUrls.add(key);
    if (request.redirectedFrom()) {
      this.redirects++;
      if (this.redirects > MAX_SAFE_REDIRECTS)
        throw new InsecureConnectionError("too_many_redirects");
    }
  }
}
