import { lookup as dnsLookup } from "node:dns";
import IPAddr from "ipaddr.js";

export const MAX_SAFE_REDIRECTS = 10;

type LookupAddress = { address: string; family: number };
export type ResolveAll = (
  hostname: string,
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses?: LookupAddress[],
  ) => void,
) => void;

export class UnsafeDestinationError extends Error {
  constructor(readonly code: string) {
    super(`Destination rejected by network policy (${code}).`);
    this.name = "UnsafeDestinationError";
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

const documentationNetworks = [
  IPAddr.parseCIDR("192.0.2.0/24"),
  IPAddr.parseCIDR("198.51.100.0/24"),
  IPAddr.parseCIDR("203.0.113.0/24"),
  IPAddr.parseCIDR("2001:db8::/32"),
];
const additionalBlockedNetworks = [
  IPAddr.parseCIDR("0.0.0.0/8"),
  IPAddr.parseCIDR("192.0.0.0/24"),
  IPAddr.parseCIDR("198.18.0.0/15"),
  IPAddr.parseCIDR("240.0.0.0/4"),
];

export function assertPublicAddress(value: string): void {
  if (!IPAddr.isValid(value)) {
    throw new UnsafeDestinationError("malformed_address");
  }
  const address = IPAddr.parse(value);
  if (
    address.kind() === "ipv6" &&
    (address as IPAddr.IPv6).isIPv4MappedAddress()
  ) {
    throw new UnsafeDestinationError("mapped_ipv6");
  }
  if (blockedRanges.has(address.range())) {
    throw new UnsafeDestinationError("non_public_address");
  }
  for (const network of [
    ...documentationNetworks,
    ...additionalBlockedNetworks,
  ]) {
    if (address.kind() === network[0].kind() && address.match(network)) {
      throw new UnsafeDestinationError("non_public_address");
    }
  }
}

export function parseSafeDestination(value: string | URL): URL {
  const raw = value instanceof URL ? value.href : value;
  const authority = raw.match(/^(?:https:)?\/\/([^/?#]+)/i);
  if (authority?.[1].includes("@")) {
    throw new UnsafeDestinationError("credentials");
  }
  if (authority?.[1].includes(":")) {
    throw new UnsafeDestinationError("explicit_port");
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new UnsafeDestinationError("malformed_url");
  }
  if (parsed.protocol !== "https:") {
    throw new UnsafeDestinationError("unsupported_scheme");
  }
  if (parsed.username || parsed.password) {
    throw new UnsafeDestinationError("credentials");
  }
  if (parsed.hash) {
    throw new UnsafeDestinationError("fragment");
  }
  if (parsed.port) {
    throw new UnsafeDestinationError("explicit_port");
  }
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
      .some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    throw new UnsafeDestinationError("invalid_hostname");
  }
  parsed.hostname = hostname;
  return parsed;
}

export function validateResolvedAddresses(
  addresses: LookupAddress[],
): LookupAddress {
  if (addresses.length === 0) {
    throw new UnsafeDestinationError("empty_dns_answer");
  }
  for (const answer of addresses) {
    assertPublicAddress(answer.address);
  }
  return addresses[0];
}

export const systemResolveAll: ResolveAll = (hostname, callback) => {
  dnsLookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
    callback(error, addresses);
  });
};

export function makePinnedLookup(resolveAll: ResolveAll = systemResolveAll) {
  return (
    hostname: string,
    _options: unknown,
    callback: (
      error: NodeJS.ErrnoException | null,
      address?: string,
      family?: number,
    ) => void,
  ): void => {
    resolveAll(hostname, (error, addresses) => {
      if (error) {
        callback(
          new UnsafeDestinationError("dns_failure") as NodeJS.ErrnoException,
        );
        return;
      }
      try {
        const selected = validateResolvedAddresses(addresses ?? []);
        callback(null, selected.address, selected.family);
      } catch (validationError) {
        callback(validationError as NodeJS.ErrnoException);
      }
    });
  };
}
