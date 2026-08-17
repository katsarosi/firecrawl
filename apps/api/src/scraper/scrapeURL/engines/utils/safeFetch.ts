import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import * as undici from "undici";
import { CookieJar } from "tough-cookie";
import { cookie } from "http-cookie-agent/undici";
import { config } from "../../../../config";
import {
  assertPublicAddress,
  makePinnedLookup,
  MAX_SAFE_REDIRECTS,
  parseSafeDestination,
  systemResolveAll,
  UnsafeDestinationError,
  validateResolvedAddresses,
  type ResolveAll,
} from "./destinationPolicy";

export { UnsafeDestinationError as InsecureConnectionError } from "./destinationPolicy";
export function isIPPrivate(address: string): boolean {
  try {
    assertPublicAddress(address);
    return false;
  } catch {
    return true;
  }
}

function attachConnectedAddressCheck(agent: undici.Dispatcher) {
  agent.on("connect", (_, targets) => {
    const client = targets.slice(-1)[0] as undici.Client;
    const socketSymbol = Object.getOwnPropertySymbols(client).find(
      x => x.description === "socket",
    );
    if (!socketSymbol) {
      client.close();
      return;
    }
    const socket = (client as any)[socketSymbol] as Socket | TLSSocket;
    try {
      if (!socket.remoteAddress) {
        throw new UnsafeDestinationError("missing_connected_address");
      }
      assertPublicAddress(socket.remoteAddress);
    } catch (error) {
      socket.destroy(error as Error);
    }
  });
}

function makeDispatcher(
  skipTlsVerification: boolean,
  withCookies: boolean,
  resolveAll: ResolveAll = systemResolveAll,
): undici.Dispatcher {
  if (config.PROXY_SERVER) {
    throw new UnsafeDestinationError("external_proxy_disabled");
  }
  const base = new undici.Agent({
    connect: {
      rejectUnauthorized: !skipTlsVerification,
      lookup: makePinnedLookup(resolveAll) as any,
    },
  });
  const dispatcher = withCookies
    ? base.compose(cookie({ jar: new CookieJar() }))
    : base;
  attachConnectedAddressCheck(dispatcher);
  return dispatcher;
}

const secureDispatcher = makeDispatcher(false, true);
const secureDispatcherSkipTlsVerification = makeDispatcher(true, true);
const secureDispatcherNoCookies = makeDispatcher(false, false);
const secureDispatcherNoCookiesSkipTlsVerification = makeDispatcher(
  true,
  false,
);

export const getSecureDispatcher = (skipTlsVerification = false) =>
  skipTlsVerification ? secureDispatcherSkipTlsVerification : secureDispatcher;

export const getSecureDispatcherNoCookies = (skipTlsVerification = false) =>
  skipTlsVerification
    ? secureDispatcherNoCookiesSkipTlsVerification
    : secureDispatcherNoCookies;

type SecureFetchOptions = undici.RequestInit & {
  dispatcher?: undici.Dispatcher;
};

export async function secureFetch(
  input: string | URL,
  options: SecureFetchOptions = {},
  resolveAll: ResolveAll = systemResolveAll,
): Promise<undici.Response> {
  let method = (options.method ?? "GET").toString().toUpperCase();
  if (method !== "GET" && method !== "HEAD" && method !== "POST") {
    throw new UnsafeDestinationError("unsupported_method");
  }
  let body = options.body;
  const headers = new undici.Headers(options.headers);
  const dispatcher = options.dispatcher ?? getSecureDispatcher(false);
  let current = parseSafeDestination(input);
  const visited = new Set<string>();

  for (let redirects = 0; ; redirects++) {
    const key = current.href;
    if (visited.has(key)) {
      throw new UnsafeDestinationError("redirect_loop");
    }
    visited.add(key);

    await new Promise<void>((resolve, reject) => {
      resolveAll(current.hostname, (error, addresses) => {
        if (error) {
          reject(new UnsafeDestinationError("dns_failure"));
          return;
        }
        try {
          validateResolvedAddresses(addresses ?? []);
          resolve();
        } catch (validationError) {
          reject(validationError);
        }
      });
    });

    const response = await undici.fetch(current, {
      ...options,
      method,
      body,
      headers,
      dispatcher,
      redirect: "manual",
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      return response;
    }
    if (redirects === MAX_SAFE_REDIRECTS) {
      await response.body?.cancel();
      throw new UnsafeDestinationError("too_many_redirects");
    }
    const location = response.headers.get("location");
    await response.body?.cancel();
    if (!location) {
      throw new UnsafeDestinationError("missing_redirect_location");
    }
    if (
      response.status === 303 ||
      ((response.status === 301 || response.status === 302) &&
        method === "POST")
    ) {
      method = "GET";
      body = undefined;
    } else if (
      body &&
      typeof body !== "string" &&
      !(body instanceof Uint8Array)
    ) {
      throw new UnsafeDestinationError("non_replayable_redirect_body");
    }
    let next: URL;
    if (/^https:\/\//i.test(location)) {
      next = parseSafeDestination(location);
    } else if (location.startsWith("//")) {
      next = parseSafeDestination(`https:${location}`);
    } else {
      next = parseSafeDestination(new URL(location, current));
    }
    if (next.origin !== current.origin) {
      for (const name of [
        "authorization",
        "cookie",
        "host",
        "proxy-authorization",
      ]) {
        headers.delete(name);
      }
    }
    current = next;
  }
}

export const __test = { makeDispatcher };
