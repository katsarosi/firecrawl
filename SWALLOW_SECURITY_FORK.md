# Swallow Firecrawl security fork

## Baseline

- Upstream: `https://github.com/mendableai/firecrawl` (redirects to the canonical `firecrawl/firecrawl` repository)
- Canonical release: GitHub Release **Firecrawl v2.11.0**, tag `v2.11.0`
- Upstream commit: `ef12eb36b2f3382838dfe0a0c1a5add3d5df7fe5`
- Fork: `https://github.com/katsarosi/firecrawl`
- Protected patch branch: `secure/swallow-v2.11.0-r1`
- Patch revision: `swallow-security-r1`
- API contract: Firecrawl HTTP API v2; no endpoint or response-shape changes

The commit also has an annotated `v2.10.30` tag, but upstream did not publish a GitHub Release named `v2.10.30`. The canonical release is therefore the published GitHub Release `v2.11.0`; the second tag is recorded as upstream tag ambiguity, not treated as a separate selected release.

## Security patch

Swallow permits page egress only to HTTPS hostnames on the implicit port 443. URL credentials, fragments, explicit ports, IP literals, malformed/non-FQDN hosts, HTTP downgrade, unsafe redirects, and all non-public IPv4/IPv6 answers are rejected. Every DNS answer must be public; mixed, empty, malformed, and failed answers fail closed.

The ordinary-fetch path validates every URL, follows redirects manually with one non-resetting ten-hop budget, resolves again in the Undici connector, dials the selected validated address, and retains the connected-socket `remoteAddress` check. Connection pools remain origin-keyed. External `PROXY_SERVER` configuration fails startup because a generic proxy cannot demonstrate this policy.

The Playwright worker starts an in-process loopback CONNECT proxy. The proxy resolves every CONNECT hostname, validates all answers, dials the selected IP directly, and verifies the connected address before opening the tunnel. It accepts only `hostname:443`. Chromium is configured at launch and context level to use this proxy, has an empty bypass list, cannot resolve public page hosts directly (`--host-resolver-rules`), and has QUIC and non-proxied WebRTC disabled. Playwright routing validates every navigation and subresource URL before request bytes are sent and maintains one ten-hop/loop budget for the acquisition context. The former 30-second DNS authorization cache is removed. External browser proxy variables now fail startup rather than weakening the connector.

These changes protect network reachability; they do not grant permission to scrape, retain, or display data.

## Test and comparison commands

```sh
# Focused security suite and type/build checks
cd apps/api
pnpm exec vitest run src/scraper/scrapeURL/engines/utils/destinationPolicy.test.ts
pnpm exec tsc --noEmit

cd ../playwright-service-ts
pnpm run build
pnpm test

# Relevant deterministic upstream URL tests (does not start the harness)
cd ../api
pnpm exec vitest run src/lib/validateUrl.test.ts

# Full upstream server test job (CI only; starts upstream test fixtures/services)
# See .github/workflows/test-server.yml. It is not part of the local security
# command because upstream's scrapeURL suite accesses live test websites.
```

Compare the patch stack with the immutable baseline:

```sh
git diff ef12eb36b2f3382838dfe0a0c1a5add3d5df7fe5...secure/swallow-v2.11.0-r1 -- \
  apps/api/src/scraper apps/api/src/lib/validateUrl.ts apps/api/src/search/v2/ddgsearch.ts \
  apps/playwright-service-ts .github SWALLOW_SECURITY_FORK.md
```

## Upstream update and release policy

`upstream-mirror/*` branches point at unmodified release commits. `secure/*` branches contain the reviewed patch stack. The scheduled update workflow discovers GitHub's latest canonical Release, creates a new update branch, merges the immutable release commit, and opens a PR only after the security guard and focused tests pass. It never updates the secure branch directly, auto-merges, publishes, deploys, or modifies Swallow.

Required repository settings:

1. Protect `secure/swallow-v2.11.0-r1` and future `secure/*` branches; disallow force pushes and deletion.
2. Require pull requests, one approving review from `@katsarosi`, dismissal of stale approvals, conversation resolution, and the `swallow-security` check.
3. Require CODEOWNER review for `apps/api/src/scraper/**`, `apps/playwright-service-ts/**`, `.github/workflows/**`, and this document.
4. Disable auto-merge for security/update PRs. Limit workflow write permissions to the update and manual release workflows.
5. Protect the `release` environment with required reviewer `@katsarosi`; do not allow administrators to bypass it.
6. Keep package visibility private until explicitly approved, and retain prior digest-pinned packages for rollback.

A human reviews upstream network topology, the patch diff, test results, API compatibility, and image inputs before merge. Passing CI is necessary but never approval. Failed/conflicting updates leave the last approved image untouched.

The manual release workflow may run only for an approved secure-branch commit. It publishes versioned API and Playwright images under `ghcr.io/katsarosi/`, emits immutable digests and provenance, and never deploys them. Task 14B must copy reviewed digests explicitly.

Rollback means restoring Task 14B's previous digests; tags are never the deployment authority. If upstream ships equivalent fixes, compare implementation and regression tests, remove each custom patch only after human review verifies equal or stronger connection-time behavior, and retain the Swallow security suite as the acceptance gate.
