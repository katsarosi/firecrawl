#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  apps/api/src/scraper/scrapeURL/engines/utils/destinationPolicy.ts
  apps/api/src/scraper/scrapeURL/engines/utils/destinationPolicy.test.ts
  apps/playwright-service-ts/network-security.ts
  apps/playwright-service-ts/network-security.test.ts
)
for file in "${required[@]}"; do
  test -s "$file" || { echo "missing Swallow security file: $file" >&2; exit 1; }
done

grep -q 'MAX_SAFE_REDIRECTS = 10' apps/api/src/scraper/scrapeURL/engines/utils/destinationPolicy.ts
grep -q 'redirect: "manual"' apps/api/src/scraper/scrapeURL/engines/utils/safeFetch.ts
! grep -q 'maxRedirections: 5000' apps/api/src/scraper/scrapeURL/engines/utils/safeFetch.ts
grep -q 'SecureEgressProxy' apps/playwright-service-ts/api.ts
grep -q -- '--host-resolver-rules=MAP \* ~NOTFOUND' apps/playwright-service-ts/network-security.ts
! grep -q 'DNS_CACHE_TTL_MS' apps/playwright-service-ts/api.ts

(
  cd apps/api
  pnpm exec vitest run src/scraper/scrapeURL/engines/utils/destinationPolicy.test.ts
)
(
  cd apps/playwright-service-ts
  pnpm run build
  pnpm test
)
