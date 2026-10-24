import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": fileURLToPath(
        new URL("packages/worker/test/cloudflare-workers.ts", import.meta.url)
      ),
    },
  },
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "infra/test/**/*.test.ts",
      "deploy/*/test/**/*.test.ts",
    ],
  },
});
