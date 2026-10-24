import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": fileURLToPath(
        new URL("../worker/test/cloudflare-workers.ts", import.meta.url)
      ),
    },
  },
  test: { include: ["packages/*/test/**/*.test.ts"] },
});
