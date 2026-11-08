import { defineConfig } from "orval";

export default defineConfig({
  cheesetrap: {
    input: {
      target: "../api/openapi.json",
      parserOptions: { externalRefs: { allow: [] } },
    },
    output: {
      // Types only: ApiClient retains all transport and session behavior.
      schemas: { path: "./src/api/generated/models.ts", mode: "single" },
      override: {
        useDates: false,
        useBigInt: false,
        enumGenerationType: "union",
      },
    },
  },
});
