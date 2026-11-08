import { defineConfig } from "orval";

const input = {
  target: "../experiments/orval/contract.openapi.json",
  parserOptions: { externalRefs: { allow: [] } },
};

export default defineConfig({
  wire: {
    input,
    output: {
      schemas: { path: "../.local/orval/fixtures-orval.ts", mode: "single" },
      override: { useDates: false, useBigInt: false, enumGenerationType: "union" },
    },
  },
  converted: {
    input,
    output: {
      schemas: { path: "../.local/orval/fixtures-converted.ts", mode: "single" },
      override: { useDates: true, useBigInt: true, enumGenerationType: "union" },
    },
  },
});
