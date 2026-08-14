import { defineConfig } from "tsup";

// The published artifact. `src/` ships TypeScript with explicit `.ts` import specifiers
// (allowImportingTsExtensions), which no consumer runtime can resolve — so the package
// entry MUST point at this build output, never at src.
export default defineConfig({
  entry: ["src/index.ts"],
  // dual-format: `import` resolves esm, `require` resolves cjs. Dropping cjs would
  // silently exclude every consumer still on require().
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "node20",
  // zero runtime dependencies — nothing to externalise, and bundling keeps the
  // published tree a single file per format.
  treeshake: true,
});
