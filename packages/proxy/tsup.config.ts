import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/cli.ts"],
  format: ["esm", "cjs"],
  dts: { entry: "src/index.ts" },
  clean: true,
  sourcemap: true,
  target: "node20",
  // the bin needs a shebang; tsup keeps the one in the source for esm output
  external: ["chainward"],
})
