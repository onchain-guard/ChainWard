/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "node20",
  // `chainward` is a real runtime dependency and `@elizaos/core` is supplied by the host
  // agent — bundling either would ship a second copy of code the consumer already has.
  external: ["chainward", "@elizaos/core"],
});
