import { defineConfig } from "tsup";

// Three entries, one package. The subpath split is what keeps `import { guard } from
// "chainward"` from dragging node:http and a server into a consumer's bundle — the proxy
// only loads for someone who asks for it by path or runs the bin.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    proxy: "src/proxy/index.ts",
    cli: "src/proxy/cli.ts",
  },
  format: ["esm", "cjs"],
  dts: { entry: { index: "src/index.ts", proxy: "src/proxy/index.ts" } },
  clean: true,
  sourcemap: true,
  target: "node20",
  // keeps the `node:` prefix on builtins; without it esbuild emits bare "http", which a
  // package of that name in node_modules could shadow.
  platform: "node",
  // The bin resolves its console page from `import.meta.url`; without this the CJS build
  // has no such binding and the page is never found.
  shims: true,
  treeshake: true,
});
