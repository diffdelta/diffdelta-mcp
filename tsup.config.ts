import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: false,
  clean: true,
  sourcemap: false,
  target: "es2022",
  outDir: "dist",
  banner: {
    js: "#!/usr/bin/env node",
  },
});
