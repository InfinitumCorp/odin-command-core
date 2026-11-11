import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { odinPlugin } from "./src/server/app";

export default defineConfig({
  plugins: [react(), odinPlugin()],
  server: { port: 5317, strictPort: true, watch: { ignored: ["**/.odin/**"] } },
  build: { outDir: "dist" },
  test: { globals: true, environment: "node", globalSetup: ["src/test/globalSetup.ts"] },
} as any);
