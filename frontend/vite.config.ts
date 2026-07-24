import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3004,
    proxy: {
      "/api": {
        target: "http://localhost:8004",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:8004",
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
